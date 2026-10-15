#[cfg(test)]
use crate::render::html_to_gemtext;
#[cfg(test)]
use reqwest::Client;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use tokio::io::{AsyncRead, AsyncReadExt};
use url::Url;

#[derive(Debug)]
pub struct Response {
    pub status: u8,
    pub meta: String,
    pub body: Vec<u8>,
    pub cacheable: bool,
}
impl Response {
    pub fn error(status: u8, meta: &str) -> Self {
        Self {
            status,
            meta: meta.into(),
            body: Vec::new(),
            cacheable: status != 44,
        }
    }
    #[cfg(test)]
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }
    pub fn wire(&self) -> Vec<u8> {
        let meta: String = self
            .meta
            .chars()
            .filter(|c| !c.is_control())
            .take(512)
            .collect();
        let mut wire = format!("{} {}\r\n", self.status, meta).into_bytes();
        wire.extend_from_slice(&self.body);
        wire
    }
}

// Read only one request, capped at Gemini's 1024-byte URL plus CRLF.
pub async fn read_request(reader: &mut (impl AsyncRead + Unpin)) -> Result<String, Response> {
    let mut bytes = Vec::new();
    loop {
        let byte = reader
            .read_u8()
            .await
            .map_err(|_| Response::error(59, "Incomplete request"))?;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes)
                .map_err(|_| Response::error(59, "Request must be UTF-8"));
        }
        if bytes.len() >= 1026
            || byte == b'\n'
            || (bytes.len() > 1 && bytes[bytes.len() - 2] == b'\r')
        {
            return Err(Response::error(
                59,
                "Expected a URL of at most 1024 bytes followed by CRLF",
            ));
        }
    }
}

pub fn target(request: &str) -> Result<Url, Response> {
    if request.len() > 8192 {
        return Err(Response::error(59, "Upstream URL length limit exceeded"));
    }
    if request.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Response::error(59, "Invalid URL"));
    }
    let mut url = Url::parse(request).map_err(|_| Response::error(59, "Invalid absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Response::error(53, "Kerbin proxies HTTP and HTTPS only"));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(Response::error(
            59,
            "Expected a URL with a host and no credentials",
        ));
    }
    if let Some(url::Host::Domain(host)) = url.host() {
        let canonical = host.trim_end_matches('.').to_string();
        url.set_host(Some(&canonical))
            .map_err(|_| Response::error(59, "Invalid hostname"))?;
    }
    url.set_fragment(None);
    Ok(url)
}

#[derive(Clone)]
pub struct Fetcher {
    pub guard: crate::abuse::Guard,
    dns: crate::destination::Dns,
    full_page: bool,
    parsers: Option<crate::parser::Pool>,
    #[cfg(test)]
    fixture_client: Option<Client>,
}
impl Fetcher {
    pub fn new(
        guard: crate::abuse::Guard,
        full_page: bool,
        parsers: crate::parser::Pool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            guard,
            dns: crate::destination::Dns::new()?,
            full_page,
            parsers: Some(parsers),
            #[cfg(test)]
            fixture_client: None,
        })
    }
    pub async fn fetch(&self, request: &str) -> Response {
        let url = match target(request) {
            Ok(url) => url,
            Err(response) => return response,
        };
        if let Err(response) = crate::destination::validate(&url) {
            self.guard
                .stats
                .denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return response;
        }
        let _permit = match self.guard.fetch() {
            Ok(permit) => permit,
            Err(response) => return response,
        };
        match tokio::time::timeout(self.guard.limits.timeout, self.fetch_inner(url)).await {
            Ok(response) => response,
            Err(_) => crate::abuse::Stats::reject(
                &self.guard.stats.timed_out,
                44,
                "Overall fetch deadline exceeded",
            ),
        }
    }
    async fn fetch_inner(&self, url: Url) -> Response {
        let mut cacheable = true;
        let mut response = self.fetch_chain(url, &mut cacheable).await;
        response.cacheable &= cacheable;
        response
    }
    async fn fetch_chain(&self, mut url: Url, chain_cacheable: &mut bool) -> Response {
        let deadline = tokio::time::Instant::now() + self.guard.limits.timeout;
        use crate::{abuse::Stats, render::RenderError};
        use reqwest::header::LOCATION;
        for hop in 0..=self.guard.limits.redirects {
            let ips = match self.dns.lookup(&url).await {
                Ok(ips) => ips,
                Err(response) => {
                    let counter = if response.status == 53 {
                        &self.guard.stats.denied
                    } else {
                        &self.guard.stats.upstream
                    };
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return response;
                }
            };
            if hop > 0
                && let Err(response) = self.guard.global()
            {
                return response;
            }
            let _destination = match self.guard.destination(url.host_str().unwrap(), &ips) {
                Ok(lease) => lease,
                Err(response) => return response,
            };
            let client = match crate::destination::client(&url, ips, self.guard.limits.timeout) {
                Ok(client) => client,
                Err(response) => return response,
            };
            #[cfg(test)]
            let client = self.fixture_client.clone().unwrap_or(client);
            let mut response = match client.get(url.clone()).send().await {
                Ok(response) => response,
                Err(error) => return self.upstream_error(&error),
            };
            *chain_cacheable &= allows_cache(response.headers());
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if hop == self.guard.limits.redirects {
                    return Response::error(43, "Upstream redirect limit exceeded");
                }
                let next = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|value| url.join(value).ok());
                let Some(next) = next else {
                    return Response::error(43, "Invalid upstream redirect");
                };
                url = match target(next.as_str()) {
                    Ok(url) => url,
                    Err(response) => return response,
                };
                // The next iteration revalidates DNS, IPs, ports, and admission.
                continue;
            }
            let cacheable = *chain_cacheable;
            if !response.status().is_success() {
                let mut error = Response::error(
                    match response.status() {
                        StatusCode::NOT_FOUND | StatusCode::GONE => 51,
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => 53,
                        StatusCode::TOO_MANY_REQUESTS => 44,
                        _ => 43,
                    },
                    &format!("Upstream HTTP {}", response.status().as_u16()),
                );
                error.cacheable = cacheable && error.status != 44;
                return error;
            }
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|value| value.len() <= 512 && value.parse::<mime::Mime>().is_ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let media = content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let is_html = matches!(media.as_str(), "text/html" | "application/xhtml+xml");
            let limit = if is_html {
                self.guard.limits.input_bytes
            } else {
                self.guard
                    .limits
                    .input_bytes
                    .min(self.guard.limits.output_bytes)
            };
            if response.content_length().is_some_and(|n| n > limit as u64) {
                return Stats::reject(
                    &self.guard.stats.oversized,
                    59,
                    "Upstream body size limit exceeded",
                );
            }
            let mut bytes = Vec::new();
            loop {
                let chunk = match response.chunk().await {
                    Ok(chunk) => chunk,
                    Err(error) => return self.upstream_error(&error),
                };
                let Some(chunk) = chunk else { break };
                // reqwest exposes decompressed chunks here. Never trust a
                // Content-Length check alone (chunked and compressed bodies).
                if chunk.len() > limit.saturating_sub(bytes.len()) {
                    return Stats::reject(
                        &self.guard.stats.oversized,
                        59,
                        "Decompressed body size limit exceeded",
                    );
                }
                bytes.extend_from_slice(&chunk);
            }
            if !is_html {
                return Response {
                    status: 20,
                    meta: content_type,
                    body: bytes,
                    cacheable,
                };
            }
            let encoding = content_type
                .split(';')
                .skip(1)
                .find_map(|part| {
                    let (name, value) = part.trim().split_once('=')?;
                    if !name.trim().eq_ignore_ascii_case("charset") {
                        return None;
                    }
                    encoding_rs::Encoding::for_label(
                        value.trim().trim_matches(['\"', '\'']).as_bytes(),
                    )
                })
                .unwrap_or(encoding_rs::UTF_8);
            let text = encoding.decode(&bytes).0.into_owned();
            drop(bytes);
            if text.len() > limit {
                return Stats::reject(
                    &self.guard.stats.oversized,
                    59,
                    "Decoded text size limit exceeded",
                );
            }
            let parser = match self.guard.parsers.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    return Stats::reject(
                        &self.guard.stats.busy,
                        44,
                        "Parser capacity unavailable",
                    );
                }
            };
            let full_page = self.full_page;
            let output_limit = self.guard.limits.output_bytes;
            let body = if let Some(pool) = &self.parsers {
                pool.render(text, url, full_page, output_limit, deadline, parser)
                    .await
            } else {
                #[cfg(test)]
                {
                    tokio::task::spawn_blocking(move || {
                        let _parser = parser;
                        html_to_gemtext(&text, &url, full_page, output_limit)
                    })
                    .await
                    .map_err(|_| crate::parser::Error::Failed)
                    .and_then(|result| result.map_err(crate::parser::Error::Render))
                }
                #[cfg(not(test))]
                {
                    return Response::error(43, "Parser supervisor unavailable");
                }
            };
            return match body {
                Ok(body) => Response {
                    status: 20,
                    meta: "text/gemini; charset=utf-8".into(),
                    body: body.into_bytes(),
                    cacheable,
                },
                Err(crate::parser::Error::Render(RenderError::TooLarge)) => Stats::reject(
                    &self.guard.stats.oversized,
                    59,
                    "Gemtext output size limit exceeded",
                ),
                Err(crate::parser::Error::Render(RenderError::TooComplex)) => Stats::reject(
                    &self.guard.stats.oversized,
                    59,
                    "HTML complexity limit exceeded",
                ),
                Err(crate::parser::Error::TimedOut) => {
                    Stats::reject(&self.guard.stats.timed_out, 44, "Parser deadline exceeded")
                }
                Err(_) => {
                    Stats::reject(&self.guard.stats.upstream, 43, "Upstream rendering failed")
                }
            };
        }
        unreachable!()
    }
    fn upstream_error(&self, error: &reqwest::Error) -> Response {
        if error.is_timeout() {
            crate::abuse::Stats::reject(&self.guard.stats.timed_out, 44, "Upstream timed out")
        } else {
            crate::abuse::Stats::reject(
                &self.guard.stats.upstream,
                43,
                "Could not fetch upstream page",
            )
        }
    }
}
pub async fn serve_proxy(
    fetcher: &Fetcher,
    cache: &crate::cache::Cache,
    request: &str,
) -> crate::cache::Wire {
    let url = match target(request) {
        Ok(url) => url,
        Err(response) => return response.wire().into(),
    };
    if let Err(response) = crate::destination::validate(&url) {
        fetcher
            .guard
            .stats
            .denied
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return response.wire().into();
    }
    let key = url.to_string();
    let fetcher = fetcher.clone();
    cache
        .get_or_fetch(
            key.clone(),
            move || async move { fetcher.fetch(&key).await },
        )
        .await
}

// Avoid retaining explicitly non-cacheable or potentially personalized pages.
fn allows_cache(headers: &reqwest::header::HeaderMap) -> bool {
    use reqwest::header::{CACHE_CONTROL, SET_COOKIE, VARY};
    !headers.contains_key(SET_COOKIE)
        && !headers.get_all(CACHE_CONTROL).iter().any(|value| {
            value.to_str().map_or(true, |value| {
                value.split(',').any(|directive| {
                    let name = directive.split('=').next().unwrap_or("").trim();
                    ["no-store", "no-cache", "private"]
                        .iter()
                        .any(|v| name.eq_ignore_ascii_case(v))
                })
            })
        })
        && !headers.get_all(VARY).iter().any(|value| {
            value
                .to_str()
                .map_or(true, |s| s.split(',').any(|v| v.trim() == "*"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upstream_cache_directives_and_cookies_disable_storage() {
        use reqwest::header::{CACHE_CONTROL, HeaderMap, HeaderValue, SET_COOKIE, VARY};
        let mut headers = HeaderMap::new();
        assert!(allows_cache(&headers));
        for directive in ["no-store", "public, No-Cache", "private=\"set-cookie\""] {
            headers.insert(CACHE_CONTROL, HeaderValue::from_str(directive).unwrap());
            assert!(!allows_cache(&headers));
        }
        headers.clear();
        headers.append(CACHE_CONTROL, HeaderValue::from_static("public"));
        headers.append(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        assert!(!allows_cache(&headers));
        headers.clear();
        headers.insert(SET_COOKIE, HeaderValue::from_static("session=abc"));
        assert!(!allows_cache(&headers));
        headers.clear();
        headers.insert(VARY, HeaderValue::from_static("Accept-Encoding, *"));
        assert!(!allows_cache(&headers));
    }
    #[tokio::test]
    async fn framing() {
        assert_eq!(
            read_request(&mut &b"http://example.org/\r\n"[..])
                .await
                .ok()
                .unwrap(),
            "http://example.org/"
        );
        for request in [
            b"http://example.org/\n".to_vec(),
            vec![b'x'; 1027],
            b"abc".to_vec(),
            b"a\rb\r\n".to_vec(),
        ] {
            assert!(read_request(&mut request.as_slice()).await.is_err());
        }
        let request = format!("{}\r\n", "x".repeat(1024));
        assert!(read_request(&mut request.as_bytes()).await.is_ok());
    }
    #[test]
    fn validates_target_and_response_framing() {
        assert!(target("https://example.org/").is_ok());
        assert_eq!(target("gemini://example.org/").err().unwrap().status, 53);
        for url in [
            "http://user:pass@example.org",
            "http://example.org/\n",
            "relative",
        ] {
            assert!(target(url).is_err());
        }
        assert_eq!(
            Response::error(43, "oops\r\ninjection").wire(),
            b"43 oopsinjection\r\n"
        );
    }
    #[tokio::test]
    async fn upstream_redirect_html_plain_and_errors() {
        use tokio::{io::AsyncWriteExt, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..5 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                let n = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..n]);
                let response = if request.starts_with("GET /redirect ") {
                    "HTTP/1.1 302 Found\r\nLocation: /dir/page\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
                } else {
                    let (status, mime, body) = if request.starts_with("GET /plain ") {
                        ("200 OK", "text/plain", "# literal")
                    } else if request.starts_with("GET /missing ") {
                        ("404 Not Found", "text/html", "missing")
                    } else if request.starts_with("GET /image ") {
                        ("200 OK", "image/png", "binary")
                    } else {
                        (
                            "200 OK",
                            "text/html; charset=utf-8",
                            "<p>Hello <a href='next'>next</a></p>",
                        )
                    };
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("public.example", address)
            .build()
            .unwrap();
        let guard = crate::abuse::Guard::new(crate::abuse::Limits {
            destination_burst: 20,
            ..Default::default()
        });
        let fetcher = Fetcher {
            guard,
            dns: crate::destination::Dns::Fixture(std::collections::HashMap::from([(
                "public.example".into(),
                vec!["8.8.8.8".parse().unwrap()],
            )])),
            full_page: false,
            parsers: None,
            fixture_client: Some(client),
        };
        let response = fetcher.fetch("http://public.example/redirect").await;
        assert_eq!(response.status, 20);
        assert!(
            response
                .text()
                .contains("=> http://public.example/dir/next")
        );
        assert!(
            fetcher
                .fetch("http://public.example/plain")
                .await
                .text()
                .contains("# literal")
        );
        assert_eq!(
            fetcher.fetch("http://public.example/missing").await.status,
            51
        );
        assert_eq!(
            fetcher.fetch("http://public.example/image").await.status,
            20
        );
        task.await.unwrap();
    }
    struct Fixture {
        fetcher: Fetcher,
        count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn fixture(wire: Vec<u8>, limits: crate::abuse::Limits) -> Fixture {
        fixture_with_delay(wire, limits, std::time::Duration::ZERO).await
    }
    async fn fixture_with_delay(
        wire: Vec<u8>,
        limits: crate::abuse::Limits,
        delay: std::time::Duration,
    ) -> Fixture {
        fixture_sequence(vec![wire], limits, delay).await
    }
    async fn fixture_sequence(
        wires: Vec<Vec<u8>>,
        limits: crate::abuse::Limits,
        delay: std::time::Duration,
    ) -> Fixture {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tokio::{io::AsyncWriteExt, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let task = tokio::spawn(async move {
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        let index = observed.fetch_add(1, Ordering::SeqCst);
                        let wire = wires[index.min(wires.len() - 1)].clone();
                        jobs.spawn(async move {
                            let mut request = Vec::new();
                            let mut buffer = [0; 1024];
                            while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
                                let n = socket.read(&mut buffer).await.unwrap_or(0);
                                if n == 0 { return; }
                                request.extend_from_slice(&buffer[..n]);
                            }
                            tokio::time::sleep(delay).await;
                            let _ = socket.write_all(&wire).await;
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
        });
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("public.example", address)
            .resolve("private.example", address)
            .build()
            .unwrap();
        Fixture {
            fetcher: Fetcher {
                guard: crate::abuse::Guard::new(limits),
                dns: crate::destination::Dns::Fixture(std::collections::HashMap::from([
                    ("public.example".into(), vec!["8.8.8.8".parse().unwrap()]),
                    ("private.example".into(), vec!["127.0.0.1".parse().unwrap()]),
                ])),
                full_page: false,
                parsers: None,
                fixture_client: Some(client),
            },
            count,
            task,
        }
    }
    fn http(headers: &str, body: &[u8]) -> Vec<u8> {
        let mut wire = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(body);
        wire
    }
    #[tokio::test]
    async fn redirects_carry_cache_restrictions_through_to_success_and_errors() {
        use std::{sync::atomic::Ordering, time::Duration};
        for restriction in [
            "Cache-Control: no-store",
            "Cache-Control: private",
            "Cache-Control: no-cache",
            "Set-Cookie: session=abc",
            "Vary: *",
        ] {
            for final_status in ["200 OK", "404 Not Found"] {
                let first = format!("HTTP/1.1 302 Found\r\nLocation: /second\r\n{restriction}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes();
                let second = b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
                let final_response = format!("HTTP/1.1 {final_status}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").into_bytes();
                let f = fixture_sequence(
                    vec![
                        first.clone(),
                        second.clone(),
                        final_response.clone(),
                        first,
                        second,
                        final_response,
                    ],
                    crate::abuse::Limits {
                        global_burst: 20,
                        destination_burst: 20,
                        ..Default::default()
                    },
                    Duration::ZERO,
                )
                .await;
                let cache = crate::cache::Cache::new(4096, Duration::from_secs(60));
                for _ in 0..2 {
                    let result = serve_proxy(&f.fetcher, &cache, "http://public.example/").await;
                    assert!(result.starts_with(if final_status == "200 OK" {
                        b"20 "
                    } else {
                        b"51 "
                    }));
                }
                assert_eq!(
                    f.count.load(Ordering::SeqCst),
                    6,
                    "{restriction}: {final_status}"
                );
                assert_eq!(cache.stats().hits.load(Ordering::Relaxed), 0);
            }
        }
    }
    #[tokio::test]
    async fn upstream_throttling_is_never_cached() {
        use std::{sync::atomic::Ordering, time::Duration};
        let f = fixture_sequence(
            vec![
                b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
                http("Content-Type: text/plain\r\n", b"Recovered"),
            ],
            Default::default(),
            Duration::ZERO,
        )
        .await;
        let cache = crate::cache::Cache::new(4096, Duration::from_secs(60));
        assert!(
            serve_proxy(&f.fetcher, &cache, "http://public.example/")
                .await
                .starts_with(b"44 ")
        );
        assert!(
            serve_proxy(&f.fetcher, &cache, "http://public.example/")
                .await
                .ends_with(b"Recovered")
        );
        assert_eq!(f.count.load(Ordering::SeqCst), 2);
    }
    fn compress(encoding: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        match encoding {
            "gzip" => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "br" => {
                let mut compressed = Vec::new();
                {
                    let mut encoder = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
                    encoder.write_all(body).unwrap();
                }
                compressed
            }
            "zstd" => zstd::stream::encode_all(body, 0).unwrap(),
            _ => unreachable!(),
        }
    }
    #[tokio::test]
    async fn redirects_to_private_ips_ports_schemes_and_dns_rebinding_never_connect() {
        use std::sync::{Arc, Mutex, atomic::Ordering};
        for location in [
            "http://127.0.0.1/",
            "http://private.example/",
            "http://public.example:8080/",
            "file:///etc/passwd",
        ] {
            let f = fixture(format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").into_bytes(), Default::default()).await;
            assert_eq!(
                f.fetcher.fetch("http://public.example/").await.status,
                53,
                "{location}"
            );
            assert_eq!(f.count.load(Ordering::SeqCst), 1);
        }
        let mut f = fixture(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec(), Default::default()).await;
        f.fetcher.dns = crate::destination::Dns::Changing {
            host: "public.example".into(),
            answers: Arc::new(Mutex::new(std::collections::VecDeque::from([
                vec!["8.8.8.8".parse().unwrap()],
                vec!["127.0.0.1".parse().unwrap()],
            ]))),
        };
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 53);
        assert_eq!(f.count.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn declared_chunked_compressed_and_decoded_body_limits_are_enforced() {
        let limits = crate::abuse::Limits {
            input_bytes: 128,
            ..Default::default()
        };
        let f = fixture(
            http("Content-Type: text/plain\r\n", &[b'x'; 1024]),
            limits.clone(),
        )
        .await;
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 59);
        let mut chunked = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n".to_vec();
        chunked.extend_from_slice(&[b'x'; 1024]);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let f = fixture(chunked, limits.clone()).await;
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 59);
        for encoding in ["gzip", "br", "zstd"] {
            let compressed = compress(encoding, &[b'x'; 4096]);
            assert!(compressed.len() < 128);
            let f = fixture(
                http(
                    &format!("Content-Type: text/plain\r\nContent-Encoding: {encoding}\r\n"),
                    &compressed,
                ),
                limits.clone(),
            )
            .await;
            let response = f.fetcher.fetch("http://public.example/").await;
            assert_eq!(response.status, 59, "{encoding}");
            assert!(response.meta.contains("Decompressed"), "{encoding}");
        }
        let f = fixture(
            http(
                "Content-Type: text/html; charset=windows-1252\r\n",
                &[0xff; 100],
            ),
            limits,
        )
        .await;
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 59);
    }
    #[tokio::test]
    async fn successful_compressed_text_and_output_limits() {
        for encoding in ["gzip", "br", "zstd"] {
            for mime in ["text/html", "text/plain"] {
                let body = b"<h1>Compressed page</h1>";
                let compressed = compress(encoding, body);
                let f = fixture(
                    http(
                        &format!("Content-Type: {mime}\r\nContent-Encoding: {encoding}\r\n"),
                        &compressed,
                    ),
                    Default::default(),
                )
                .await;
                let response = f.fetcher.fetch("http://public.example/").await;
                assert_eq!(response.status, 20, "{encoding}: {mime}");
                if mime == "text/html" {
                    assert!(response.text().contains("# Compressed page"), "{encoding}");
                } else {
                    assert_eq!(response.body, body, "{encoding}");
                }
            }
        }
        for mime in ["text/html", "text/plain", "text/gemini"] {
            let f = fixture(
                http(&format!("Content-Type: {mime}\r\n"), &[b'x'; 128]),
                crate::abuse::Limits {
                    output_bytes: 64,
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(
                f.fetcher.fetch("http://public.example/").await.status,
                59,
                "{mime}"
            );
        }
    }
    #[tokio::test]
    async fn redirect_count_and_overall_deadline_are_bounded() {
        use std::{sync::atomic::Ordering, time::Duration};
        let wire = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec();
        let f = fixture(
            wire.clone(),
            crate::abuse::Limits {
                redirects: 2,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 43);
        assert_eq!(f.count.load(Ordering::SeqCst), 3);
        let f = fixture_with_delay(
            wire,
            crate::abuse::Limits {
                timeout: Duration::from_millis(100),
                ..Default::default()
            },
            Duration::from_millis(60),
        )
        .await;
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 44);
        assert_eq!(f.count.load(Ordering::SeqCst), 2);
        assert!(f.fetcher.guard.fetch().is_ok());
    }
    #[tokio::test]
    async fn cache_hits_still_cost_client_tokens_but_not_upstream_tokens() {
        use std::{sync::atomic::Ordering, time::Duration};
        let f = fixture(
            http("Content-Type: text/html\r\n", b"<p>Cached page</p>"),
            crate::abuse::Limits {
                client_burst: 2,
                global_burst: 1,
                ..Default::default()
            },
        )
        .await;
        let cache = crate::cache::Cache::new(4096, Duration::from_secs(60));
        let ip = "1.2.3.4".parse().unwrap();
        assert!(f.fetcher.guard.client(ip).is_ok());
        let first = serve_proxy(&f.fetcher, &cache, "http://PUBLIC.example./#a").await;
        assert!(first.starts_with(b"20 "));
        assert!(f.fetcher.guard.client(ip).is_ok());
        let second = serve_proxy(&f.fetcher, &cache, "http://public.example/#b").await;
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert!(f.fetcher.guard.client(ip).is_err());
        assert_eq!(f.count.load(Ordering::SeqCst), 1);
        assert_eq!(cache.stats().hits.load(Ordering::Relaxed), 1);
        assert!(!f.fetcher.guard.global().is_ok());
    }
    #[tokio::test]
    async fn exhausted_fetch_and_parser_capacity_is_bounded() {
        use std::time::Duration;
        let f = fixture(
            http("Content-Type: text/html\r\n", b"<p>Page</p>"),
            crate::abuse::Limits {
                fetches: 1,
                parsers: 1,
                timeout: Duration::from_millis(50),
                ..Default::default()
            },
        )
        .await;
        let fetch = f.fetcher.guard.fetch().unwrap();
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 44);
        drop(fetch);
        let parser = f
            .fetcher
            .guard
            .parsers
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 44);
        drop(parser);
        assert_eq!(f.fetcher.fetch("http://public.example/").await.status, 20);
    }
    #[tokio::test]
    async fn unicode_url_expansion_is_not_mistaken_for_an_oversized_gemini_request() {
        let f = fixture(
            http("Content-Type: text/html\r\n", b"<p>Unicode path</p>"),
            Default::default(),
        )
        .await;
        let cache = crate::cache::Cache::new(8192, std::time::Duration::from_secs(60));
        let request = format!("http://public.example/{}", "漢".repeat(200));
        assert!(request.len() < 1024);
        assert!(target(&request).unwrap().as_str().len() > 1024);
        assert!(
            serve_proxy(&f.fetcher, &cache, &request)
                .await
                .starts_with(b"20 ")
        );
    }
    #[tokio::test]
    async fn non_html_bodies_keep_original_mime_and_every_byte_and_can_be_cached() {
        use std::{sync::atomic::Ordering, time::Duration};
        let payload = (0u8..=255).collect::<Vec<_>>();
        for mime in [
            "image/jpeg",
            "image/png",
            "application/pdf",
            "text/plain; charset=windows-1252",
            "text/gemini",
            "application/octet-stream",
        ] {
            let f = fixture(
                http(&format!("Content-Type: {mime}\r\n"), &payload),
                Default::default(),
            )
            .await;
            let cache = crate::cache::Cache::new(4096, Duration::from_secs(60));
            let first = serve_proxy(&f.fetcher, &cache, "http://public.example/file").await;
            let mut expected = format!("20 {mime}\r\n").into_bytes();
            expected.extend_from_slice(&payload);
            assert_eq!(first.as_ref(), expected, "{mime}");
            assert!(std::sync::Arc::ptr_eq(
                &first,
                &serve_proxy(&f.fetcher, &cache, "http://public.example/file").await
            ));
            assert_eq!(f.count.load(Ordering::SeqCst), 1);
        }
        let f = fixture(http("", &payload), Default::default()).await;
        let response = f.fetcher.fetch("http://public.example/file").await;
        assert_eq!(response.meta, "application/octet-stream");
        assert_eq!(response.body, payload);
    }
    #[tokio::test]
    async fn raw_responses_keep_size_limits_and_do_not_wait_for_html_parsers() {
        let f = fixture(
            http("Content-Type: image/jpeg\r\n", &[0xff; 128]),
            crate::abuse::Limits {
                parsers: 1,
                ..Default::default()
            },
        )
        .await;
        let _held = f
            .fetcher
            .guard
            .parsers
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            f.fetcher.fetch("http://public.example/image"),
        )
        .await
        .unwrap();
        assert_eq!(response.status, 20);
        assert_eq!(response.body, vec![0xff; 128]);
        let f = fixture(
            http("Content-Type: image/jpeg\r\n", &[0xff; 128]),
            crate::abuse::Limits {
                output_bytes: 64,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(
            f.fetcher.fetch("http://public.example/image").await.status,
            59
        );
    }
}
