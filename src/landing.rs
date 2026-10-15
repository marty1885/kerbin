//! Built-in capsule content requires no filesystem access after confinement.
use crate::proxy::Response;
use url::Url;

const HOST: &str = "kerbin.northwire.xyz";
const INDEX: &str = include_str!("../assets/index.gmi");
const PRIVACY: &str = include_str!("../assets/privacy.gmi");
const ROBOTS: &str = "User-agent: *\nDisallow: /\n";

// The capsule listener never delegates to the HTTP/HTTPS proxy.
pub fn serve(request: &str) -> Response {
    let url = match Url::parse(request) {
        Ok(url) => url,
        Err(_) => return Response::error(59, "Invalid Gemini URL"),
    };
    if url.scheme() != "gemini" {
        return Response::error(53, "Capsule listener accepts Gemini URLs only");
    }
    if request.chars().any(|c| c.is_whitespace() || c.is_control())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Response::error(59, "Invalid Gemini URL");
    }
    if url
        .host_str()
        .is_none_or(|host| !host.trim_end_matches('.').eq_ignore_ascii_case(HOST))
        || url.port().unwrap_or(1965) != 1965
    {
        return Response::error(
            53,
            "Kerbin serves its own capsule; it does not proxy Gemini",
        );
    }
    match url.path() {
        "" | "/" | "/index.gmi" => Response {
            status: 20,
            meta: "text/gemini; charset=utf-8".into(),
            body: INDEX.as_bytes().to_vec(),
            cacheable: false,
        },
        "/privacy" | "/privacy.gmi" => Response {
            status: 20,
            meta: "text/gemini; charset=utf-8".into(),
            body: PRIVACY.as_bytes().to_vec(),
            cacheable: false,
        },
        "/robots.txt" => Response {
            status: 20,
            meta: "text/plain; charset=utf-8".into(),
            body: ROBOTS.as_bytes().to_vec(),
            cacheable: false,
        },
        _ => Response::error(51, "Page not found; visit gemini://kerbin.northwire.xyz/"),
    }
}
