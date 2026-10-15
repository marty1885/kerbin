//! Conservative public-address policy based on IANA special-purpose registries.
use crate::proxy::{Response, target};
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use reqwest::{
    Client,
    dns::{Addrs, Name, Resolve, Resolving},
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use url::{Host, Url};

#[derive(Debug)]
struct Denied;
impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prohibited destination")
    }
}
impl std::error::Error for Denied {}

pub fn validate(url: &Url) -> Result<(), Response> {
    target(url.as_str())?;
    let port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => unreachable!(),
    };
    if url.port_or_known_default() != Some(port) {
        return Err(Response::error(
            53,
            "Only HTTP port 80 and HTTPS port 443 are allowed",
        ));
    }
    match url.host().unwrap() {
        Host::Ipv4(ip) if !public_ip(ip.into()) => {
            Err(Response::error(53, "Prohibited destination address"))
        }
        Host::Ipv6(ip) if !public_ip(ip.into()) => {
            Err(Response::error(53, "Prohibited destination address"))
        }
        Host::Domain(host)
            if !host.contains('.')
                || host.ends_with(".localhost")
                || host.ends_with(".local")
                || host.ends_with(".onion") =>
        {
            Err(Response::error(53, "Prohibited destination hostname"))
        }
        _ => Ok(()),
    }
}
fn v4_prefix(ip: u32, net: u32, bits: u32) -> bool {
    ip >> (32 - bits) == net >> (32 - bits)
}
fn v6_prefix(ip: u128, net: u128, bits: u32) -> bool {
    ip >> (128 - bits) == net >> (128 - bits)
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            ![
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 4),
                (0xf0000000, 4),
            ]
            .into_iter()
            .any(|(net, bits)| v4_prefix(n, net, bits))
        }
        IpAddr::V6(ip) => {
            let n = u128::from(ip);
            // Permit native global unicast only. Excludes mapped/compatible IPv4,
            // NAT64, ULA, link-local, multicast, and transition mechanisms.
            v6_prefix(n, 0x2000u128 << 112, 3)
                && ![
                    (0x20010000u128 << 96, 23),
                    (0x20010db8u128 << 96, 32),
                    (0x2002u128 << 112, 16),
                    (0x3fff0u128 << 108, 20),
                ]
                .into_iter()
                .any(|(net, bits)| v6_prefix(n, net, bits))
        }
    }
}
pub fn checked_answers(ips: Vec<IpAddr>) -> Result<Vec<IpAddr>, Response> {
    if ips.is_empty() {
        return Err(Response::error(43, "DNS returned no addresses"));
    }
    if ips.len() > 32 {
        return Err(Response::error(53, "Too many destination addresses"));
    }
    if ips.iter().any(|ip| !public_ip(*ip)) {
        return Err(Response::error(
            53,
            "DNS returned a prohibited destination address",
        ));
    }
    let mut ips = ips;
    ips.sort();
    ips.dedup();
    Ok(ips)
}
#[derive(Clone)]
pub enum Dns {
    Real(Arc<TokioResolver>),
    #[cfg(test)]
    Fixture(std::collections::HashMap<String, Vec<IpAddr>>),
    #[cfg(test)]
    Changing {
        host: String,
        answers: Arc<std::sync::Mutex<std::collections::VecDeque<Vec<IpAddr>>>>,
    },
}
impl Dns {
    pub fn new() -> anyhow::Result<Self> {
        let mut builder = TokioResolver::builder_tokio()?;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        // Do not append search domains to user-supplied destination names.
        Ok(Self::Real(Arc::new(builder.build())))
    }
    pub async fn lookup(&self, url: &Url) -> Result<Vec<IpAddr>, Response> {
        validate(url)?;
        let ips = match url.host().unwrap() {
            Host::Ipv4(ip) => vec![ip.into()],
            Host::Ipv6(ip) => vec![ip.into()],
            Host::Domain(host) => match self {
                Self::Real(resolver) => resolver
                    .lookup_ip(format!("{host}."))
                    .await
                    .map_err(|_| Response::error(43, "Could not resolve destination"))?
                    .iter()
                    .collect(),
                #[cfg(test)]
                Self::Fixture(answers) => answers.get(host).cloned().unwrap_or_default(),
                #[cfg(test)]
                Self::Changing {
                    host: expected,
                    answers,
                } => {
                    if host == expected {
                        answers.lock().unwrap().pop_front().unwrap_or_default()
                    } else {
                        vec![]
                    }
                }
            },
        };
        checked_answers(ips)
    }
}
// reqwest connects using these exact, previously checked addresses; there is no
// second DNS lookup between validation and connect. URL/Host/TLS SNI stay intact.
struct Pinned {
    host: String,
    ips: Vec<IpAddr>,
}
impl Resolve for Pinned {
    fn resolve(&self, name: Name) -> Resolving {
        let result: Result<Addrs, Box<dyn std::error::Error + Send + Sync>> =
            if name.as_str() == self.host {
                Ok(Box::new(
                    self.ips
                        .iter()
                        .map(|ip| SocketAddr::new(*ip, 0))
                        .collect::<Vec<_>>()
                        .into_iter(),
                ))
            } else {
                Err(Box::new(Denied))
            };
        Box::pin(async move { result })
    }
}
pub fn client(
    url: &Url,
    ips: Vec<IpAddr>,
    timeout: std::time::Duration,
) -> Result<Client, Response> {
    validate(url)?;
    let ips = checked_answers(ips)?;
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(Pinned {
            host: url.host_str().unwrap().to_string(),
            ips,
        }))
        .user_agent(concat!("Kerbin/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(std::time::Duration::from_secs(10))
        .referer(false)
        .build()
        .map_err(|_| Response::error(43, "Could not initialize upstream client"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn special_addresses_and_obfuscated_urls_are_blocked() {
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::a00:1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002:a00:1::",
            "3fff::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.215.14",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
        for url in [
            "http://2130706433/",
            "http://0x7f000001/",
            "http://127.1/",
            "http://0177.0.0.1/",
            "http://[::ffff:127.0.0.1]/",
            "http://example.org:8080/",
            "https://example.org:80/",
            "http://localhost/",
            "http://example.local/",
            "file:///etc/passwd",
        ] {
            assert!(validate(&Url::parse(url).unwrap()).is_err(), "{url}");
        }
        assert!(validate(&Url::parse("https://example.org/").unwrap()).is_ok());
    }
    #[test]
    fn mixed_answers_fail_closed_and_answers_are_bounded() {
        assert!(
            checked_answers(vec![
                "8.8.8.8".parse().unwrap(),
                "127.0.0.1".parse().unwrap()
            ])
            .is_err()
        );
        assert!(checked_answers(vec!["8.8.8.8".parse().unwrap(); 33]).is_err());
        assert!(checked_answers(vec![]).is_err());
    }
    #[tokio::test]
    async fn pinned_resolver_has_no_lookup_fallback() {
        let pinned = Pinned {
            host: "example.org".into(),
            ips: vec!["8.8.8.8".parse().unwrap()],
        };
        let ips: Vec<_> = pinned
            .resolve("example.org".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert_eq!(ips, vec!["8.8.8.8:0".parse::<SocketAddr>().unwrap()]);
        assert!(
            pinned
                .resolve("other.example".parse().unwrap())
                .await
                .is_err()
        );
    }
}
