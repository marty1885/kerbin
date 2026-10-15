mod abuse;
mod cache;
mod destination;
mod landing;
mod parser;
mod proxy;
mod render;
mod sandbox;

use anyhow::{Context, Result};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

/// A Gemini TLS proxy that renders HTTP/HTTPS pages as Gemtext.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Listener for the Gemini guide and robots.txt only.
    #[arg(long, default_value = "127.0.0.1:1965")]
    capsule_listen: SocketAddr,
    /// Listener for HTTP/HTTPS proxy requests only.
    #[arg(long, default_value = "127.0.0.1:1964")]
    proxy_listen: SocketAddr,
    /// PEM certificate chain presented to Gemini clients.
    #[arg(long)]
    cert: PathBuf,
    /// PEM private key matching the certificate.
    #[arg(long)]
    key: PathBuf,
    /// Render the whole page instead of automatically extracting articles.
    #[arg(long)]
    full_page: bool,
    /// Maximum lifetime of cached pages, measured from fetch completion (0 disables storage).
    #[arg(long, default_value_t = 300)]
    cache_ttl_secs: u32,
    /// Total cache byte budget, including URL keys and an entry bookkeeping allowance.
    #[arg(long, default_value_t = 67_108_864)]
    cache_max_bytes: usize,
    #[command(flatten)]
    safety: abuse::Options,
}

fn main() -> Result<()> {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--parser-supervisor")) {
        return parser::supervise();
    }
    let args = Args::parse();
    // Start supervisors before loading TLS secrets or creating worker threads.
    let parsers = parser::Pool::new(args.safety.limits().parsers)?;
    let certs = CertificateDer::pem_file_iter(&args.cert)
        .context("Read certificate file")?
        .collect::<Result<Vec<_>, _>>()
        .context("Parse certificate chain")?;
    let key = PrivateKeyDer::from_pem_file(&args.key).context("Read private key")?;
    // Construct configs independently so TLS session caches are not shared.
    let capsule_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())
        .context("Configure capsule TLS")?;
    let proxy_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Configure proxy TLS")?;
    let capsule_acceptor = TlsAcceptor::from(Arc::new(capsule_config));
    let proxy_acceptor = TlsAcceptor::from(Arc::new(proxy_config));
    sandbox::install(&parsers.descriptors()).context("Install mandatory process sandbox")?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Start confined Tokio runtime")?
        .block_on(serve(args, capsule_acceptor, proxy_acceptor, parsers))
}

struct ProxyService {
    fetcher: proxy::Fetcher,
    cache: cache::Cache,
}
enum Handler {
    Capsule,
    Proxy(Box<ProxyService>),
}
struct Endpoint {
    acceptor: TlsAcceptor,
    guard: abuse::Guard,
    handler: Handler,
}
impl Endpoint {
    async fn respond(&self, request: &str) -> cache::Wire {
        match &self.handler {
            Handler::Capsule => {
                let response = landing::serve(request);
                if response.status == 53 {
                    self.guard
                        .stats
                        .denied
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                response.wire().into()
            }
            Handler::Proxy(service) => {
                proxy::serve_proxy(&service.fetcher, &service.cache, request).await
            }
        }
    }
}

async fn serve(
    args: Args,
    capsule_acceptor: TlsAcceptor,
    proxy_acceptor: TlsAcceptor,
    parsers: parser::Pool,
) -> Result<()> {
    let guard = abuse::Guard::new(args.safety.limits());
    let fetcher = proxy::Fetcher::new(guard.clone(), args.full_page, parsers)
        .context("Initialize confined DNS resolver")?;
    let cache = cache::Cache::new(
        args.cache_max_bytes,
        Duration::from_secs(args.cache_ttl_secs.into()),
    );
    let capsule_guard = abuse::Guard::new(args.safety.limits());
    let capsule_stats = capsule_guard.stats.clone();
    let stats = guard.stats.clone();
    let cache_stats = cache.stats();
    tokio::spawn(async move {
        use std::sync::atomic::Ordering::Relaxed;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            eprintln!(
                "proxy stats cache_hits={} shared={} misses={} denied={} throttled={} busy={} resource_rejected={} timeouts={} upstream_errors={} transport_errors={}",
                cache_stats.hits.load(Relaxed),
                cache_stats.shared.load(Relaxed),
                cache_stats.misses.load(Relaxed),
                stats.denied.load(Relaxed),
                stats.throttled.load(Relaxed),
                stats.busy.load(Relaxed),
                stats.oversized.load(Relaxed),
                stats.timed_out.load(Relaxed),
                stats.upstream.load(Relaxed),
                stats.transport.load(Relaxed)
            );
            eprintln!(
                "capsule stats denied={} throttled={} busy={} transport_errors={}",
                capsule_stats.denied.load(Relaxed),
                capsule_stats.throttled.load(Relaxed),
                capsule_stats.busy.load(Relaxed),
                capsule_stats.transport.load(Relaxed)
            );
        }
    });
    let capsule_listener = TcpListener::bind(args.capsule_listen)
        .await
        .context("Bind capsule listener")?;
    let proxy_listener = TcpListener::bind(args.proxy_listen)
        .await
        .context("Bind proxy listener")?;
    let capsule = Arc::new(Endpoint {
        acceptor: capsule_acceptor,
        guard: capsule_guard,
        handler: Handler::Capsule,
    });
    let proxy = Arc::new(Endpoint {
        acceptor: proxy_acceptor,
        guard,
        handler: Handler::Proxy(Box::new(ProxyService { fetcher, cache })),
    });
    eprintln!(
        "Kerbin capsule listening on {}",
        capsule_listener.local_addr()?
    );
    eprintln!("Kerbin proxy listening on {}", proxy_listener.local_addr()?);
    loop {
        let (socket, peer, endpoint) = tokio::select! {
            result = capsule_listener.accept() => { let (socket, peer) = result?; (socket, peer, capsule.clone()) },
            result = proxy_listener.accept() => { let (socket, peer) = result?; (socket, peer, proxy.clone()) },
            _ = tokio::signal::ctrl_c() => break,
        };
        let guard = &endpoint.guard;
        let Ok(connection) = guard.connections.clone().try_acquire_owned() else {
            guard
                .stats
                .busy
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        };
        if !guard.handshake(peer.ip()) {
            continue;
        }
        let acceptor = endpoint.acceptor.clone();
        let guard = guard.clone();
        tokio::spawn(async move {
            let _connection = connection;
            let result: Result<()> = async {
                let mut stream =
                    timeout(Duration::from_secs(10), acceptor.accept(socket)).await??;
                let response = if let Err(response) = guard.client(peer.ip()) {
                    response.wire().into()
                } else {
                    match timeout(Duration::from_secs(10), proxy::read_request(&mut stream)).await {
                        Ok(Ok(request)) => endpoint.respond(&request).await,
                        Ok(Err(response)) => response.wire().into(),
                        Err(_) => proxy::Response::error(59, "Request timed out")
                            .wire()
                            .into(),
                    }
                };
                timeout(Duration::from_secs(30), async {
                    stream.write_all(&response).await?;
                    stream.shutdown().await
                })
                .await??;
                Ok(())
            }
            .await;
            if result.is_err() {
                guard
                    .stats
                    .transport
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }
    Ok(())
}
