# Kerbin

Kerbin is a small Rust web proxy for Gemini clients. Lagrange sends an HTTP or HTTPS URL to Kerbin over TLS, Kerbin fetches the page, and it returns UTF-8 Gemtext.

## Run

Kerbin supports Linux 6.3 or newer with Landlock and seccomp enabled, and OpenBSD with pledge and unveil (best effort; not yet compiled or tested on OpenBSD). Rust and OpenSSL 3.4 or newer are needed for the setup below. Kerbin does not generate or renew certificates, so create a local ECDSA P-256 certificate valid until 9999-12-31 first, then start it.

```sh
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -not_after 99991231235959Z \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
cargo run -- --cert certs/cert.pem --key certs/key.pem
```

Kerbin runs two listeners on loopback by default: the capsule on `127.0.0.1:1965` serves the Gemini landing page and privacy policy, and the proxy on `127.0.0.1:1964` handles web fetches. Change them with `--capsule-listen IP:PORT` and `--proxy-listen IP:PORT`, using numeric addresses only (for IPv6, use `[::1]:1965` and `[::1]:1964`). Both listeners must bind before Kerbin serves anything.

For public hosting, point `kerbin.northwire.xyz` at the server, provide a certificate that covers it, and bind both listeners to a public interface:

```sh
cargo run -- --capsule-listen 0.0.0.0:1965 --proxy-listen 0.0.0.0:1964 \
  --cert certs/cert.pem --key certs/key.pem
```

DNS and deployment are managed outside this repository.

## Use with Lagrange

In Lagrange, open **Preferences → Proxies** (the **Network** panel on mobile) and set the **HTTP** proxy to `localhost:1964`. Enter a host and port only, with no URL scheme, and include `:1964` because Lagrange defaults to port 1965. Accept the local certificate when prompted, then open any `http://` or `https://` URL. Browser HTTP proxy settings and HTTP CONNECT do not work with the proxy listener.

## Landing page

The capsule on port 1965 serves `gemini://kerbin.northwire.xyz/` and `/index.gmi` from `assets/index.gmi`, plus `/privacy.gmi` (also `/privacy`) from `assets/privacy.gmi`, which is compiled into the binary, so it needs no filesystem access or upstream fetch. `/robots.txt` disallows all crawlers, which is advisory only; admission limits still apply. Unknown paths return 51, and any other destination or HTTP request to the capsule returns 53.

## Behavior

- Fetches HTTP and HTTPS with verified upstream TLS, up to five validated redirects, and a 30-second deadline. Names resolve through Hickory using `/etc/resolv.conf` and `/etc/hosts`.
- Detects article pages with `dom_smoothie` (Readability) and keeps only the main content. Pass `--full-page` to keep navigation and everything else.
- Parses HTML without running JavaScript and renders titles, headings, paragraphs, lists, quotes, preformatted text, and basic tables.
- Turns links into numbered references in the prose and places Gemtext links after each paragraph. Web links stay as HTTP/HTTPS URLs, so Lagrange sends later visits through the proxy too.
- Decodes HTML entities and declared character sets, and uses reqwest for HTTP, TLS, and automatic gzip, Brotli, Zstandard, and deflate decompression.
- Converts only HTML and XHTML. Every other content type, including images, plain text, and PDFs, passes through with its original MIME type and bytes.
- Returns Gemini errors for bad requests, unsupported schemes or content, upstream failures, missing pages, and oversized responses.
- Supports one URL per TLS connection. It does not handle logins, cookies, form submissions, or JavaScript.

## Cache

The default cache holds **64 MiB** and expires each page **300 seconds** after its fetch completes. Cache hits do not extend that lifetime, and least recently used entries are evicted first. Set `--cache-ttl-secs 0` or `--cache-max-bytes 0` to disable storage.

```sh
cargo run -- --cert certs/cert.pem --key certs/key.pem \
  --cache-ttl-secs 120 --cache-max-bytes 33554432
```

Simultaneous requests for the same URL share one fetch. Responses marked `no-store`, `no-cache`, or `private`, responses with `Set-Cookie`, and responses with `Vary: *` are never stored. Upstream errors are cached for at most ten seconds.

## Abuse prevention

Kerbin fetches only public HTTP port 80 and HTTPS port 443 destinations. It rejects loopback, private, link-local, shared, documentation, benchmarking, multicast, reserved, and transition-mechanism addresses, following the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose registries. Every DNS answer must pass the policy, and each redirect hop is checked again. Connections go to the validated addresses while keeping the hostname for Host and SNI checks. Environment proxies are disabled.

Default limits:

| Control | Default | Option |
| --- | --- | --- |
| Connections per listener | 64 | `--max-connections` |
| Concurrent fetches | 8 | `--max-fetches` |
| Concurrent fetches per host or IP | 2 | `--max-fetches-per-destination` |
| Parser workers | 2 | `--max-parsers` |
| Decompressed input | 2 MiB | `--max-input-bytes` |
| Response body | 1 MiB | `--max-output-bytes` |
| Redirects | 5 | `--max-redirects` |
| Fetch deadline | 30 s | `--fetch-timeout-secs` |
| Client requests | 30/min, burst 10 | `--client-requests-per-minute`, `--client-burst` |
| Global fetch hops | 60/min, burst 10 | `--global-fetches-per-minute`, `--global-burst` |
| Per-destination fetches | 12/min, burst 6 | `--destination-fetches-per-minute`, `--destination-burst` |

Clients are identified by socket peer address, using the IPv4 address or IPv6 /64. Rejected requests, cache hits, and malformed requests all use client tokens. Rejections return **53**. Post-TLS throttling and deadline failures return **44**. Oversized bodies or overly complex HTML return **59**. Throttling is never cached.

## Process confinement

Kerbin reads its certificate and key, closes inherited descriptors other than standard input/output/error, then installs the platform sandbox before starting Tokio. If installation fails, startup fails; there is no fallback. Other operating systems are rejected.

- **Linux filesystem (Landlock ABI v3):** reads are limited to `/etc/resolv.conf`, `/etc/hosts`, and `/dev/urandom`. Writes, execution, and directory listing are denied.
- **Linux memory (MDWE):** `PR_SET_MDWE` with `PR_MDWE_REFUSE_EXEC_GAIN` is mandatory and inherited by workers. Writable/executable mappings and executable permission gains are denied; seccomp additionally rejects all `mmap`/`mprotect` calls requesting `PROT_EXEC`.
- **Linux syscalls (seccomp):** only memory, threads, clocks, signals, and TCP/UDP networking are allowed. Process execution, namespaces, mounts, tracing, io_uring, and raw sockets are denied.

On OpenBSD, the [priv_sep](https://docs.rs/crate/priv_sep/2.2.0) crate installs [unveil](https://man.openbsd.org/unveil.2) with read-only access to `/etc/resolv.conf`, `/etc/hosts`, and `/dev/urandom`, then locks the allowlist. [Pledge](https://man.openbsd.org/pledge.2) promises are limited to `stdio rpath inet` for the runtime, file reads, and Internet sockets. Process creation, execution, filesystem writes, Unix socket connections, and executable mappings are not promised. OpenBSD libc may internally access certain system files under `stdio`, as documented by pledge. This backend has not been compiled or run on OpenBSD; run the verification commands below on an OpenBSD host before deployment.

Kerbin does not restrict egress by network address; use kernel firewalling for that.

## Verify

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build
python3 scripts/smoke-test.py
```

The smoke test uses local servers and a temporary certificate to check TLS, listener separation, port and destination rejection, throttling, and the pre-TLS connection cap. Add `--public-url https://example.com/` to also test a live fetch and the cache. Unit tests use injected local transports to cover redirects, DNS rebinding, decompression limits, and cache admission.

Kerbin is built with [dom_smoothie](https://github.com/niklak/dom_smoothie), [scraper](https://docs.rs/scraper/), and [tokio-rustls](https://github.com/rustls/tokio-rustls).
