# Kerbin

A Rust based web proxy for Gemini clients for Lagrange (or any client that is willing to send a HTTP URL over Gemini)

## Run

Kerbin does not generate or renew certificates, so create a local ECDSA P-256 certificate valid until 9999-12-31 first, then start it.

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

## Use with Lagrange

In Lagrange, open **Preferences -> Proxies** (the **Network** panel on mobile) and set the **HTTP** proxy to `localhost:1964`. Enter a host and port only, with no URL scheme, and include `:1964` because Lagrange defaults to port 1965. Then open any `http://` or `https://` URL. Browser HTTP proxy settings and HTTP CONNECT do not work with the proxy listener.

## Behavior

- Fetches HTTP and HTTPS with verified upstream TLS, up to five redirects, and a 30-second deadline.
- Detects article pages with `dom_smoothie` (Readability) and keeps only the main content. Pass `--full-page` to keep navigation and everything else.
- Parses HTML without running JavaScript and renders titles, headings, paragraphs, lists, quotes, preformatted text, and basic tables.
- Runs each HTML parser in a disposable process with a 512 MiB address-space limit on Linux (data-segment limit on OpenBSD), a CPU limit, and a wall deadline within the fetch timeout. Supervisors kill and reap overdue workers before reusing the slot. Parser workers have no filesystem, network, execution, or process-creation access. Supervisors start before TLS keys are loaded; the network process still cannot create processes. OpenBSD remains best effort and untested.
- Turns links into numbered references in the prose and places Gemtext links after each paragraph. Web links stay as HTTP/HTTPS URLs, so Lagrange sends later visits through the proxy too.
- Handles gzip, brotil and zstd compressed responses
- Converts only HTML and XHTML. Every other content type, including images, plain text, and PDFs, passes through with its original MIME type and bytes.
- Returns Gemini errors for bad requests, unsupported schemes or content, upstream failures, missing pages, and oversized responses.
- Supports one URL per TLS connection. It does not handle logins, cookies, form submissions, or JavaScript.

## Cache

The default cache holds 64 MiB and expires each page 300 seconds after its fetch completes. Cache hits do not extend that lifetime, and least recently used entries are evicted first. Set `--cache-ttl-secs 0` or `--cache-max-bytes 0` to disable storage.

```sh
cargo run -- --cert certs/cert.pem --key certs/key.pem \
  --cache-ttl-secs 120 --cache-max-bytes 33554432
```

Simultaneous requests for the same URL share one fetch. Responses marked `no-store`, `no-cache`, or `private`, responses with `Set-Cookie`, and responses with `Vary: *` are never stored, including when those restrictions appear on any redirect in the chain. Upstream errors are cached for at most ten seconds.

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

Clients are identified by socket peer address, using the IPv4 address or IPv6 /64. Rejected requests, cache hits, and malformed requests all use client tokens. Rejections return **53**. Post-TLS throttling and deadline failures return **44**. Oversized bodies or overly complex HTML return **59**. Throttling is never cached. **DON'T PUT IT BEHIND A REVERSE PROXY**
