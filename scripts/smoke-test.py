#!/usr/bin/env python3
"""Test the production TLS listener with mandatory sandboxing and abuse policy."""
import argparse
import contextlib
import http.server
import pathlib
import os
import select
import signal
import struct
import socket
import ssl
import subprocess
import tempfile
import threading
import time


class Fixture(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self):
        Fixture.requests += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"This local page must never be fetched.")

    def log_message(self, *_):
        pass


def verify_parser(binary):
    # Exercise the real confined supervisor, not the unit-test renderer.
    with subprocess.Popen([binary, "--parser-supervisor"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, bufsize=0) as process:
        def read_exact(size):
            data = bytearray()
            deadline = time.monotonic() + 10
            while len(data) < size:
                remaining = deadline - time.monotonic()
                assert remaining > 0 and select.select([process.stdout], [], [], remaining)[0], "Parser hung"
                chunk = os.read(process.stdout.fileno(), size - len(data))
                assert chunk, "Parser supervisor exited unexpectedly"
                data.extend(chunk)
            return bytes(data)

        def send_job(html, timeout_ms=1000, output_limit=4096):
            url = b"https://example.org/"
            payload = struct.pack(">QQBQQ", timeout_ms, output_limit, 0, len(url), len(html)) + url + html
            # Raw pipes can perform short writes.
            while payload:
                payload = payload[os.write(process.stdin.fileno(), payload):]

        def result():
            status = read_exact(1)[0]
            return status, read_exact(struct.unpack(">Q", read_exact(8))[0])

        def job(html, timeout_ms=1000, output_limit=4096):
            send_job(html, timeout_ms, output_limit)
            return result()

        assert read_exact(1) == b"R", "Parser sandbox failed startup self-check"
        assert job(b"<h1>Isolated page</h1>") == (0, b"# Isolated page\n\n")
        assert job(b"<p>Too much output</p>", output_limit=4) == (1, b"")
        assert job(b"<div>" * 200 + b"deep" + b"</div>" * 200) == (2, b"")
        start = time.monotonic()
        assert job(b"<span>x</span>" * 150000, timeout_ms=1) == (4, b""), "Parser did not enforce wall deadline"
        assert time.monotonic() - start < 5, "Parser timeout took too long"
        children = pathlib.Path(f"/proc/{process.pid}/task/{process.pid}/children")
        if children.exists():
            assert not children.read_text().strip(), "Timed-out parser was not reaped"
        assert job(b"<p>Recovered</p>") == (0, b"Recovered\n\n"), "Parser slot did not recover"
        if children.exists():
            # Verify actual OS limits, then simulate a parser crash and recover.
            send_job(b"<span>x</span>" * 150000, timeout_ms=5000)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                pids = children.read_text().split()
                if pids:
                    pid = int(pids[0])
                    try:
                        limits = pathlib.Path(f"/proc/{pid}/limits").read_text()
                    except FileNotFoundError:
                        continue
                    address_limit = next(line for line in limits.splitlines() if line.startswith("Max address space"))
                    if "536870912" in address_limit:
                        assert address_limit.split()[-3:-1] == ["536870912", "536870912"]
                        core_limit = next(line for line in limits.splitlines() if line.startswith("Max core file size"))
                        assert core_limit.split()[-3:-1] == ["0", "0"]
                        cpu_limit = next(line for line in limits.splitlines() if line.startswith("Max cpu time"))
                        assert "unlimited" not in cpu_limit
                        os.kill(pid, signal.SIGKILL)
                        break
                time.sleep(0.001)
            else:
                raise AssertionError("Could not verify parser memory/CPU limits")
            assert result() == (3, b""), "Parser crash was not contained"
            assert not children.read_text().strip(), "Crashed parser was not reaped"
            assert job(b"<p>Still alive</p>") == (0, b"Still alive\n\n")
        process.stdin.close()
        assert process.wait(timeout=10) == 0
    print("PASS: isolated parser, output/complexity limits, hard timeout and recovery (Linux: OS resource limits, crash containment, and child reaping)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/kerbin")
    parser.add_argument("--public-url", help="Optional real public-page fetch and cache check; omitted for offline tests")
    parser.add_argument("--image-url", help="Optional public image fetch and binary cache check")
    args = parser.parse_args()
    binary = str(pathlib.Path(args.binary).resolve())
    verify_parser(binary)
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="kerbin-smoke-") as directory:
            cert, key = [str(pathlib.Path(directory) / name) for name in ("cert.pem", "key.pem")]
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.create_default_context(cafile=cert)

            @contextlib.contextmanager
            def proxy(*flags):
                process = subprocess.Popen([binary, "--capsule-listen", "127.0.0.1:0", "--proxy-listen", "127.0.0.1:0", "--cert", cert, "--key", key, *flags],
                                           stderr=subprocess.PIPE, text=True)
                try:
                    ports = {}
                    for service in ["capsule", "proxy"]:
                        line = process.stderr.readline().strip()
                        if not line.startswith(f"Kerbin {service} listening on "):
                            process.wait(timeout=5)
                            raise AssertionError(f"Startup failed ({process.returncode}): {line} {process.stderr.read()}")
                        ports[service] = int(line.rsplit(":", 1)[1])
                    assert ports["capsule"] != ports["proxy"]
                    yield ports
                finally:
                    process.terminate()
                    process.wait(timeout=5)

            def request(port, payload, raw=False):
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname="localhost") as tls:
                        tls.settimeout(35)
                        tls.sendall(payload)
                        chunks = []
                        while chunk := tls.recv(65536):
                            chunks.append(chunk)
                        response = b"".join(chunks)
                        return response if raw else response.decode()

            with proxy() as ports:
                port = ports["capsule"]
                home = request(port, b"gemini://kerbin.northwire.xyz/\r\n")
                assert home.startswith("20 text/gemini; charset=utf-8\r\n"), home
                assert "Gemini-to-HTTP proxy" in home
                assert "kerbin.northwire.xyz:1964" in home
                assert "HTTP proxy field" in home
                assert request(port, b"gemini://kerbin.northwire.xyz:1965/index.gmi\r\n") == home
                assert "gemini://kerbin.northwire.xyz/privacy.gmi" in home
                privacy = request(port, b"gemini://kerbin.northwire.xyz/privacy.gmi\r\n")
                assert privacy.startswith("20 text/gemini; charset=utf-8\r\n# Privacy policy"), privacy
                assert "shared in-memory cache" in privacy
                assert request(port, b"gemini://kerbin.northwire.xyz/privacy\r\n") == privacy
                robots = request(port, b"gemini://kerbin.northwire.xyz/robots.txt\r\n")
                assert robots == "20 text/plain; charset=utf-8\r\nUser-agent: *\nDisallow: /\n", robots
                assert request(port, b"gemini://kerbin.northwire.xyz/missing\r\n").startswith("51 ")
                assert request(port, b"gemini://other.example/\r\n").startswith("53 ")
                assert request(port, b"gemini://kerbin.northwire.xyz:1966/\r\n").startswith("53 ")
                assert request(port, b"gemini://user@kerbin.northwire.xyz/\r\n").startswith("59 ")
                assert request(port, b"http://127.0.0.1/\r\n") == "53 Capsule listener accepts Gemini URLs only\r\n"
                assert request(ports["proxy"], b"gemini://kerbin.northwire.xyz/\r\n").startswith("53 ")
                assert request(ports["proxy"], b"gemini://kerbin.northwire.xyz/robots.txt\r\n").startswith("53 ")
                assert Fixture.requests == 0, "Landing page unexpectedly fetched upstream"

            with proxy() as ports:
                port = ports["proxy"]
                blocked = [
                    f"http://127.0.0.1:{fixture.server_port}/".encode(),
                    b"http://2130706433/", b"http://0x7f000001/",
                    b"http://[::ffff:127.0.0.1]/", b"http://169.254.169.254/",
                    b"https://example.org:8080/", b"gemini://example.org/",
                ]
                for url in blocked:
                    response = request(port, url + b"\r\n")
                    assert response.startswith("53 "), response
                for malformed in [b"http://example.org/\n", b"x" * 1027, b"\xff\r\n"]:
                    response = request(port, malformed)
                    assert response.startswith("59 "), response
                response = request(port, b"https://example.org/\r\n")
                assert response.startswith("44 "), response
                assert Fixture.requests == 0, "Prohibited local destination received traffic"

            # Raw sockets reserve TLS handshake slots; excess connections must
            # be rejected before allocating another per-connection task.
            with proxy("--max-connections", "1") as ports:
                port = ports["proxy"]
                with socket.create_connection(("127.0.0.1", port), timeout=5) as held:
                    time.sleep(0.05)
                    assert request(ports["capsule"], b"gemini://kerbin.northwire.xyz/\r\n").startswith("20 "), "Proxy saturation blocked the capsule"
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as excess:
                        try:
                            assert excess.recv(1) == b"", "Excess connection was accepted"
                        except ConnectionResetError:
                            pass

            with proxy("--client-burst", "2") as ports:
                for path in [b"/", b"/robots.txt"]:
                    assert request(ports["capsule"], b"gemini://kerbin.northwire.xyz" + path + b"\r\n").startswith("20 ")
                assert request(ports["capsule"], b"gemini://kerbin.northwire.xyz/\r\n").startswith("44 ")
                assert request(ports["proxy"], b"http://127.0.0.1/\r\n").startswith("53 "), "Capsule requests consumed proxy tokens"
                assert request(ports["proxy"], b"http://127.0.0.1/\r\n").startswith("53 ")
                assert request(ports["proxy"], b"http://127.0.0.1/\r\n").startswith("44 ")

            if args.public_url:
                with proxy() as ports:
                    port = ports["proxy"]
                    payload = args.public_url.encode() + b"\r\n"
                    page = request(port, payload)
                    assert page.startswith("20 text/gemini; charset=utf-8\r\n"), page
                    assert len(page.split("\r\n", 1)[1]) > 0, "Empty public page"
                    assert request(port, payload) == page, "Cached response differed"
                    print("PASS: real public-page fetch and cached response with confinement active")
            if args.image_url:
                with proxy() as ports:
                    payload = args.image_url.encode() + b"\r\n"
                    image = request(ports["proxy"], payload, raw=True)
                    header, separator, body = image.partition(b"\r\n")
                    assert separator and header.startswith(b"20 image/"), header
                    assert body, "Empty image body"
                    if args.image_url.lower().endswith((".jpg", ".jpeg")):
                        assert body.startswith(b"\xff\xd8") and body.endswith(b"\xff\xd9"), "JPEG bytes were corrupted"
                    assert request(ports["proxy"], payload, raw=True) == image, "Binary cache changed the response"
                    print(f"PASS: raw image response ({len(body)} bytes) and binary cache with confinement active")
            print("PASS: separate capsule/proxy listeners, cross-protocol rejection, independent admission limits, and proxy abuse controls")
    finally:
        fixture.shutdown()


if __name__ == "__main__":
    main()
