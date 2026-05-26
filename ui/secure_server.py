#!/usr/bin/env python3
import http.client
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "credentialless",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self' "
        "http://localhost:8000 http://127.0.0.1:8000 "
        "http://host.docker.internal:8000 https://host.docker.internal:8000; "
        "form-action 'self'"
    ),
}

API_PROXY_PREFIX = "/api/"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class SecureStaticHandler(SimpleHTTPRequestHandler):
    server_version = "TLSAuditHub"
    sys_version = ""

    def end_headers(self):
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        super().end_headers()

    def do_GET(self):
        if self.path.startswith(API_PROXY_PREFIX):
            self._proxy_api_request()
            return
        super().do_GET()

    def do_POST(self):
        if self.path.startswith(API_PROXY_PREFIX):
            self._proxy_api_request()
            return
        self.send_error(501, "Unsupported method ('POST')")

    def do_PUT(self):
        if self.path.startswith(API_PROXY_PREFIX):
            self._proxy_api_request()
            return
        self.send_error(501, "Unsupported method ('PUT')")

    def do_PATCH(self):
        if self.path.startswith(API_PROXY_PREFIX):
            self._proxy_api_request()
            return
        self.send_error(501, "Unsupported method ('PATCH')")

    def do_DELETE(self):
        if self.path.startswith(API_PROXY_PREFIX):
            self._proxy_api_request()
            return
        self.send_error(501, "Unsupported method ('DELETE')")

    def do_OPTIONS(self):
        if self.path.startswith(API_PROXY_PREFIX):
            self._proxy_api_request()
            return
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def _proxy_api_request(self):
        upstream = urlsplit(os.environ.get("API_UPSTREAM", "http://api:8000"))
        upstream_host = upstream.hostname or "api"
        upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)
        upstream_path = self.path[len("/api"):] or "/"
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(content_length) if content_length > 0 else None

        forwarded_headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
        }
        forwarded_headers["Host"] = upstream.netloc or upstream_host
        forwarded_headers["X-Forwarded-For"] = self.client_address[0]
        forwarded_headers["X-Forwarded-Proto"] = self.headers.get(
            "X-Forwarded-Proto", "https" if self.server.server_port == 443 else "http"
        )
        forwarded_headers["X-Forwarded-Host"] = self.headers.get("Host", "")

        connection_class = (
            http.client.HTTPSConnection if upstream.scheme == "https" else http.client.HTTPConnection
        )
        connection = connection_class(upstream_host, upstream_port, timeout=60)
        try:
            connection.request(self.command, upstream_path, body=body, headers=forwarded_headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() in HOP_BY_HOP_HEADERS:
                    continue
                self.send_header(key, value)
            self.end_headers()
            if payload:
                self.wfile.write(payload)
        except OSError as exc:
            self.send_error(502, f"API upstream unavailable: {exc}")
        finally:
            connection.close()


def main():
    bind = os.environ.get("UI_BIND", "0.0.0.0")
    port = int(os.environ.get("UI_PORT", "5173"))
    server = ThreadingHTTPServer((bind, port), SecureStaticHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
