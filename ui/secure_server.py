#!/usr/bin/env python3
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


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


class SecureStaticHandler(SimpleHTTPRequestHandler):
    server_version = "TLSAuditHub"
    sys_version = ""

    def end_headers(self):
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        super().end_headers()


def main():
    bind = os.environ.get("UI_BIND", "0.0.0.0")
    port = int(os.environ.get("UI_PORT", "5173"))
    server = ThreadingHTTPServer((bind, port), SecureStaticHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
