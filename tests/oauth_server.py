"""Dummy OAuth HTTP server for testing OAUTHBEARER authentication."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _OAuthHandler(BaseHTTPRequestHandler):
    """Handler for the three OAuth endpoints."""

    def do_GET(self) -> None:
        if self.path == "/.well-known/openid-configuration":
            server = self.server
            assert isinstance(server, DummyOAuthServer)
            port = server.server_port
            devauth_port = server.devauth_port
            body = json.dumps(
                {
                    "issuer": f"http://localhost:{port}",
                    "token_endpoint": f"http://localhost:{port}/token",
                    "device_authorization_endpoint": (
                        f"http://localhost:{devauth_port}/devauth"
                    ),
                }
            )
            self._respond(200, body)
        else:
            self._respond(404, "Not Found")

    def do_POST(self) -> None:
        server = self.server
        assert isinstance(server, DummyOAuthServer)
        port = server.server_port

        if self.path == "/devauth":
            body = json.dumps(
                {
                    "device_code": "42",
                    "user_code": "666",
                    "verification_uri": f"http://localhost:{port}/verify",
                    "expires_in": 60,
                }
            )
            self._respond(200, body)
        elif self.path == "/token":
            body = json.dumps({"access_token": "yes", "token_type": ""})
            self._respond(200, body)
        else:
            self._respond(404, "Not Found")

    def _respond(self, code: int, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format: str, *args: object) -> None:
        # Suppress request logging during tests
        pass


class DummyOAuthServer(HTTPServer):
    """Minimal OIDC discovery, device auth, and token endpoints.

    Usage::

        with DummyOAuthServer(port=0) as server:
            # server.server_port has the actual port
            ...
    """

    def __init__(self, port: int = 0, devauth_port: int | None = None):
        super().__init__(("127.0.0.1", port), _OAuthHandler)
        self.devauth_port = (
            devauth_port if devauth_port is not None else self.server_port
        )
        self._thread: threading.Thread | None = None

    def __enter__(self) -> DummyOAuthServer:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown()
        self.server_close()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
