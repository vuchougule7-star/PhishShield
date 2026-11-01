
"""Local-only HTTP server for the PhishShield student project."""

from __future__ import annotations

import json
import webbrowser
from threading import Timer
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from analyzer import MAX_EMAIL_CHARS, analyse_email

BASE_DIR = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8000
MAX_REQUEST_BYTES = MAX_EMAIL_CHARS * 4 + 20_000


class PhishShieldHandler(BaseHTTPRequestHandler):
    server_version = "PhishShieldLocal/1.0"

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, data: dict) -> None:
        self._send(
            status,
            json.dumps(data, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8"
        )

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path

        if path in {"/", "/index.html"}:
            try:
                html = (BASE_DIR / "index.html").read_bytes()
            except OSError:
                self._json(500, {"error": "The interface file is missing."})
                return

            self._send(200, html, "text/html; charset=utf-8")

        elif path == "/api/health":
            self._json(
                200,
                {"status": "ok", "mode": "local-only", "storage": "none"}
            )

        else:
            self._json(404, {"error": "Route not found."})

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/analyze":
            self._json(404, {"error": "Route not found."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "Invalid request length."})
            return

        if length <= 0:
            self._json(400, {"error": "Request body is empty."})
            return

        if length > MAX_REQUEST_BYTES:
            self._json(413, {"error": "Upload is larger than the 1 MB limit."})
            return

        try:
            body = self.rfile.read(length)
            data = json.loads(body.decode("utf-8"))

            if not isinstance(data, dict):
                raise ValueError("Request must be a JSON object.")

            content = data.get("content", "")
            filename = data.get("filename")

            if not isinstance(content, str):
                raise ValueError("Email content must be text.")

            if filename is not None and not isinstance(filename, str):
                raise ValueError("Filename must be text.")

            result = analyse_email(content, filename=filename)
            self._json(200, result)

        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(
                400,
                {
                    "error": "Invalid JSON. Please paste the email again "
                    "or choose a text .eml file."
                }
            )

        except ValueError as exc:
            self._json(400, {"error": str(exc)})

        except Exception:
            self._json(
                500,
                {
                    "error": "Analysis failed unexpectedly. "
                    "Try a smaller or different sample."
                }
            )

    def log_message(self, format: str, *args) -> None:
        print(
            f"[PhishShield] {self.address_string()} - "
            f"{format % args}"
        )


def create_server(
    host: str = HOST,
    port: int = PORT
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), PhishShieldHandler)


if __name__ == "__main__":
    server = create_server()

    Timer(
        1,
        lambda: webbrowser.open(f"http://{HOST}:{PORT}")
    ).start()

    print(f"PhishShield is running locally: http://{HOST}:{PORT}")
    print("Email content is analysed in memory and is not saved by the application.")
    print("Press Ctrl+C to stop the server.")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nShutting down PhishShield...")

    finally:
        server.server_close()
