import json
from pathlib import Path
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_server  # noqa: E402


def test_health_and_analysis_endpoints():
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(base + "/", timeout=3) as response:
            homepage = response.read().decode("utf-8")
            assert response.status == 200
        assert "PhishShield AI" in homepage

        with urllib.request.urlopen(base + "/api/health", timeout=3) as response:
            health = json.loads(response.read().decode())
        assert health["status"] == "ok"
        assert health["storage"] == "none"

        payload = json.dumps({"content": "From: A <a@example.test>\nSubject: Hello\n\nNormal note."}).encode()
        request = urllib.request.Request(base + "/api/analyze", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=3) as response:
            result = json.loads(response.read().decode())
        assert result["risk_level"] == "Low"

        empty = json.dumps({"content": " "}).encode()
        bad_request = urllib.request.Request(base + "/api/analyze", data=empty, headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(bad_request, timeout=3)
            assert False, "Expected HTTP 400 for empty input"
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
