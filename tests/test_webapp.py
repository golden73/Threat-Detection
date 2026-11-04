"""Smoke tests for the local dashboard (webapp.py)."""
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import webapp  # noqa: E402


def test_overview_structure():
    data = webapp.build_overview()
    assert "counts" in data
    assert "pipeline" in data
    assert len(data["pipeline"]["steps"]) == len(webapp.STEPS)
    for step in data["pipeline"]["steps"]:
        assert step["status"] in {"done", "partial", "pending"}


def test_incident_lookup():
    data = webapp.build_incident("INC-003")
    if data is not None:
        assert data["incident"]["incident_id"] == "INC-003"
        assert isinstance(data["alerts"], list)
        assert set(data["reports"]) == {"offline", "llm"}


def test_report_ids_reject_paths():
    assert webapp.build_report("../secret") is None
    assert webapp.build_report("..%2Fsecret") is None
    assert webapp.build_report("INC-001/../../etc/passwd") is None


def test_http_smoke():
    server = ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(f"{base}/api/health", timeout=5) as resp:
            assert json.load(resp)["ok"] is True
        with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
            assert b"AEGIS" in resp.read()
        with urllib.request.urlopen(f"{base}/app.js", timeout=5) as resp:
            assert b"viewOverview" in resp.read()
        with urllib.request.urlopen(f"{base}/api/overview", timeout=5) as resp:
            assert "counts" in json.load(resp)
        with urllib.request.urlopen(f"{base}/api/pipeline", timeout=5) as resp:
            assert "steps" in json.load(resp)
        try:
            urllib.request.urlopen(f"{base}/api/incidents/NOPE", timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("expected 404 for missing incident")
    finally:
        server.shutdown()
        server.server_close()
