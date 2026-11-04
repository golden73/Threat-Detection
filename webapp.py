#!/usr/bin/env python3
"""Local web dashboard for the AI-Assisted Threat Detection & Response System.

Standard library only - no extra dependencies, fully offline.

Usage:
    python3 webapp.py                  # http://127.0.0.1:8080
    python3 webapp.py --port 9000      # custom port
    python3 webapp.py --open           # open the browser automatically

The dashboard reads the JSON/CSV artifacts already produced by steps 1-6 and
can launch/stop the pipeline while streaming its log to the browser.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "outputs"
WEB = ROOT / "web"
LOG_PATH = OUT / "pipeline.log"

# ---------------------------------------------------------------------------
# Pipeline definition (mirrors run_pipeline.py)
# ---------------------------------------------------------------------------
STEPS = [
    {
        "id": "step1",
        "label": "Load & clean data",
        "detail": "Merge CICIDS2017 CSVs, drop duplicates",
        "artifacts": ["data/clean.csv"],
    },
    {
        "id": "step2",
        "label": "Train baseline",
        "detail": "XGBoost, 3-fold out-of-fold, no destination port",
        "artifacts": ["outputs/metrics.json", "outputs/predictions.csv",
                      "models/xgb.json", "models/classes.json"],
    },
    {
        "id": "step2b",
        "label": "Destination-port run",
        "detail": "Comparison run with Destination Port as a feature",
        "artifacts": ["outputs/metrics_with_port.json"],
    },
    {
        "id": "step3",
        "label": "Alerts & incidents",
        "detail": "Correlate flows into alerts, chain alerts into incidents",
        "artifacts": ["outputs/alerts.json", "outputs/incidents.json"],
    },
    {
        "id": "step4",
        "label": "AI analyst reports",
        "detail": "Offline knowledge-base report per incident",
        "artifacts": ["outputs/reports"],
    },
    {
        "id": "step5",
        "label": "Hard evaluation",
        "detail": "Chronological, leave-one-attack-out, cross-capture",
        "artifacts": ["outputs/hard_eval.json"],
    },
    {
        "id": "step5b",
        "label": "Hard eval + port",
        "detail": "Destination-port comparison variant",
        "artifacts": ["outputs/hard_eval_with_port.json"],
    },
    {
        "id": "step6",
        "label": "Demo page",
        "detail": "Standalone one-file HTML report",
        "artifacts": ["outputs/demo.html"],
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _json_load(rel: str, default):
    path = ROOT / rel
    if not path.exists():
        return default
    for attempt in range(3):
        try:
            with path.open(encoding="utf-8") as fh:
                return json.load(fh)
        except ValueError:
            # A pipeline step may be rewriting the file; retry briefly.
            if attempt == 2:
                return default
            time.sleep(0.05)
        except OSError:
            return default
    return default


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def _utcnow() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _artifact(rel: str) -> dict:
    path = ROOT / rel
    info = {
        "path": rel,
        "name": path.name,
        "exists": path.exists(),
        "is_dir": path.is_dir(),
        "size": 0,
        "count": None,
        "updated": None,
    }
    if not path.exists():
        return info
    if path.is_dir():
        files = [f for f in path.rglob("*") if f.is_file()]
        info["size"] = sum(f.stat().st_size for f in files)
        info["count"] = len(files)
        info["updated"] = _iso(max((f.stat().st_mtime for f in files),
                                   default=path.stat().st_mtime))
    else:
        st = path.stat()
        info["size"] = st.st_size
        info["updated"] = _iso(st.st_mtime)
    return info


def _step_status(step: dict) -> dict:
    arts = [_artifact(a) for a in step["artifacts"]]
    present = [a for a in arts if a["exists"] and (not a["is_dir"] or a["count"])]
    if len(present) == len(arts):
        status = "done"
    elif present:
        status = "partial"
    else:
        status = "pending"
    return {**step, "artifacts": arts, "status": status}


def list_reports() -> list[dict]:
    folder = OUT / "reports"
    items = []
    if folder.exists():
        for file in sorted(folder.glob("*.md")):
            stem = file.stem
            incident_id, _, mode = stem.rpartition("_")
            if not incident_id:
                incident_id, mode = stem, "offline"
            st = file.stat()
            items.append({
                "id": stem,
                "incident_id": incident_id,
                "mode": mode,
                "size": st.st_size,
                "updated": _iso(st.st_mtime),
            })
    return items


# ---------------------------------------------------------------------------
# Pipeline runner (in-process)
# ---------------------------------------------------------------------------
_proc: subprocess.Popen | None = None
_proc_lock = threading.Lock()
_exit_code: int | None = None
_started_at: str | None = None


def _external_pipeline_running() -> bool:
    """True when a run_pipeline.py process exists that we do not manage."""
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            try:
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
                    "utf-8", "replace")
            except OSError:
                continue
            if "run_pipeline.py" in cmd:
                return True
    except OSError:
        pass
    return False


def _pipeline_running() -> bool:
    return _proc is not None and _proc.poll() is None


def pipeline_status() -> dict:
    managed = _pipeline_running()
    external = (not managed) and _external_pipeline_running()
    return {
        "running": managed or external,
        "managed": managed,
        "external": external,
        "exit_code": _exit_code,
        "started_at": _started_at,
        "log_available": LOG_PATH.exists(),
    }


def _watch(proc: subprocess.Popen) -> None:
    global _exit_code
    _exit_code = proc.wait()


def start_pipeline() -> tuple[bool, str]:
    global _proc, _exit_code, _started_at
    with _proc_lock:
        if _pipeline_running():
            return False, "The pipeline is already running."
        if _external_pipeline_running():
            return False, ("Another pipeline process is already running outside "
                           "the dashboard.")
        OUT.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        handle = LOG_PATH.open("wb")
        try:
            _proc = subprocess.Popen(
                [sys.executable, "-u", "run_pipeline.py"],
                cwd=ROOT,
                stdout=handle,
                stderr=subprocess.STDOUT,
                env=env,
            )
        finally:
            handle.close()
        _exit_code = None
        _started_at = _utcnow()
        threading.Thread(target=_watch, args=(_proc,), daemon=True).start()
        return True, "Pipeline started."


def stop_pipeline() -> tuple[bool, str]:
    global _proc
    with _proc_lock:
        if not _pipeline_running():
            return False, "No pipeline started from the dashboard is running."
        assert _proc is not None
        _proc.terminate()
        try:
            _proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _proc.kill()
            _proc.wait(timeout=5)
        return True, "Pipeline stopped."


def read_log(offset: int) -> dict:
    if not LOG_PATH.exists():
        return {"offset": 0, "text": "", "size": 0, "truncated": False}
    size = LOG_PATH.stat().st_size
    offset = max(0, min(offset, size))
    with LOG_PATH.open("rb") as fh:
        fh.seek(offset)
        data = fh.read(262_144)
    end = offset + len(data)
    return {
        "offset": end,
        "text": data.decode("utf-8", "replace"),
        "size": size,
        "truncated": end < size,
    }


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------
def build_overview() -> dict:
    check = _json_load("outputs/data_check.json", {})
    metrics = _json_load("outputs/metrics.json", {})
    metrics_port = _json_load("outputs/metrics_with_port.json", {})
    hard = _json_load("outputs/hard_eval.json", {})
    alerts = _json_load("outputs/alerts.json", [])
    incidents = _json_load("outputs/incidents.json", [])
    reports = list_reports()

    classes = check.get("attack_classes", {})
    attack_flows = sum(v for k, v in classes.items() if k.upper() != "BENIGN")

    return {
        "generated_at": _utcnow(),
        "dataset": check,
        "metrics": metrics,
        "metrics_with_port": metrics_port,
        "counts": {
            "alerts": len(alerts),
            "incidents": len(incidents),
            "reports": len(reports),
            "attack_flows": attack_flows,
            "benign_flows": classes.get("BENIGN", 0),
        },
        "alerts_by_severity": dict(Counter(a.get("severity", "unknown") for a in alerts)),
        "alerts_by_attack": dict(Counter(a.get("attack_type", "unknown") for a in alerts)),
        "alerts_by_tactic": dict(Counter(a.get("tactic", "unknown") for a in alerts)),
        "incidents_by_severity": dict(Counter(i.get("severity", "unknown") for i in incidents)),
        "hard_eval": hard,
        "recent_incidents": incidents[:6],
        "pipeline": {**pipeline_status(), "steps": [_step_status(s) for s in STEPS]},
    }


def build_incident(incident_id: str) -> dict | None:
    incidents = _json_load("outputs/incidents.json", [])
    incident = next((i for i in incidents if i.get("incident_id") == incident_id), None)
    if incident is None:
        return None
    alerts = {a["alert_id"]: a for a in _json_load("outputs/alerts.json", [])}
    linked = [alerts[x] for x in incident.get("alert_ids", []) if x in alerts]
    reports = {}
    for mode in ("offline", "llm"):
        path = OUT / "reports" / f"{incident_id}_{mode}.md"
        reports[mode] = path.read_text(encoding="utf-8") if path.exists() else None
    return {"incident": incident, "alerts": linked, "reports": reports}


def build_report(report_id: str) -> dict | None:
    # allow only simple ids, never paths
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", report_id):
        return None
    path = OUT / "reports" / f"{report_id}.md"
    if not path.exists():
        return None
    return {
        "id": report_id,
        "markdown": path.read_text(encoding="utf-8"),
        "updated": _iso(path.stat().st_mtime),
    }


def build_hard_eval() -> dict:
    return {
        "hard_eval": _json_load("outputs/hard_eval.json", {}),
        "hard_eval_with_port": _json_load("outputs/hard_eval_with_port.json", {}),
    }


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ThreatDashboard/1.0"

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        return

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(json.dumps(obj).encode("utf-8"),
                   "application/json; charset=utf-8", status)

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    # -- GET ----------------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            if path.startswith("/api/"):
                self._api_get(path, parse_qs(parsed.query))
            else:
                self._static(path)
        except Exception as exc:  # keep the server alive on bad input
            self._error(f"{type(exc).__name__}: {exc}", 500)

    def _api_get(self, path: str, query: dict) -> None:
        if path == "/api/health":
            self._json({"ok": True, "generated_at": _utcnow()})
        elif path == "/api/overview":
            self._json(build_overview())
        elif path == "/api/alerts":
            self._json(_json_load("outputs/alerts.json", []))
        elif path == "/api/incidents":
            self._json(_json_load("outputs/incidents.json", []))
        elif path.startswith("/api/incidents/"):
            data = build_incident(path.rsplit("/", 1)[-1])
            self._json(data) if data else self._error("Incident not found", 404)
        elif path == "/api/reports":
            self._json(list_reports())
        elif path.startswith("/api/reports/"):
            data = build_report(path.rsplit("/", 1)[-1])
            self._json(data) if data else self._error("Report not found", 404)
        elif path == "/api/hard-eval":
            self._json(build_hard_eval())
        elif path == "/api/pipeline":
            self._json({**pipeline_status(), "steps": [_step_status(s) for s in STEPS]})
        elif path == "/api/pipeline/log":
            try:
                offset = int(query.get("offset", ["0"])[0])
            except ValueError:
                offset = 0
            self._json(read_log(offset))
        elif path == "/api/pipeline/events":
            self._sse_pipeline()
        else:
            self._error("Unknown endpoint", 404)

    def _sse_pipeline(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        offset = 0
        try:
            while True:
                st = pipeline_status()
                res = read_log(offset)
                if res.get("text"):
                    offset = res["offset"]
                    self.wfile.write(
                        ("event: log\ndata: " + json.dumps(res["text"]) + "\n\n").encode("utf-8")
                    )
                    self.wfile.flush()
                self.wfile.write(
                    ("event: status\ndata: " + json.dumps(st) + "\n\n").encode("utf-8")
                )
                self.wfile.flush()
                if not st.get("running") and st.get("exit_code") is not None:
                    self.wfile.write(
                        ("event: done\ndata: " + json.dumps(st) + "\n\n").encode("utf-8")
                    )
                    self.wfile.flush()
                    break
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def _static(self, path: str) -> None:
        routes = {
            "/": ("web/index.html", "text/html; charset=utf-8"),
            "/index.html": ("web/index.html", "text/html; charset=utf-8"),
            "/app.js": ("web/app.js", "application/javascript; charset=utf-8"),
            "/style.css": ("web/style.css", "text/css; charset=utf-8"),
            "/demo.html": ("outputs/demo.html", "text/html; charset=utf-8"),
            "/demo.pdf": ("outputs/demo.pdf", "application/pdf"),
        }
        if path == "/favicon.ico":
            self._send(b"", "image/x-icon", 204)
            return
        route = routes.get(path)
        if route is None:
            self._error("Not found", 404)
            return
        file = ROOT / route[0]
        if not file.exists():
            self._error("Not found", 404)
            return
        self._send(file.read_bytes(), route[1])

    # -- POST ---------------------------------------------------------------
    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if path == "/api/pipeline/start":
            ok, message = start_pipeline()
            self._json({"ok": ok, "message": message, "pipeline": pipeline_status()},
                       200 if ok else 409)
        elif path == "/api/pipeline/stop":
            ok, message = stop_pipeline()
            self._json({"ok": ok, "message": message, "pipeline": pipeline_status()},
                       200 if ok else 409)
        else:
            self._error("Unknown endpoint", 404)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Threat Detection dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--open", action="store_true", help="open the browser")
    args = ap.parse_args()

    if not (WEB / "index.html").exists():
        sys.exit("error: web/index.html is missing")

    url = f"http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}/"
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("Threat Detection dashboard")
    print(f"  serving {ROOT}")
    print(f"  open    {url}")
    print("  stop    Ctrl+C")
    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
