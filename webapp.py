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
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter

import llm_providers
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "outputs"
WEB = ROOT / "web"
LOG_PATH = OUT / "pipeline.log"
LIVE_DIR = OUT / "live"
LIVE_LOG_PATH = LIVE_DIR / "live.log"

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
    {
        "id": "step7",
        "label": "Anomaly layer",
        "detail": "IsolationForest on benign traffic, fused with XGBoost",
        "artifacts": ["outputs/anomaly_metrics.json", "models/anomaly_iforest.joblib"],
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


def read_log(offset: int, path: Path = LOG_PATH) -> dict:
    if not path.exists():
        return {"offset": 0, "text": "", "size": 0, "truncated": False}
    size = path.stat().st_size
    offset = max(0, min(offset, size))
    with path.open("rb") as fh:
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
# Live detection engine (in-process management)
# ---------------------------------------------------------------------------
_live_proc: subprocess.Popen | None = None
_live_lock = threading.Lock()
_live_exit_code: int | None = None
_live_started_at: str | None = None
_live_options: dict = {}
# Session memory only — keys are never written to disk.
_api_keys: dict[str, str] = {}
_live_models: dict[str, str] = {}


def _live_running() -> bool:
    return _live_proc is not None and _live_proc.poll() is None


def _watch_live(proc: subprocess.Popen) -> None:
    global _live_exit_code
    _live_exit_code = proc.wait()


def api_key_configured(provider: str | None = None) -> bool:
    if provider:
        return llm_providers.configured(provider, _api_keys.get(provider))
    return any(llm_providers.configured(p, _api_keys.get(p)) for p in llm_providers.ORDER)


def set_api_key(provider: str, key: str, model: str | None = None) -> tuple[bool, str]:
    if not llm_providers.is_provider(provider):
        return False, f"Unknown provider: {provider}"
    key = (key or "").strip()
    if key:
        _api_keys[provider] = key
    else:
        _api_keys.pop(provider, None)
    model = (model or "").strip()
    if model:
        if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,120}", model):
            return False, "Invalid model ID."
        _live_models[provider] = model
    label = llm_providers.PROVIDERS[provider]["label"]
    if key:
        return True, f"{label} key set for this browser session (not saved to disk)."
    return True, f"{label} key cleared for this session."


def _external_live_pids() -> list[int]:
    """PIDs of live_engine.py processes running outside the dashboard."""
    managed_pid = _live_proc.pid if _live_proc is not None else None
    found: list[int] = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or int(pid) == os.getpid() or int(pid) == managed_pid:
                continue
            try:
                args = [a for a in Path(f"/proc/{pid}/cmdline").read_bytes()
                        .split(b"\0") if a]
            except OSError:
                continue
            if not args:
                continue
            exe = args[0].decode("utf-8", "replace")
            # Only count actual python processes launched with live_engine.py,
            # not shells whose command text merely mentions the filename.
            if "python" not in exe:
                continue
            if any(a in (b"live_engine.py", b"./live_engine.py") or
                   a.endswith(b"/live_engine.py") for a in args[1:]):
                found.append(int(pid))
    except OSError:
        pass
    return found


def _external_live_running() -> bool:
    return bool(_external_live_pids())


def live_status() -> dict:
    disk = _json_load("outputs/live/status.json", {})
    feed_path = LIVE_DIR / "feed.jsonl"
    total = 0
    if feed_path.exists():
        with feed_path.open(encoding="utf-8") as fh:
            total = sum(1 for _ in fh)
    managed = _live_running()
    running = managed or _external_live_running()
    providers = {
        name: {
            "label": info["label"],
            "env": info["env"],
            "configured": api_key_configured(name),
            "model": _live_models.get(name) or llm_providers.default_model(name),
            "hint": info["hint"],
        }
        for name, info in llm_providers.PROVIDERS.items()
    }
    requested = _live_options.get("provider")
    if not requested and running:
        requested = disk.get("provider")
    if not requested or requested == "auto" or not llm_providers.is_provider(requested):
        requested = next((p for p in llm_providers.ORDER if providers[p]["configured"]), None)
    return {
        **disk,
        "running": running,
        "managed": managed,
        "external": running and not managed,
        "exit_code": _live_exit_code,
        "started_at": _live_started_at,
        "options": _live_options,
        "api_key_configured": api_key_configured(),
        "providers": providers,
        "provider": requested,
        "model": _live_options.get("model") or _live_models.get(requested or "", ""),
        "feed_total": total,
        "log_available": LIVE_LOG_PATH.exists(),
    }


def read_feed(offset: int | None = None, tail: int | None = None, limit: int = 200) -> dict:
    path = LIVE_DIR / "feed.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    total = len(lines)
    if tail:
        start = max(0, total - tail)
    else:
        start = max(0, min(offset or 0, total))
    chunk = lines[start:start + limit]
    items = []
    for raw in chunk:
        try:
            items.append(json.loads(raw))
        except ValueError:
            continue
    return {"offset": start + len(chunk), "total": total, "items": items}


def build_live(query: dict) -> dict:
    offset_raw = query.get("offset", [None])[0]
    try:
        offset = int(offset_raw) if offset_raw is not None else None
    except ValueError:
        offset = None
    try:
        tail = int(query.get("tail", [0])[0]) or None
    except ValueError:
        tail = None
    try:
        limit = max(1, min(1000, int(query.get("limit", [200])[0])))
    except ValueError:
        limit = 200
    log_offset = 0
    try:
        log_offset = int(query.get("log_offset", [0])[0])
    except ValueError:
        pass
    return {
        "status": live_status(),
        "feed": read_feed(offset=offset, tail=tail, limit=limit),
        "alerts": _json_load("outputs/live/alerts.json", []),
        "incidents": _json_load("outputs/live/incidents.json", []),
        "log": read_log(log_offset, LIVE_LOG_PATH),
    }


def start_live(options: dict) -> tuple[bool, str]:
    global _live_proc, _live_exit_code, _live_started_at, _live_options
    source = options.get("source", "replay")
    ai_mode = options.get("ai_mode", "auto")
    provider = (options.get("provider") or "").strip() or None
    model = (options.get("model") or "").strip() or None
    if source not in ("replay", "tshark"):
        return False, "Unknown live source."
    if ai_mode not in ("auto", "llm", "offline"):
        return False, "Unknown AI mode."
    if provider and not llm_providers.is_provider(provider):
        return False, f"Unknown LLM provider: {provider}"
    if model and not re.fullmatch(r"[A-Za-z0-9._:/-]{1,120}", model):
        return False, "Invalid model ID."
    if ai_mode == "llm" and not api_key_configured(provider):
        target = llm_providers.PROVIDERS.get(provider or "", {}).get("env", "any provider key")
        return False, (f"LLM mode needs a key for {provider or 'a provider'} "
                       f"({target}). Save one below or set it in the environment.")
    with _live_lock:
        if _live_running() or _external_live_running():
            return False, ("A live engine is already running (started here or from "
                           "the command line).")

        env = dict(os.environ, PYTHONUNBUFFERED="1")
        for name, key in _api_keys.items():
            env[llm_providers.PROVIDERS[name]["env"]] = key
        cmd = [sys.executable, "-u", "live_engine.py", "--source", source,
               "--ai-mode", ai_mode]
        if provider:
            cmd += ["--provider", provider]
        if model:
            cmd += ["--model", model]
        if source == "replay":
            try:
                rate = float(options.get("rate", 10))
                count = int(options.get("count", 0))
            except (TypeError, ValueError):
                return False, "Rate and count must be numbers."
            if not (0.1 <= rate <= 500) or not (0 <= count <= 100_000):
                return False, "Rate must be 0.1–500/s and count 0–100,000 (0 = continuous)."
            cmd += ["--rate", str(rate), "--count", str(count)]
        else:
            interface = str(options.get("interface") or "eth0")
            if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", interface):
                return False, "Invalid network interface name."
            cmd += ["--interface", interface]

        LIVE_DIR.mkdir(parents=True, exist_ok=True)
        # A new session starts with a clean live feed, but keeps batch artifacts.
        for rel in ("feed.jsonl", "alerts.json", "incidents.json", "status.json"):
            (LIVE_DIR / rel).unlink(missing_ok=True)
        for old in (OUT / "reports").glob("LIVE-*.md"):
            old.unlink()
        handle = LIVE_LOG_PATH.open("wb")
        try:
            _live_proc = subprocess.Popen(
                cmd, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT,
                env=env, start_new_session=True,
            )
        finally:
            handle.close()
        _live_exit_code = None
        _live_started_at = _utcnow()
        _live_options = {
            "source": source,
            "ai_mode": ai_mode,
            "provider": provider or "auto",
            "model": model or _live_models.get(provider or "", ""),
            "rate": options.get("rate", 10) if source == "replay" else None,
            "count": options.get("count", 600) if source == "replay" else None,
            "interface": options.get("interface", "eth0") if source == "tshark" else None,
        }
        threading.Thread(target=_watch_live, args=(_live_proc,), daemon=True).start()
        return True, "Live detection started."


def stop_live() -> tuple[bool, str]:
    with _live_lock:
        stopped = False
        if _live_running():
            assert _live_proc is not None
            try:
                os.killpg(os.getpgid(_live_proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                _live_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(_live_proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    _live_proc.kill()
                _live_proc.wait(timeout=5)
            stopped = True

        # Also stop an engine left over from a previous dashboard process.
        for pid in _external_live_pids():
            try:
                os.kill(pid, signal.SIGTERM)
                stopped = True
            except ProcessLookupError:
                pass
        if stopped:
            return True, "Live detection stopped."
        return False, "No live detection run is active."


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------
def build_overview() -> dict:
    check = _json_load("outputs/data_check.json", {})
    metrics = _json_load("outputs/metrics.json", {})
    metrics_port = _json_load("outputs/metrics_with_port.json", {})
    hard = _json_load("outputs/hard_eval.json", {})
    anomaly = _json_load("outputs/anomaly_metrics.json", {})
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
        "anomaly": {
            "fused": anomaly.get("fused", {}),
            "isolation_forest_only": anomaly.get("isolation_forest_only", {}),
            "cross_capture_anomaly": anomaly.get("cross_capture_anomaly", {}),
        },
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
    if re.fullmatch(r"[A-Za-z0-9_-]+", incident_id):
        for path in sorted((OUT / "reports").glob(f"{incident_id}_*.md")):
            mode = path.stem[len(incident_id) + 1:]
            reports[mode] = path.read_text(encoding="utf-8")
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
        elif path == "/api/live":
            self._json(build_live(query))
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
        body = self.rfile.read(length) if length else b""
        data: dict = {}
        if body:
            try:
                data = json.loads(body)
            except ValueError:
                self._error("Invalid JSON body")
                return
        if path == "/api/pipeline/start":
            ok, message = start_pipeline()
            self._json({"ok": ok, "message": message, "pipeline": pipeline_status()},
                       200 if ok else 409)
        elif path == "/api/pipeline/stop":
            ok, message = stop_pipeline()
            self._json({"ok": ok, "message": message, "pipeline": pipeline_status()},
                       200 if ok else 409)
        elif path == "/api/live/start":
            ok, message = start_live(data)
            self._json({"ok": ok, "message": message, "status": live_status()},
                       200 if ok else 409)
        elif path == "/api/live/stop":
            ok, message = stop_live()
            self._json({"ok": ok, "message": message, "status": live_status()},
                       200 if ok else 409)
        elif path == "/api/live/key":
            ok, message = set_api_key(data.get("provider") or llm_providers.ORDER[0],
                                      data.get("key", ""), data.get("model"))
            self._json({"ok": ok, "message": message, "status": live_status()},
                       200 if ok else 400)
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
