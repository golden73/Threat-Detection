"""Provider-agnostic LLM calls for the SOC assistant.

One tiny HTTP layer (Python standard library only) for Google Gemini,
OpenRouter and Groq (via OpenRouter). Each has an API key environment variable
and a default model. Keys passed in by the dashboard take precedence over env vars.

Defaults are checked against provider docs in Nov 2026; model names and free
quotas change, so every call accepts an explicit model override.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def load_env() -> None:
    """Load KEY=value lines from the project .env (local only, gitignored)."""
    path = Path(__file__).resolve().parent / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env()

PROVIDERS = {
    "gemini": {
        "label": "Google Gemini",
        "env": "GEMINI_API_KEY",
        "alt_env": "GOOGLE_API_KEY",
        "model": "gemini-3.5-flash-lite",
        "hint": "Free tier: gemini-3.5-flash-lite (fast) or gemini-4-hydrogen (reasoning).",
    },
    "openrouter": {
        "label": "OpenRouter",
        "env": "OPENROUTER_API_KEY",
        "model": "openrouter/free",
        "hint": "Free tier: openrouter/free, or any model ending in :free.",
    },
    "groq": {
        # Groq-hosted models are reached through OpenRouter; no direct
        # direct Groq endpoint calls and no separate Groq key are used.
        "label": "Groq (via OpenRouter)",
        "env": "OPENROUTER_API_KEY",
        "model": "meta-llama/llama-3.1-8b-instruct",
        "hint": "Groq-only via OpenRouter; uses OPENROUTER_API_KEY.",
    },
}

ORDER = ["gemini", "openrouter", "groq"]


def is_provider(name: str) -> bool:
    return name in PROVIDERS


def default_model(provider: str) -> str:
    return PROVIDERS.get(provider, {}).get("model", "")


def api_key(provider: str, override: str | None = None) -> str:
    if override:
        return override.strip()
    info = PROVIDERS.get(provider, {})
    return (os.environ.get(info.get("env", ""), "") or
            os.environ.get(info.get("alt_env", ""), "")).strip()


def configured(provider: str, override: str | None = None) -> bool:
    return bool(api_key(provider, override))


def available(override: str | None = None, override_provider: str | None = None) -> str | None:
    """First provider with a key, for 'auto' mode."""
    if override and override_provider and is_provider(override_provider):
        return override_provider
    for name in ORDER:
        if configured(name, override if name == override_provider else None):
            return name
    return None


def _post(url: str, headers: dict, payload: dict, timeout: float = 60) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc


def call(provider: str, model: str, key: str, system: str, prompt: str,
         max_tokens: int = 1200) -> str:
    """Return plain text from one LLM. Raises RuntimeError on any API problem."""
    if not is_provider(provider):
        raise RuntimeError(f"Unknown provider: {provider}")
    if not key:
        raise RuntimeError(f"No API key for {provider}")
    model = (model or "").strip() or default_model(provider)

    if provider == "gemini":
        data = _post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            {"x-goog-api-key": key},
            {"system_instruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": prompt}]}],
             "generation_config": {"max_output_tokens": max_tokens}},
        )
        text = "".join(
            part.get("text", "")
            for candidate in data.get("candidates", [])
            for part in candidate.get("content", {}).get("parts", [])
            if "text" in part
        )

    else:  # openrouter and groq(via openrouter) use chat completions
        base = "https://openrouter.ai/api/v1"
        headers = {"Authorization": f"Bearer {key}",
                   "HTTP-Referer": "https://localhost/aegis",
                   "X-Title": "AEGIS SOC Assistant"}
        payload = {
            "model": model, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
        }
        if provider == "groq":
            payload["provider"] = {"only": ["groq"], "allow_fallbacks": False}
        data = _post(f"{base}/chat/completions", headers, payload)
        choices = data.get("choices") or []
        text = (choices[0].get("message", {}).get("content") or "") if choices else ""

    text = (text or "").strip()
    if not text:
        raise RuntimeError(f"Empty response from {provider} ({model})")
    return text
