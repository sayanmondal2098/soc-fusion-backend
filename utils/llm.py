from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from utils.prompt import get_default_prompt


class LLMConfigurationError(RuntimeError):
    """Raised when LLM configuration is missing or invalid."""


class LLMRequestError(RuntimeError):
    """Raised when a provider request fails or returns invalid data."""


PROMPT_MODULE = "utils.prompt"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default

    try:
        return int(raw)
    except ValueError as exc:
        raise LLMConfigurationError(f"{name} must be an integer when provided") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default

    try:
        return float(raw)
    except ValueError as exc:
        raise LLMConfigurationError(f"{name} must be a float when provided") from exc


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default

    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_default_prompt() -> str:
    prompt = get_default_prompt().strip()
    if not prompt:
        raise LLMConfigurationError(f"Default prompt is empty in {PROMPT_MODULE}")

    return prompt


def build_prompt(user_prompt: str, system_prompt: str | None = None) -> str:
    final_user_prompt = user_prompt.strip()
    if not final_user_prompt:
        raise LLMConfigurationError("user prompt cannot be empty")

    final_system_prompt = (system_prompt or load_default_prompt()).strip()
    if not final_system_prompt:
        raise LLMConfigurationError("system prompt cannot be empty")

    return f"{final_system_prompt}\n\nUser request:\n{final_user_prompt}"


def _json_request(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: int = 90,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMRequestError(
            f"LLM provider returned HTTP {exc.code}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise LLMRequestError(f"LLM provider request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LLMRequestError("LLM provider returned invalid JSON") from exc


def _extract_openai_text(response_payload: dict[str, Any]) -> str:
    choices = response_payload.get("choices", [])
    if not choices:
        raise LLMRequestError("OpenAI-compatible provider returned no choices")

    message = choices[0].get("message", {})
    content = message.get("content", "")

    if isinstance(content, str):
        text = content.strip()
    elif isinstance(content, list):
        text = "".join(
            item.get("text", "")
            for item in content
            if isinstance(item, dict)
            and item.get("type") in {None, "text", "output_text"}
        ).strip()
    else:
        text = ""

    if not text:
        raise LLMRequestError("OpenAI-compatible provider returned an empty response")

    return text


def _extract_gemini_text(response_payload: dict[str, Any]) -> str:
    candidates = response_payload.get("candidates", [])
    if not candidates:
        raise LLMRequestError("Gemini provider returned no candidates")

    parts = candidates[0].get("content", {}).get("parts", [])
    text = "".join(
        part.get("text", "") for part in parts if isinstance(part, dict)
    ).strip()

    if not text:
        raise LLMRequestError("Gemini provider returned an empty response")

    return text


def _call_gemini(prompt: str) -> dict[str, str]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise LLMConfigurationError("GEMINI_API_KEY is not configured")

    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash").strip() or "gemini-1.5-flash"
    temperature = _env_float("LLM_TEMPERATURE", _env_float("GEMINI_TEMPERATURE", 0.2))
    max_output_tokens = _env_int(
        "LLM_MAX_OUTPUT_TOKENS",
        _env_int("GEMINI_MAX_OUTPUT_TOKENS", 512),
    )

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{urllib.parse.quote(model, safe='')}:generateContent"
        f"?key={urllib.parse.quote(api_key, safe='')}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_output_tokens,
        },
    }

    response_payload = _json_request(
        url=url,
        payload=payload,
        headers={"Content-Type": "application/json"},
    )

    return {
        "provider": "gemini",
        "model": model,
        "text": _extract_gemini_text(response_payload),
    }


def _call_openai_compatible(prompt: str) -> dict[str, str]:
    api_key = os.getenv("LLM_API_KEY", "").strip()
    if not api_key:
        raise LLMConfigurationError("LLM_API_KEY is not configured")

    base_url = (
        os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
    )
    model = os.getenv("LLM_MODEL", "").strip()
    if not model:
        raise LLMConfigurationError("LLM_MODEL is not configured")

    temperature = _env_float("LLM_TEMPERATURE", 0.2)
    max_tokens = _env_int("LLM_MAX_OUTPUT_TOKENS", 512)

    response_payload = _json_request(
        url=f"{base_url}/chat/completions",
        payload={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    return {
        "provider": "openai-compatible",
        "model": model,
        "text": _extract_openai_text(response_payload),
    }


def get_provider() -> str:
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if provider:
        return provider

    if os.getenv("LLM_API_KEY") and os.getenv("LLM_MODEL"):
        return "openai-compatible"

    if os.getenv("GEMINI_API_KEY"):
        return "gemini"

    raise LLMConfigurationError(
        "No LLM provider configured. Set LLM_PROVIDER or provider-specific environment variables."
    )


def generate_text(prompt: str, system_prompt: str | None = None) -> dict[str, str]:
    final_prompt = build_prompt(prompt, system_prompt=system_prompt)
    provider = get_provider()

    if provider == "gemini":
        return _call_gemini(final_prompt)

    if provider in {"openai", "openai-compatible", "openrouter"}:
        return _call_openai_compatible(final_prompt)

    raise LLMConfigurationError(f"Unsupported LLM provider: {provider}")


def generate_text_with_gemini(prompt: str) -> dict[str, str]:
    """Backward-compatible alias for older code paths."""

    return generate_text(prompt)


def generate_text_from_file(prompt_path: str | os.PathLike[str]) -> dict[str, str]:
    path = Path(prompt_path)
    if not path.exists():
        raise LLMConfigurationError(f"Prompt file not found: {path}")

    prompt = path.read_text(encoding="utf-8").lstrip("\ufeff").strip()
    if not prompt:
        raise LLMConfigurationError(f"Prompt file is empty: {path}")

    return generate_text(prompt)


def get_llm_settings() -> dict[str, Any]:
    configured_provider = os.getenv("LLM_PROVIDER", "").strip().lower() or None

    try:
        resolved_provider = get_provider()
    except LLMConfigurationError:
        resolved_provider = None

    return {
        "configured_provider": configured_provider,
        "resolved_provider": resolved_provider,
        "model": os.getenv("LLM_MODEL") or os.getenv("GEMINI_MODEL") or None,
        "temperature": os.getenv("LLM_TEMPERATURE")
        or os.getenv("GEMINI_TEMPERATURE")
        or None,
        "max_output_tokens": os.getenv("LLM_MAX_OUTPUT_TOKENS")
        or os.getenv("GEMINI_MAX_OUTPUT_TOKENS")
        or None,
        "base_url": os.getenv("LLM_BASE_URL") or None,
        "prompt_module": PROMPT_MODULE,
        "has_llm_api_key": bool(os.getenv("LLM_API_KEY")),
        "has_gemini_api_key": bool(os.getenv("GEMINI_API_KEY")),
        "verbose_logging": _env_bool("LLM_VERBOSE", False),
    }
