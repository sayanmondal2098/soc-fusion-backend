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

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        provider: str | None = None,
        hint: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.field = field
        self.provider = provider
        self.hint = hint
        self.details = details or {}

    def __str__(self) -> str:
        parts = [self.message]
        if self.field:
            parts.append(f"field={self.field}")
        if self.provider:
            parts.append(f"provider={self.provider}")
        if self.hint:
            parts.append(f"hint={self.hint}")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "llm_configuration_error",
            "message": self.message,
        }
        if self.field:
            payload["field"] = self.field
        if self.provider:
            payload["provider"] = self.provider
        if self.hint:
            payload["hint"] = self.hint
        if self.details:
            payload["details"] = self.details
        return payload


class LLMRequestError(RuntimeError):
    """Raised when the Gemini request fails or returns invalid data."""

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        status_code: int | None = None,
        endpoint: str | None = None,
        retryable: bool | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.status_code = status_code
        self.endpoint = endpoint
        self.retryable = retryable
        self.details = details or {}

    def __str__(self) -> str:
        parts = [self.message]
        if self.provider:
            parts.append(f"provider={self.provider}")
        if self.status_code is not None:
            parts.append(f"status_code={self.status_code}")
        if self.retryable is not None:
            parts.append(f"retryable={str(self.retryable).lower()}")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "llm_request_error",
            "message": self.message,
        }
        if self.provider:
            payload["provider"] = self.provider
        if self.status_code is not None:
            payload["status_code"] = self.status_code
        if self.endpoint:
            payload["endpoint"] = self.endpoint
        if self.retryable is not None:
            payload["retryable"] = self.retryable
        if self.details:
            payload["details"] = self.details
        return payload


PROMPT_MODULE = "utils.prompt"
SUPPORTED_PROVIDER = "gemini"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default

    try:
        return int(raw)
    except ValueError as exc:
        raise LLMConfigurationError(
            f"{name} must be an integer when provided",
            field=name,
            provider=SUPPORTED_PROVIDER,
        ) from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default

    try:
        return float(raw)
    except ValueError as exc:
        raise LLMConfigurationError(
            f"{name} must be a float when provided",
            field=name,
            provider=SUPPORTED_PROVIDER,
        ) from exc


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default

    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_default_prompt() -> str:
    prompt = get_default_prompt().strip()
    if not prompt:
        raise LLMConfigurationError(
            f"Default prompt is empty in {PROMPT_MODULE}",
            field="default_prompt",
            provider=SUPPORTED_PROVIDER,
        )

    return prompt


def build_prompt(user_prompt: str, system_prompt: str | None = None) -> str:
    final_user_prompt = user_prompt.strip()
    if not final_user_prompt:
        raise LLMConfigurationError(
            "user prompt cannot be empty",
            field="user_prompt",
            provider=SUPPORTED_PROVIDER,
        )

    final_system_prompt = (system_prompt or load_default_prompt()).strip()
    if not final_system_prompt:
        raise LLMConfigurationError(
            "system prompt cannot be empty",
            field="system_prompt",
            provider=SUPPORTED_PROVIDER,
        )

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
            f"Gemini returned HTTP {exc.code}",
            provider=SUPPORTED_PROVIDER,
            status_code=exc.code,
            endpoint=url,
            retryable=exc.code >= 500,
            details={"body": detail},
        ) from exc
    except urllib.error.URLError as exc:
        raise LLMRequestError(
            f"Gemini request failed: {exc}",
            provider=SUPPORTED_PROVIDER,
            endpoint=url,
            retryable=True,
        ) from exc
    except json.JSONDecodeError as exc:
        raise LLMRequestError(
            "Gemini returned invalid JSON",
            provider=SUPPORTED_PROVIDER,
            endpoint=url,
            retryable=True,
        ) from exc


def _extract_gemini_text(response_payload: dict[str, Any]) -> str:
    candidates = response_payload.get("candidates", [])
    if not candidates:
        raise LLMRequestError(
            "Gemini returned no candidates",
            provider=SUPPORTED_PROVIDER,
        )

    parts = candidates[0].get("content", {}).get("parts", [])
    text = "".join(
        part.get("text", "") for part in parts if isinstance(part, dict)
    ).strip()

    if not text:
        raise LLMRequestError(
            "Gemini returned an empty response",
            provider=SUPPORTED_PROVIDER,
        )

    return text


def get_provider() -> str:
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if not provider:
        return SUPPORTED_PROVIDER

    if provider != SUPPORTED_PROVIDER:
        raise LLMConfigurationError(
            f"Unsupported LLM provider: {provider}",
            field="LLM_PROVIDER",
            provider=provider,
            hint="Only Gemini is supported in the current backend.",
        )

    return provider


def generate_text(prompt: str, system_prompt: str | None = None) -> dict[str, str]:
    final_prompt = build_prompt(prompt, system_prompt=system_prompt)
    provider = get_provider()

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise LLMConfigurationError(
            "GEMINI_API_KEY is not configured",
            field="GEMINI_API_KEY",
            provider=provider,
        )

    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash").strip() or "gemini-1.5-flash"
    temperature = _env_float("LLM_TEMPERATURE", _env_float("GEMINI_TEMPERATURE", 0.2))
    max_output_tokens = _env_int(
        "LLM_MAX_OUTPUT_TOKENS",
        _env_int("GEMINI_MAX_OUTPUT_TOKENS", 512),
    )

    url = (
        f"{GEMINI_API_BASE}/{urllib.parse.quote(model, safe='')}:generateContent"
        f"?key={urllib.parse.quote(api_key, safe='')}"
    )
    payload = {
        "contents": [{"parts": [{"text": final_prompt}]}],
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
        "provider": provider,
        "model": model,
        "text": _extract_gemini_text(response_payload),
    }


def generate_text_with_gemini(prompt: str) -> dict[str, str]:
    return generate_text(prompt)


def generate_text_from_file(prompt_path: str | os.PathLike[str]) -> dict[str, str]:
    path = Path(prompt_path)
    if not path.exists():
        raise LLMConfigurationError(
            f"Prompt file not found: {path}",
            field="prompt_file",
            provider=SUPPORTED_PROVIDER,
            details={"path": str(path)},
        )

    prompt = path.read_text(encoding="utf-8").lstrip("\ufeff").strip()
    if not prompt:
        raise LLMConfigurationError(
            f"Prompt file is empty: {path}",
            field="prompt_file",
            provider=SUPPORTED_PROVIDER,
            details={"path": str(path)},
        )

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
        "supported_provider": SUPPORTED_PROVIDER,
        "model": os.getenv("GEMINI_MODEL") or "gemini-1.5-flash",
        "temperature": os.getenv("LLM_TEMPERATURE")
        or os.getenv("GEMINI_TEMPERATURE")
        or None,
        "max_output_tokens": os.getenv("LLM_MAX_OUTPUT_TOKENS")
        or os.getenv("GEMINI_MAX_OUTPUT_TOKENS")
        or None,
        "prompt_module": PROMPT_MODULE,
        "has_gemini_api_key": bool(os.getenv("GEMINI_API_KEY")),
        "verbose_logging": _env_bool("LLM_VERBOSE", False),
    }
