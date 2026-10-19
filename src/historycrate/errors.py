"""Stable failures with bounded, credential-safe diagnostic serialization."""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,95}\Z")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_PRIVATE_KEYS = ("password", "credential", "token", "secret", "authorization", "config")
_EXIT_CODES = frozenset({2, 3, 4, 5, 6, 130})


def _safe_value(value: Any, key: str = "", depth: int = 0) -> object:
    """Copy context without rendering raw configuration or URLs.

    Context is diagnostic metadata, never a channel for raw native output. URL
    identities are digests, even when credentials are not obviously present.
    JSON escaping is left to serialization so paths retain their identity.
    """
    if depth > 8:
        return "<diagnostic-depth-limit>"
    lowered = key.casefold()
    if any(part in lowered for part in _PRIVATE_KEYS):
        return "<redacted>"
    if isinstance(value, str):
        if re.fullmatch(r"<url-sha256:[0-9a-f]{64}>", value):
            return value
        if ("url" in lowered and not lowered.endswith("sha256")) or _URL.search(value):
            digest = hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
            return "<url-sha256:" + digest + ">"
        return value if len(value) <= 2048 else value[:2048] + "<truncated>"
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else "<nonfinite-diagnostic-number>"
    if isinstance(value, dict):
        result = {}
        for index, (child_key, child_value) in enumerate(value.items()):
            if index == 100:
                result["context_truncated"] = True
                break
            if isinstance(child_key, str):
                # Unknown diagnostic keys must not themselves reveal a URL.
                safe_key = _safe_value(child_key)
                result[str(safe_key)] = _safe_value(child_value, child_key, depth + 1)
        return result
    if isinstance(value, (tuple, list)):
        items = [_safe_value(item, key, depth + 1) for item in value[:100]]
        if len(value) > 100:
            omitted = len(value) - 100
            previous = value[-1]
            if (len(value) == 101 and isinstance(previous, dict)
                    and previous.get("context_truncated") is True
                    and type(previous.get("omitted")) is int
                    and previous["omitted"] >= 1):
                omitted = previous["omitted"]
            items.append({"context_truncated": True, "omitted": omitted})
        return items
    return "<unsupported-diagnostic-value>"


class CrateError(Exception):
    """A stable machine code, documented exit category and safe context."""

    def __init__(self, code: str, exit_code: int, context: dict[str, object] | None = None):
        if not isinstance(code, str) or _CODE.fullmatch(code) is None:
            code, exit_code, context = "INTERNAL_INVARIANT", 6, {"reason": "invalid diagnostic code"}
        if type(exit_code) is not int or exit_code not in _EXIT_CODES:
            code, exit_code, context = "INTERNAL_INVARIANT", 6, {"reason": "invalid exit category"}
        self.code = code
        self.exit_code = exit_code
        self.context = _safe_value(context or {})
        super().__init__(code)

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "exit_code": self.exit_code, "context": _safe_value(self.context)}

    def __str__(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
