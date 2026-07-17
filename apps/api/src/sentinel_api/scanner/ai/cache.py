"""Prompt-hash cache containing only validated structured AI output."""

import json
from pathlib import Path
from typing import Protocol

from sentinel_api.scanner.ai.formatter import AIModelOutput


class ExplanationCache(Protocol):
    """Provider-neutral cache contract."""

    def get(self, finding_id: str, prompt_hash: str) -> AIModelOutput | None:
        """Return an exact finding/prompt match when available."""
        ...

    def set(self, finding_id: str, prompt_hash: str, output: AIModelOutput) -> None:
        """Store validated output without the prompt or API credential."""
        ...


class MemoryExplanationCache:
    """Small deterministic cache for tests and short-lived callers."""

    def __init__(self) -> None:
        self._entries: dict[str, AIModelOutput] = {}

    def get(self, finding_id: str, prompt_hash: str) -> AIModelOutput | None:
        return self._entries.get(_cache_key(finding_id, prompt_hash))

    def set(self, finding_id: str, prompt_hash: str, output: AIModelOutput) -> None:
        self._entries[_cache_key(finding_id, prompt_hash)] = output


class FileExplanationCache:
    """Local JSON cache under Sentinel's ignored workspace directory."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def get(self, finding_id: str, prompt_hash: str) -> AIModelOutput | None:
        entries = self._read()
        value = entries.get(_cache_key(finding_id, prompt_hash))
        if not isinstance(value, dict):
            return None
        try:
            return AIModelOutput.model_validate(value)
        except ValueError:
            return None

    def set(self, finding_id: str, prompt_hash: str, output: AIModelOutput) -> None:
        entries = self._read()
        entries[_cache_key(finding_id, prompt_hash)] = output.model_dump(mode="json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temporary.write_text(
            json.dumps(entries, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def _read(self) -> dict[str, object]:
        try:
            content = self.path.read_text(encoding="utf-8")
            parsed = json.loads(content)
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}


def _cache_key(finding_id: str, prompt_hash: str) -> str:
    return f"{finding_id}:{prompt_hash}"
