"""Pydantic validation for CLI-supplied log file arguments.

Kept separate from the top-level ``models`` package (which is the engine's
data-model surface) to avoid ``from models import X`` / ``from cli.models
import Y`` ambiguity in the same file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ValidationError, model_validator

from utils.exceptions import CliInputError


def _check_log_file(path: Path) -> Path:
    if not path.exists():
        raise ValueError(f"{path}: no such file")
    if not path.is_file():
        raise ValueError(f"{path}: not a regular file")
    if path.suffix.lower() != ".log":
        raise ValueError(f"{path}: expected a '.log' file, got {path.suffix or '(no extension)'}")
    return path


_LogFilePath = Annotated[Path, AfterValidator(_check_log_file)]


class LogFileArgs(BaseModel):
    """Validated set of CLI-supplied log file paths."""

    paths: list[_LogFilePath]

    @model_validator(mode="after")
    def _check_non_empty_and_unique(self) -> LogFileArgs:
        if not self.paths:
            raise ValueError("at least one log file is required")
        resolved = [p.resolve() for p in self.paths]
        seen: set[Path] = set()
        dupes: set[Path] = set()
        for p in resolved:
            (dupes if p in seen else seen).add(p)
        if dupes:
            names = ", ".join(str(d) for d in sorted(dupes))
            raise ValueError(f"duplicate log file path(s): {names}")
        return self


def validate_log_files(paths: list[Path]) -> list[Path]:
    """Validate CLI-supplied paths, raising ``CliInputError`` (never pydantic's own type)."""
    try:
        return LogFileArgs(paths=paths).paths
    except ValidationError as exc:
        messages = [err["msg"].removeprefix("Value error, ") for err in exc.errors()]
        raise CliInputError("; ".join(messages)) from exc
