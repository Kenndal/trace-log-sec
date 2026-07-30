"""Shared, dependency-free utilities: currently just the project's custom exceptions."""

from __future__ import annotations

from utils.exceptions import ConfigError, MalformedLineError, RuleConfigError, TraceLogSecError

__all__ = [
    "TraceLogSecError",
    "ConfigError",
    "MalformedLineError",
    "RuleConfigError",
]
