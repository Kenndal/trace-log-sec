"""Project-wide constants: standalone literals shared across packages."""

from __future__ import annotations

DEFAULT_CONFIG_FILENAME = "config.yaml"

COMBINED_LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
SYSLOG_TIME_FORMAT = "%Y %b %d %H:%M:%S"

MAX_DECODE_PASSES = 2
DEFAULT_MAX_EVIDENCE = 20
DEFAULT_CORRELATION_WINDOW_MINUTES = 10

DEFAULT_WEBLOG_SOURCE = "webserver"
DEFAULT_AUTHLOG_SOURCE = "auth"
