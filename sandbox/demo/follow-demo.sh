#!/usr/bin/env bash
# One-command demo of `analyze --follow`.
#
# Seeds two empty log files (so their format can be detected), starts a writer
# replaying the sample logs into them line by line, and tails them live.
# Press Ctrl+C when you have seen enough — the report is produced on the way out.
#
#   ./sandbox/demo/follow-demo.sh            # default 20 lines/s
#   RATE=100 ./sandbox/demo/follow-demo.sh   # faster feed
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIVE="${LIVE_DIR:-/tmp/trace-log-sec-demo}"
RATE="${RATE:-20}"
PY="${REPO}/.venv/bin/python"
CLI="${REPO}/.venv/bin/trace-log-sec"

rm -rf "$LIVE"
mkdir -p "$LIVE"

# Format detection sniffs existing content, so each file needs one real line
# before the tailer opens it. That seeded line is not analyzed: --follow starts
# at end of file.
head -n 1 "${REPO}/samples/webserver_incidents.log" > "${LIVE}/webserver.log"
head -n 1 "${REPO}/samples/auth_incidents.log"      > "${LIVE}/auth.log"

"$PY" "${REPO}/sandbox/demo/replay.py" "${REPO}/samples/webserver_incidents.log" "${LIVE}/webserver.log" \
  --rate "$RATE" --skip 1 --chunky 2>/dev/null &
WEB_PID=$!
"$PY" "${REPO}/sandbox/demo/replay.py" "${REPO}/samples/auth_incidents.log" "${LIVE}/auth.log" \
  --rate "$RATE" --skip 1 2>/dev/null &
AUTH_PID=$!

cleanup() { kill "$WEB_PID" "$AUTH_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "Replaying samples into ${LIVE} at ${RATE} lines/s. Press Ctrl+C to stop and get the report."
echo

cd "$LIVE"
"$CLI" analyze --follow "${LIVE}/auth.log" "${LIVE}/webserver.log"
