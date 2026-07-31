"""Drip-feed a log file into another file, to simulate a live writer.

Gives ``analyze --follow`` something to tail: lines are appended one at a
time at a fixed rate, flushed immediately, exactly as a real logger would.

    python sandbox/demo/replay.py samples/webserver_incidents.log /tmp/live/webserver.log --rate 20

``--chunky`` writes every 10th line in two halves, pausing in between, so you
can confirm a half-written line never shows up as a parse error.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="log file to replay from")
    parser.add_argument("target", type=Path, help="file to append to (what --follow tails)")
    parser.add_argument("--rate", type=float, default=20.0, help="lines per second (default: 20)")
    parser.add_argument("--skip", type=int, default=0, help="skip this many leading lines")
    parser.add_argument("--chunky", action="store_true", help="split every 10th line across two writes")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lines = args.source.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)[args.skip :]
    delay = 1 / args.rate if args.rate > 0 else 0

    args.target.parent.mkdir(parents=True, exist_ok=True)
    with args.target.open("a", encoding="utf-8") as out:
        for n, line in enumerate(lines, start=1):
            if args.chunky and n % 10 == 0:
                half = len(line) // 2
                out.write(line[:half])
                out.flush()
                time.sleep(delay)
                out.write(line[half:])
            else:
                out.write(line)
            out.flush()
            time.sleep(delay)

    sys.stderr.write(f"replay finished: {len(lines)} lines → {args.target}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
