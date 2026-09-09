#!/usr/bin/env python3
"""Wait on a common barrier and run one unlabeled HTTP client."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def now_ms():
    return time.time_ns() // 1_000_000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-at-ms", required=True, type=int)
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--cookie-jar", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--delay-ms", type=int, default=400)
    args = parser.parse_args()

    remaining = args.start_at_ms - now_ms()
    if remaining > 0:
        time.sleep(remaining / 1000)
    started_at = now_ms()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(Path(__file__).with_name("http_client.py")),
        "--base-url", args.base_url,
        "--cookie-jar", str(args.cookie_jar),
        "--delay-ms", str(args.delay_ms),
    ]
    with args.log.open("wb") as output:
        completed = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=False)
    result = {
        "barrierMs": args.start_at_ms,
        "startedAt": started_at,
        "endedAt": now_ms(),
        "exitCode": completed.returncode,
    }
    args.result.write_text(json.dumps(result) + "\n", encoding="utf-8")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
