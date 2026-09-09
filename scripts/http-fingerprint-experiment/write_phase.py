#!/usr/bin/env python3
"""Write out-of-band phase metadata without adding an HTTP label."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--round", required=True, type=int)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--started-at", required=True, type=int)
    parser.add_argument("--ended-at", required=True, type=int)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    args = parser.parse_args()
    value = {
        "round": args.round,
        "subject": args.subject,
        "startedAt": args.started_at,
        "endedAt": args.ended_at,
        "before": args.before,
        "after": args.after,
    }
    args.path.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
