#!/usr/bin/env python3
"""Run an unlabeled stdlib HTTP flow, optionally preserving cookies."""

import argparse
import http.cookiejar
import time
import urllib.error
import urllib.request
from pathlib import Path


PATHS = (
    "/",
    "/api/Products/",
    "/rest/products/search?q=",
    "/rest/products/search?q=%27%29%29--",
    "/api/Users/999999",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--cookie-jar", type=Path)
    parser.add_argument("--stateless", action="store_true")
    parser.add_argument("--delay-ms", type=int, default=0)
    args = parser.parse_args()

    jar = None
    if args.cookie_jar:
        args.cookie_jar.parent.mkdir(parents=True, exist_ok=True)
        jar = http.cookiejar.MozillaCookieJar(str(args.cookie_jar))
        if args.cookie_jar.exists():
            jar.load(ignore_discard=True, ignore_expires=True)

    opener = urllib.request.build_opener(
        *([] if args.stateless else [urllib.request.HTTPCookieProcessor(jar)])
    )
    for index, path in enumerate(PATHS):
        try:
            with opener.open(args.base_url + path, timeout=20) as response:
                response.read(4096)
        except urllib.error.HTTPError as error:
            error.read(4096)
        if args.delay_ms > 0 and index + 1 < len(PATHS):
            time.sleep(args.delay_ms / 1000)

    if jar is not None and not args.stateless:
        jar.save(ignore_discard=True, ignore_expires=True)


if __name__ == "__main__":
    main()
