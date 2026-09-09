#!/usr/bin/env python3
"""Run an unlabeled browser flow against the local detector."""

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args()
    args.profile.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            str(args.profile),
            headless=True,
            executable_path="/usr/bin/google-chrome",
            locale="ko-KR",
            args=["--no-sandbox"],
        )
        page = context.new_page()
        # Juice Shop의 SPA/background 요청은 networkidle을 장시간 만족하지 않을 수 있다.
        # DOM 로드까지만 성공 조건으로 삼고 이후 고정 관찰 구간을 둔다.
        page.goto(args.base_url, wait_until="domcontentloaded", timeout=60_000)
        page.wait_for_timeout(2_000)
        page.evaluate(
            """async () => {
              const paths = [
                '/api/Products/',
                '/rest/products/search?q=',
                '/rest/products/search?q=%27%29%29--',
                '/api/Users/999999'
              ];
              for (const path of paths) {
                try { await fetch(path); } catch (_) {}
              }
            }"""
        )
        page.wait_for_timeout(1_500)
        context.close()


if __name__ == "__main__":
    main()
