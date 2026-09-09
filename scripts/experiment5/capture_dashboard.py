#!/usr/bin/env python3
"""Capture rendered detector dashboard views as offline HTML snapshots."""

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright


def offline_html(page):
    return page.evaluate(
        """() => {
          const clone = document.documentElement.cloneNode(true);
          clone.querySelectorAll('script').forEach((node) => node.remove());
          return '<!DOCTYPE html>\\n' + clone.outerHTML;
        }"""
    )


def save_view(page, output_dir, name):
    (output_dir / name).write_text(offline_html(page), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080/__detection/dashboard")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path="/usr/bin/google-chrome",
            args=["--no-sandbox"],
        )
        page = browser.new_page(locale="ko-KR")
        page.goto(args.url, wait_until="domcontentloaded")
        page.locator("#actorRows tr").first.wait_for(state="visible", timeout=15_000)
        page.wait_for_timeout(2_500)

        save_view(page, args.output_dir, "Traffic Detection Dashboard - Actor Candidates.html")

        page.locator('[data-tab="sessions"]').click()
        page.locator("#sessionRows tr").first.wait_for(state="visible", timeout=10_000)
        save_view(page, args.output_dir, "Traffic Detection Dashboard - Sessions.html")

        page.locator('[data-tab="actors"]').click()
        page.locator("#actorRows tr.clickable").first.click()
        page.locator("#backdrop .modal").wait_for(state="visible", timeout=10_000)
        save_view(page, args.output_dir, "Traffic Detection Dashboard - Actor Detail.html")
        page.screenshot(path=str(args.output_dir / "dashboard-actor-detail.png"), full_page=True)
        browser.close()


if __name__ == "__main__":
    main()
