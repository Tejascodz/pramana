"""Regenerate docs/img/viewer.png: the audit viewer opened on the credit-scoring sample pack.

Needs the dashboard and browser extras:

    pip install -e ".[dashboard,browser]" && playwright install chromium
    python scripts/screenshot_viewer.py
"""

from __future__ import annotations

import socket
import subprocess  # nosec B404 - fixed argument list, no shell
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "docs" / "sample-audits" / "credit_scoring"
OUT = ROOT / "docs" / "img" / "viewer.png"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    from playwright.sync_api import sync_playwright

    port = free_port()
    server = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argument list, no shell
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard" / "app.py"),
         "--server.headless", "true", "--server.port", str(port), "--", "--pack", str(PACK)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        url = f"http://127.0.0.1:{port}/"
        for _ in range(60):
            try:
                urllib.request.urlopen(url, timeout=2)  # noqa: S310  # nosec B310 - local server
                break
            except OSError:
                time.sleep(0.5)
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(
                viewport={"width": 1280, "height": 900}, device_scale_factor=2, color_scheme="light"
            )
            page.goto(url, wait_until="networkidle")
            page.wait_for_selector("text=What needs attention", timeout=60_000)
            page.wait_for_timeout(1500)
            page.screenshot(path=str(OUT))
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
