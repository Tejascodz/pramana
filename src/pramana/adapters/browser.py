"""Audit a chat assistant through its web page, as a user would, with no API key.

Many assistants have no API you can reach: they live in a chat window on a website.
``llm.mode: browser`` drives that window with Playwright (a real Chromium): it types
each probe into the message box, sends it, waits until the reply has finished
appearing, and reads it back. Everything after that is the same audit.

    llm:
      mode: browser
      url: https://assistant.example.com/chat
      input_selector: "textarea"                 # the message box
      reply_selector: ".message.assistant"       # every reply bubble from the assistant
      send_selector: "button[type=submit]"       # optional; Enter is pressed otherwise
      settle_ms: 1200                            # a reply is final once unchanged this long

Install with ``pip install "pramana-audit[browser]"`` and ``playwright install chromium``.

Each new conversation runs in a fresh browser context (no cookies, storage or history
from the previous probe). A multi-turn probe stays on one page, turn after turn, while
the history it is given matches what the page actually showed. Test only sites you own
or are allowed to test: the probes are real attacks.
"""

from __future__ import annotations

import atexit
import os
import threading
import time
from typing import Any

from pramana.adapters.llm import Completion, check_endpoint, endpoint_label, strip_reasoning

INSTALL_HINT = (
    'browser mode needs Playwright: pip install "pramana-audit[browser]", then run '
    "`playwright install chromium`"
)


_RUNTIME: dict[str, Any] = {}
_RUNTIME_LOCK = threading.Lock()


def _shared_browser(headless: bool) -> Any:
    """One Playwright and one Chromium per process: Playwright allows a single sync instance
    per thread, so every client shares them and keeps its own isolated context."""
    with _RUNTIME_LOCK:
        key = "headless" if headless else "headed"
        if key not in _RUNTIME:
            try:
                from playwright.sync_api import sync_playwright
            except ImportError as exc:
                raise RuntimeError(INSTALL_HINT) from exc
            if "playwright" not in _RUNTIME:
                _RUNTIME["playwright"] = sync_playwright().start()
                atexit.register(_shutdown)
            executable = os.environ.get("PRAMANA_CHROMIUM")  # a Chromium already installed
            _RUNTIME[key] = _RUNTIME["playwright"].chromium.launch(
                headless=headless, **({"executable_path": executable} if executable else {})
            )
        return _RUNTIME[key]


def _shutdown() -> None:
    for key in ("headless", "headed"):
        try:
            if key in _RUNTIME:
                _RUNTIME.pop(key).close()
        except Exception:  # noqa: BLE001,S110 - best effort at exit
            pass
    if "playwright" in _RUNTIME:
        try:
            _RUNTIME.pop("playwright").stop()
        except Exception:  # noqa: BLE001,S110
            pass


class BrowserChatClient:
    """Sends probes through a web chat window and reads the replies from the page."""

    name = "browser"

    def __init__(
        self,
        url: str,
        input_selector: str,
        reply_selector: str,
        send_selector: str | None = None,
        timeout: float = 60.0,
        settle_ms: int = 1200,
        headless: bool = True,
        **_: Any,
    ):
        check_endpoint(url, sends_credentials=False)
        self.url = url
        self.input_selector = input_selector
        self.reply_selector = reply_selector
        self.send_selector = send_selector
        self.timeout = float(timeout)
        self.settle_ms = int(settle_ms)
        self.headless = bool(headless)
        self._lock = threading.Lock()
        self._browser = self._context = self._page = None
        self._history: list[dict[str, str]] | None = None
        self._headers: dict[str, str] | None = None

    # Browser lifecycle -----------------------------------------------------------

    def _start(self) -> None:
        if self._browser is None:
            self._browser = _shared_browser(self.headless)

    def close(self) -> None:
        """Close this client's page; the shared browser closes when the process exits."""
        try:
            if self._context is not None:
                self._context.close()
        except Exception:  # noqa: BLE001,S110 - the browser may already be gone
            pass
        self._context = self._page = None
        self._history = None

    def _new_conversation(self, headers: dict[str, str] | None) -> None:
        if self._context is not None:
            self._context.close()
        self._context = self._browser.new_context(
            accept_downloads=False, extra_http_headers=headers or None
        )
        self._page = self._context.new_page()
        self._page.goto(self.url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
        self._page.wait_for_selector(self.input_selector, timeout=self.timeout * 1000)
        self._history = []
        self._headers = headers

    def _send(self, text: str) -> str:
        """Type one message, send it, and return the reply once it has stopped changing."""
        page = self._page
        replies = page.locator(self.reply_selector)
        before = replies.count()
        box = page.locator(self.input_selector).first
        box.fill(text)
        if self.send_selector:
            page.locator(self.send_selector).first.click()
        else:
            box.press("Enter")
        deadline = time.monotonic() + self.timeout
        while replies.count() <= before:
            if time.monotonic() > deadline:
                raise TimeoutError(f"no reply appeared within {self.timeout:.0f} s")
            page.wait_for_timeout(100)
        # Replies often stream in word by word: wait until the text stops changing.
        last, since = None, time.monotonic()
        while True:
            now = replies.nth(replies.count() - 1).inner_text()
            if now != last:
                last, since = now, time.monotonic()
            elif now.strip() and (time.monotonic() - since) * 1000 >= self.settle_ms:
                return now.strip()
            if time.monotonic() > deadline:
                if last and last.strip():
                    return last.strip()
                raise TimeoutError(f"the reply stayed empty for {self.timeout:.0f} s")
            page.wait_for_timeout(100)

    # Client interface ------------------------------------------------------------

    def complete(
        self, system: str, user: str, sample: int = 0, headers: dict[str, str | None] | None = None
    ) -> Completion:
        return self.chat(
            system, [{"role": "user", "content": user}], sample=sample, headers=headers
        )

    def chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        sample: int = 0,
        headers: dict[str, str | None] | None = None,
    ) -> Completion:
        """The reply to the last message. ``system`` is ignored: the site has its own."""
        sent = {k: v for k, v in (headers or {}).items() if v is not None} or None
        with self._lock:
            started = time.perf_counter()
            try:
                self._start()
                prefix = [{"role": m["role"], "content": m["content"]} for m in messages[:-1]]
                if not prefix or prefix != self._history or sent != self._headers:
                    # A new conversation, or one this page did not see: start clean and
                    # replay the earlier user turns so the site holds the same context.
                    self._new_conversation(sent)
                    for m in prefix:
                        if m["role"] == "user":
                            self._send(m["content"])
                reply = strip_reasoning(self._send(str(messages[-1]["content"])))
                # Stored exactly as returned, so the next turn's history matches this page.
                self._history = prefix + [
                    {"role": "user", "content": str(messages[-1]["content"])},
                    {"role": "assistant", "content": reply},
                ]
                return Completion(
                    text=reply,
                    latency_ms=round((time.perf_counter() - started) * 1000, 1),
                    model=None,
                )
            except Exception as exc:  # noqa: BLE001 - reported as a failed call, never raised
                self._history = None
                return Completion(text="", error=f"{type(exc).__name__}: {str(exc)[:280]}")

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.name,
            "endpoint": endpoint_label(self.url),
            "input_selector": self.input_selector,
            "reply_selector": self.reply_selector,
            "send": self.send_selector or "Enter",
            "timeout_s": self.timeout,
        }
