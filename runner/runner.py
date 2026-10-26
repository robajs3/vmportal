"""Wykonuje skrypt użytkownika (Python + Playwright) na działającej przeglądarce sesji.

W skrypcie dostępne są: playwright, browser, context (profil z ciasteczkami/wtyczkami), page.
Skrypt przychodzi base64 w zmiennej BR_SCRIPT.
"""
import base64
import os
import sys
import traceback

from playwright.sync_api import sync_playwright

CDP = os.environ.get("BR_CDP", "http://127.0.0.1:9222")


def main():
    code = base64.b64decode(os.environ["BR_SCRIPT"]).decode("utf-8")
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP)
        context = browser.contexts[0] if browser.contexts else browser.new_context()
        page = context.pages[0] if context.pages else context.new_page()
        env = {"__name__": "__main__", "playwright": p, "browser": browser, "context": context, "page": page}
        try:
            exec(compile(code, "<skrypt>", "exec"), env)
        except SystemExit as e:
            sys.exit(e.code)
        except BaseException:
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
