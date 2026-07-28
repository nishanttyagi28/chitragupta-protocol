#!/usr/bin/env python
"""Capture real screenshots of the running Chitragupta Protocol public demo.

Starts the actual FastAPI app (the same code path used by the Dockerfile
and render.yaml), drives it with a real Chromium browser via Playwright,
and saves screenshots of genuine rendered pages -- no mockups, no hand-edited
images. Re-run any time the demo UI changes to refresh docs/assets/screenshots/.

Prerequisites:
    pip install chitragupta-protocol[api]
    pip install playwright
    playwright install chromium

Usage:
    python scripts/capture_screenshots.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _demo_server import demo_server
from playwright.sync_api import Page, sync_playwright

OUT_DIR = Path(__file__).parent.parent / "docs" / "assets" / "screenshots"
VIEWPORT = {"width": 1280, "height": 900}


def _shot(page: Page, name: str, *, full_page: bool = True, selector: str | None = None) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{name}.png"
    if selector:
        page.locator(selector).screenshot(path=str(path))
    else:
        page.screenshot(path=str(path), full_page=full_page)
    print(f"saved {path.relative_to(OUT_DIR.parent.parent.parent)}")


def _run_scenario(page: Page, base_url: str, key: str) -> None:
    page.request.post(f"{base_url}/demo/scenario/{key}/run")
    page.goto(f"{base_url}/demo/scenario/{key}")


def capture(base_url: str) -> None:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)

        # 1. Product landing / overview
        page.goto(f"{base_url}/demo/")
        page.wait_for_selector("text=guided refund walkthrough")
        _shot(page, "01-landing-overview")

        # 2 & 3. Pending effect approval + exact Effect Manifest before/after diff
        page.request.post(f"{base_url}/demo/refund/propose")
        page.goto(f"{base_url}/demo/")
        page.click("text=Resume the in-progress refund walkthrough")
        page.wait_for_selector("text=Approve exact effect")
        _shot(page, "02-pending-effect-approval")
        _shot(page, "03-effect-manifest-before-after-diff", selector=".diff")

        # 4. Successful verified execution
        manifest_url = page.url
        page.click("text=Approve exact effect")
        page.wait_for_selector("text=Execution result")
        _shot(page, "04-successful-verified-execution")

        # 9. Action Passport
        page.click("text=View Action Passport")
        page.wait_for_selector("text=Action Passport")
        _shot(page, "09-action-passport")

        # 5. Blocked tampering attempt
        _run_scenario(page, base_url, "tampering")
        page.wait_for_selector("text=Blocked")
        _shot(page, "05-blocked-tampering-attempt")

        # 6. Revoked grant blocked
        _run_scenario(page, base_url, "revoked")
        page.wait_for_selector("text=Blocked")
        _shot(page, "06-revoked-grant-blocked")

        # 7. Delegation tree
        _run_scenario(page, base_url, "delegation")
        page.goto(f"{base_url}/demo/delegation")
        page.wait_for_selector("text=Root grant")
        _shot(page, "07-delegation-tree")

        # 8. Audit timeline
        page.goto(f"{base_url}/demo/audit")
        page.wait_for_selector("text=Chain integrity")
        _shot(page, "08-audit-timeline")

        # 10. Final verification/proof view (independent outcome verification catching a mismatch)
        _run_scenario(page, base_url, "outcome-mismatch")
        page.wait_for_selector("text=Independent verification")
        _shot(page, "10-verification-proof-view")

        browser.close()
        print(f"\n{manifest_url}")


def main() -> None:
    with demo_server() as base_url:
        capture(base_url)


if __name__ == "__main__":
    main()
