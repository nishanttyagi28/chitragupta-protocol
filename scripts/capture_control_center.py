#!/usr/bin/env python
"""Capture real screenshots from the authenticated Milestone A UI."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _control_center_demo import ControlCenterDemo, control_center_demo_server
from playwright.sync_api import Page, sync_playwright

OUT_DIR = Path(__file__).parent.parent / "docs" / "assets" / "control-center"
VIEWPORT = {"width": 1440, "height": 1000}


def _login(page: Page, demo: ControlCenterDemo) -> None:
    page.goto(f"{demo.base_url}/control-center/login")
    page.get_by_label("Organization ID").fill(demo.org_id)
    page.get_by_label("Email").fill(demo.owner_email)
    page.get_by_label("Password").fill(demo.owner_password)
    page.get_by_role("button", name="Enter Control Center").click()
    page.wait_for_selector("h1:text('Effect overview')")


def _shot(page: Page, name: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=True)
    print(f"saved {path.relative_to(Path(__file__).parent.parent)}")


def capture(demo: ControlCenterDemo) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
        _login(page, demo)

        _shot(page, "01-overview-dashboard")

        page.goto(f"{demo.base_url}/control-center/approvals")
        page.wait_for_selector("h1:text('Approval inbox')")
        _shot(page, "02-approval-inbox")

        page.goto(f"{demo.base_url}/control-center/refunds/{demo.pending_manifest_id}")
        page.wait_for_selector("h2:text('Exact before and after')")
        _shot(page, "03-exact-effect-risk-policy")

        page.goto(f"{demo.base_url}/control-center/refunds/{demo.verified_manifest_id}/passport")
        page.wait_for_selector("text=Action Passport")
        _shot(page, "04-action-passport")

        page.goto(f"{demo.base_url}/control-center/audit?q={demo.verified_manifest_id}")
        page.wait_for_selector("h1:text('Audit explorer')")
        _shot(page, "05-searchable-audit")
        browser.close()


def main() -> None:
    with control_center_demo_server() as demo:
        capture(demo)


if __name__ == "__main__":
    main()
