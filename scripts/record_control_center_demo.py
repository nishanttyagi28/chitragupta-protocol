#!/usr/bin/env python
"""Record the real authenticated Control Center buyer journey."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _control_center_demo import ControlCenterDemo, control_center_demo_server
from playwright.sync_api import Page, sync_playwright

OUT_DIR = Path(__file__).parent.parent / "docs" / "assets" / "control-center"
VIDEO_SIZE = {"width": 1280, "height": 720}

_CAPTION_JS = """
([title, subtitle]) => {
    let element = document.getElementById('__ks_caption__');
    if (!element) {
        element = document.createElement('div');
        element.id = '__ks_caption__';
        Object.assign(element.style, {
            position: 'fixed', left: '0', right: '0', bottom: '0',
            padding: '0.85rem 1.5rem', background: 'rgba(3, 8, 15, 0.94)',
            color: '#fff', fontFamily: 'Inter, Segoe UI, sans-serif',
            borderTop: '2px solid #63e6be', zIndex: '999999'
        });
        document.body.appendChild(element);
    }
    element.innerHTML = `<strong>${title}</strong>` +
        `<div style="color:#b7c4d6;margin-top:0.2rem">${subtitle}</div>`;
}
"""


def _caption(page: Page, title: str, subtitle: str, hold_ms: int = 4500) -> None:
    page.evaluate(_CAPTION_JS, [title, subtitle])
    page.wait_for_timeout(hold_ms)


def _login(page: Page, demo: ControlCenterDemo) -> None:
    page.goto(f"{demo.base_url}/control-center/login")
    page.get_by_label("Organization ID").fill(demo.org_id)
    page.get_by_label("Email").fill(demo.owner_email)
    page.get_by_label("Password").fill(demo.owner_password)
    page.get_by_role("button", name="Enter Control Center").click()
    page.wait_for_selector("h1:text('Effect overview')")


def record(demo: ControlCenterDemo, video_dir: Path) -> Path:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(
            viewport=VIDEO_SIZE,
            record_video_dir=str(video_dir),
            record_video_size=VIDEO_SIZE,
        )
        page = context.new_page()
        _login(page, demo)
        _caption(
            page,
            "One organization. Real Gateway state.",
            "The overview is read through the typed SDK; audit integrity is verified.",
        )

        page.goto(f"{demo.base_url}/control-center/approvals")
        page.wait_for_selector("h1:text('Approval inbox')")
        _caption(
            page,
            "An exact sealed refund waits for a human decision.",
            "The inbox is organization-scoped and populated by the real Gateway API.",
        )

        page.goto(f"{demo.base_url}/control-center/refunds/{demo.pending_manifest_id}")
        page.wait_for_selector("h2:text('Exact before and after')")
        _caption(
            page,
            "Before, after, risk signals, and policy requirements.",
            "The manifest hash binds amount, beneficiary, balances, and idempotency key.",
            6500,
        )
        page.get_by_role("button", name="Approve exact effect").click()
        page.wait_for_selector("text=1 / 3 completed")
        _caption(
            page,
            "One approval cannot bypass a 3-person quorum.",
            "The authenticated identity is server-derived; the effect remains pending.",
        )

        page.goto(f"{demo.base_url}/control-center/refunds/{demo.verified_manifest_id}")
        page.wait_for_selector("text=verified match")
        _caption(
            page,
            "A completed effect is independently observed.",
            "The timeline records proposal, quorum authorization, commit, and verification.",
            5500,
        )
        page.get_by_role("link", name="View Action Passport").click()
        page.wait_for_selector("text=Action Passport")
        _caption(
            page,
            "Action Passport V2 packages the factual evidence.",
            "Seal, quorum-bound grant, outcome, and audit-chain checks are visible.",
            5500,
        )

        page.goto(f"{demo.base_url}/control-center/audit?q={demo.verified_manifest_id}")
        page.wait_for_selector("h1:text('Audit explorer')")
        _caption(
            page,
            "The audit explorer searches only this organization.",
            "The displayed journal is append-only and hash-chain verified.",
            5500,
        )
        context.close()
        browser.close()

    videos = sorted(video_dir.glob("*.webm"), key=lambda path: path.stat().st_mtime)
    if not videos:
        raise RuntimeError("Playwright did not produce a video")
    return videos[-1]


def transcode(webm_path: Path) -> None:
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise RuntimeError("ffmpeg is required to produce MP4 and GIF outputs")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    mp4_path = OUT_DIR / "control-center-demo.mp4"
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-i",
            str(webm_path),
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            "-crf",
            "23",
            "-preset",
            "medium",
            str(mp4_path),
        ],
        check=True,
        capture_output=True,
    )

    gif_path = OUT_DIR / "control-center-preview.gif"
    palette_path = webm_path.parent / "palette.png"
    filters = "fps=6,scale=640:-1:flags=lanczos"
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-ss",
            "8",
            "-t",
            "20",
            "-i",
            str(mp4_path),
            "-vf",
            f"{filters},palettegen",
            str(palette_path),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-ss",
            "8",
            "-t",
            "20",
            "-i",
            str(mp4_path),
            "-i",
            str(palette_path),
            "-lavfi",
            f"{filters}[frame];[frame][1:v]paletteuse",
            str(gif_path),
        ],
        check=True,
        capture_output=True,
    )
    print(f"wrote {mp4_path}")
    print(f"wrote {gif_path}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="karmasakshi-control-video-") as temp:
        with control_center_demo_server() as demo:
            webm_path = record(demo, Path(temp))
        transcode(webm_path)


if __name__ == "__main__":
    main()
