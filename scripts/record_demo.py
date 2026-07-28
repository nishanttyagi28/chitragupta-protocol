#!/usr/bin/env python
"""Record a real, reproducible demo video of the Chitragupta Protocol
public sandbox: the actual running application, driven by a real browser
via Playwright -- not a hand-designed animation.

Produces:
    docs/assets/demo/demo.mp4          (H.264, for the repo / README link)
    docs/assets/demo/demo-preview.gif  (optimized loop, embedded in README)

Prerequisites:
    pip install chitragupta-protocol[api]
    pip install playwright
    playwright install chromium
    ffmpeg on PATH (https://ffmpeg.org/) -- used only to transcode the raw
    WebM Playwright records into MP4/GIF; no other role.

Usage:
    python scripts/record_demo.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _demo_server import demo_server
from playwright.sync_api import Page, sync_playwright

OUT_DIR = Path(__file__).parent.parent / "docs" / "assets" / "demo"
VIDEO_SIZE = {"width": 1280, "height": 720}

_CAPTION_JS = """
(payload) => {
    const [title, subtitle] = payload;
    let el = document.getElementById('__demo_caption__');
    if (!el) {
        el = document.createElement('div');
        el.id = '__demo_caption__';
        el.style.position = 'fixed';
        el.style.left = '0';
        el.style.right = '0';
        el.style.bottom = '0';
        el.style.padding = '1.1rem 2rem';
        el.style.background = 'linear-gradient(0deg, rgba(0,0,0,0.92), rgba(0,0,0,0.78))';
        el.style.color = '#fff';
        el.style.fontFamily = '-apple-system, Segoe UI, Helvetica, Arial, sans-serif';
        el.style.zIndex = '999999';
        el.style.borderTop = '2px solid #6ea8ff';
        document.body.appendChild(el);
    }
    el.innerHTML = '<div style="font-size:1.15rem;font-weight:700;">' + title + '</div>' +
        (subtitle ? '<div style="font-size:0.92rem;color:#c8d0e0;margin-top:0.2rem;">' + subtitle + '</div>' : '');
}
"""

_TITLE_CARD_JS = """
(payload) => {
    const [title, subtitle] = payload;
    let el = document.getElementById('__demo_titlecard__');
    if (el) el.remove();
    el = document.createElement('div');
    el.id = '__demo_titlecard__';
    el.style.position = 'fixed';
    el.style.inset = '0';
    el.style.background = 'rgba(6,10,20,0.94)';
    el.style.color = '#fff';
    el.style.display = 'flex';
    el.style.flexDirection = 'column';
    el.style.alignItems = 'center';
    el.style.justifyContent = 'center';
    el.style.textAlign = 'center';
    el.style.padding = '3rem';
    el.style.fontFamily = '-apple-system, Segoe UI, Helvetica, Arial, sans-serif';
    el.style.zIndex = '1000000';
    el.innerHTML = '<div style="font-size:1.8rem;font-weight:800;max-width:900px;line-height:1.3;">' + title + '</div>' +
        (subtitle ? '<div style="font-size:1.1rem;color:#9aa3b5;margin-top:1rem;max-width:800px;">' + subtitle + '</div>' : '');
    document.body.appendChild(el);
}
"""


def _caption(page: Page, title: str, subtitle: str = "") -> None:
    page.evaluate(_CAPTION_JS, [title, subtitle])


def _title_card(page: Page, title: str, subtitle: str, hold_ms: int) -> None:
    page.evaluate(_TITLE_CARD_JS, [title, subtitle])
    page.wait_for_timeout(hold_ms)
    page.evaluate("document.getElementById('__demo_titlecard__')?.remove()")


def _run_scenario(page: Page, base_url: str, key: str) -> None:
    page.request.post(f"{base_url}/demo/scenario/{key}/run")
    page.goto(f"{base_url}/demo/scenario/{key}")


def record(base_url: str, video_dir: Path) -> Path:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(
            viewport=VIDEO_SIZE,
            record_video_dir=str(video_dir),
            record_video_size=VIDEO_SIZE,
        )
        page = context.new_page()

        # 1. The business problem
        page.goto(f"{base_url}/demo/")
        page.wait_for_selector("text=guided refund walkthrough")
        _title_card(
            page,
            "Did the exact approved effect happen — or just an API call that returned 200?",
            "Chitragupta Protocol: seal the intended effect, verify the actual outcome.",
            10000,
        )

        # 2. Agent proposes a refund
        _caption(page, "An agent proposes an INR 1,500 refund", "PROPOSE → PREPARE → SEAL")
        page.wait_for_timeout(3500)
        page.click("text=Start the guided refund walkthrough")
        page.wait_for_load_state("networkidle")

        # 3. Effect Manifest resolves the exact change
        _caption(
            page,
            "The exact resolved Effect Manifest is sealed",
            "Target, amount, beneficiary, and preconditions are all cryptographically bound.",
        )
        page.wait_for_timeout(11000)

        # 4. Human approves the sealed effect
        _caption(
            page,
            "A human approves the exact sealed effect",
            "AUTHORIZE — the agent cannot approve its own action.",
        )
        page.wait_for_timeout(3500)
        page.click("text=Approve exact effect")
        page.wait_for_load_state("networkidle")

        # 5 & 6. Execution succeeds exactly once + outcome verified
        _caption(
            page,
            "Execution succeeds exactly once — outcome independently verified",
            "COMMIT → VERIFY: the payment simulator's ledger is re-queried, not trusted from the commit response.",
        )
        page.wait_for_timeout(12000)

        # 7. Action Passport appears
        page.click("text=View Action Passport")
        page.wait_for_load_state("networkidle")
        _caption(
            page,
            "An Action Passport proves what actually happened",
            "PROVE — a factual record, not a security certification.",
        )
        page.wait_for_timeout(11000)

        # 8 & 9. Agent tampers with the amount/recipient -> blocked
        _caption(
            page,
            "Now: an agent tampers with the recipient after approval",
            "Same grant, different manifest — what happens?",
        )
        page.wait_for_timeout(5500)
        _run_scenario(page, base_url, "tampering")
        page.wait_for_load_state("networkidle")
        _caption(
            page,
            "Blocked: the manifest hash no longer matches",
            "The grant is bound to the exact approved effect, not just a tool name.",
        )
        page.wait_for_timeout(12000)

        # 10. Closing comparison with AgentEval
        _title_card(
            page,
            "AgentEval asks: did the agent behave correctly during development and CI?",
            "Chitragupta asks: did the exact approved effect match the actual executed outcome?",
            11000,
        )
        _title_card(
            page,
            "chitragupta-protocol",
            "MIT licensed • reference implementation • not a security certification",
            5500,
        )

        context.close()
        browser.close()

    webm_files = sorted(video_dir.glob("*.webm"), key=lambda p: p.stat().st_mtime)
    if not webm_files:
        raise RuntimeError("Playwright did not produce a video file")
    return webm_files[-1]


def transcode(webm_path: Path) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise RuntimeError("ffmpeg not found on PATH; install it to produce mp4/gif output")

    mp4_path = OUT_DIR / "demo.mp4"
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
    print(f"wrote {mp4_path}")

    # The GIF is a short teaser for the README, not the full video: clip the
    # most representative ~20s (manifest sealed -> approve -> execution
    # result) rather than encoding the entire ~90s recording at GIF sizes.
    gif_path = OUT_DIR / "demo-preview.gif"
    palette_path = Path(tempfile.gettempdir()) / "chitragupta-demo-palette.png"
    clip_start, clip_duration = "14", "20"
    filters = "fps=6,scale=640:-1:flags=lanczos"
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-ss",
            clip_start,
            "-t",
            clip_duration,
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
            clip_start,
            "-t",
            clip_duration,
            "-i",
            str(mp4_path),
            "-i",
            str(palette_path),
            "-lavfi",
            f"{filters}[x];[x][1:v]paletteuse",
            str(gif_path),
        ],
        check=True,
        capture_output=True,
    )
    print(f"wrote {gif_path}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="chitragupta-video-") as tmp:
        video_dir = Path(tmp)
        with demo_server() as base_url:
            webm_path = record(base_url, video_dir)
        transcode(webm_path)


if __name__ == "__main__":
    main()
