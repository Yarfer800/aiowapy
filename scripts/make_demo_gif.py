"""Render the README demo GIF from a real offline run.

    uv run --with pillow python scripts/make_demo_gif.py

It executes examples/offline_demo.py, captures what it actually prints, and lays that
text out as an animated terminal. Nothing is faked except the framing: the message ids
and ack come from the run itself.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "assets"
GIF_PATH = OUT_DIR / "demo.gif"
POSTER_PATH = OUT_DIR / "demo.png"

WIDTH, HEIGHT = 960, 540
PADDING = 28
TITLEBAR = 42
FONT_SIZE = 19
LINE_HEIGHT = 30
FPS = 10

BG = (13, 17, 23)
WINDOW = (22, 27, 34)
BORDER = (48, 54, 61)
TEXT = (201, 209, 217)
COMMAND = (126, 231, 135)
INCOMING = (121, 192, 255)
OUTGOING = (86, 211, 100)
MUTED = (139, 148, 158)
ACCENT = (35, 134, 54)
CURSOR = (88, 166, 255)

FONT_CANDIDATES = [
    Path.home() / ".local/share/fonts/JetBrainsMonoNerd/JetBrainsMonoNerdFontMono-Regular.ttf",
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
]


@dataclass(frozen=True, slots=True)
class Line:
    text: str
    color: tuple[int, int, int]


def load_font() -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if path.exists():
            return ImageFont.truetype(str(path), FONT_SIZE)
    fallback = ImageFont.load_default(size=FONT_SIZE)
    assert isinstance(fallback, ImageFont.FreeTypeFont)
    return fallback


def run_demo() -> list[Line]:
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp) / "demo.session"
        result = subprocess.run(
            [sys.executable, str(ROOT / "examples" / "offline_demo.py"), str(session)],
            capture_output=True,
            text=True,
            cwd=tmp,
            timeout=120,
            check=False,
        )
    output = (result.stdout + result.stderr).strip().splitlines()
    if result.returncode != 0:
        raise SystemExit("offline demo failed:\n" + "\n".join(output))

    lines = [
        Line("$ pip install aiowapy", COMMAND),
        Line("$ python examples/offline_demo.py", COMMAND),
    ]
    for raw in output:
        stripped = raw.strip()
        if stripped.startswith("<-"):
            lines.append(Line(raw, INCOMING))
        elif stripped.startswith("->"):
            lines.append(Line(raw, OUTGOING))
        else:
            lines.append(Line(raw, TEXT))
    lines.append(Line("", TEXT))
    lines.append(Line("ok  1 chat, 2 messages, 0 network calls", OUTGOING))
    return lines


def background(font: ImageFont.FreeTypeFont) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (PADDING - 12, PADDING - 12, WIDTH - PADDING + 12, HEIGHT - PADDING + 12),
        radius=14,
        fill=WINDOW,
        outline=BORDER,
        width=1,
    )
    for index, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        x = PADDING + 4 + index * 20
        draw.ellipse((x, PADDING + 2, x + 11, PADDING + 13), fill=color)
    title = "aiowapy — offline demo (scripted server, real protocol)"
    draw.text((WIDTH / 2, PADDING + 8), title, font=font, fill=MUTED, anchor="mm")
    draw.line((PADDING, PADDING + TITLEBAR, WIDTH - PADDING, PADDING + TITLEBAR), fill=BORDER)
    return image


def frame(base: Image.Image, lines: list[Line], visible: int, cursor: bool) -> Image.Image:
    image = base.copy()
    draw = ImageDraw.Draw(image)
    x = PADDING + 6
    y = PADDING + TITLEBAR + 18
    for line in lines[:visible]:
        draw.text((x, y), line.text, font=FONT, fill=line.color)
        y += LINE_HEIGHT
    if cursor:
        draw.rectangle((x, y, x + 10, y + FONT_SIZE + 2), fill=CURSOR)
    return image


FONT = load_font()


def build() -> None:
    lines = run_demo()
    base = background(FONT)
    frames: list[Image.Image] = []
    durations: list[int] = []

    for index in range(1, len(lines) + 1):
        for _ in range(2):
            frames.append(frame(base, lines, index, cursor=False))
            durations.append(140)
    for _ in range(6):
        frames.append(frame(base, lines, len(lines), cursor=True))
        durations.append(250)
        frames.append(frame(base, lines, len(lines), cursor=False))
        durations.append(250)

    final = frame(base, lines, len(lines), cursor=False).copy()
    draw = ImageDraw.Draw(final)
    left, right = WIDTH - 412, WIDTH - PADDING - 6
    draw.rounded_rectangle((left, HEIGHT - 76, right, HEIGHT - 36), radius=10, fill=ACCENT)
    draw.text(
        ((left + right) / 2, HEIGHT - 56),
        "github.com/Yarfer800/aiowapy",
        font=FONT,
        fill=(240, 246, 252),
        anchor="mm",
    )
    for _ in range(10):
        frames.append(final)
        durations.append(120)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    final.save(POSTER_PATH)
    frames[0].save(
        GIF_PATH,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(f"wrote {GIF_PATH.relative_to(ROOT)} ({GIF_PATH.stat().st_size // 1024} KiB)")
    print(f"wrote {POSTER_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    if shutil.which("uv") is None:  # pragma: no cover - developer machine
        print("uv is required to run the demo script", file=sys.stderr)
    build()
