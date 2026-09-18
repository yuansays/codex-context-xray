from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets"
BG = "#07111f"
PANEL = "#101d30"
PANEL_2 = "#14243a"
TEXT = "#f3f7ff"
MUTED = "#8fa4bf"
PURPLE = "#9b87f5"
CYAN = "#42d6d0"
AMBER = "#f7ba52"
RED = "#fb7185"
GREEN = "#4ade80"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    names = (
        ["C:/Windows/Fonts/seguisb.ttf", "C:/Windows/Fonts/arialbd.ttf"]
        if bold
        else ["C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/arial.ttf"]
    )
    names += [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/SFNS.ttf",
    ]
    for name in names:
        if Path(name).exists():
            return ImageFont.truetype(name, size=size)
    return ImageFont.load_default()


def rounded(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    fill: str,
    radius: int = 16,
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def base_canvas(width: int, height: int) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    for x in range(0, width, 32):
        draw.line((x, 0, x, height), fill="#0b192a", width=1)
    for y in range(0, height, 32):
        draw.line((0, y, width, y), fill="#0b192a", width=1)
    return image, draw


def draw_header(draw: ImageDraw.ImageDraw, width: int, subtitle: str) -> None:
    draw.text((48, 30), "CODEX", font=font(14, True), fill=CYAN)
    draw.text((48, 52), "CONTEXT X-RAY", font=font(36, True), fill=TEXT)
    draw.text((48, 101), subtitle, font=font(15), fill=MUTED)
    rounded(draw, (width - 214, 36, width - 48, 74), PANEL_2, 19)
    draw.ellipse((width - 194, 51, width - 184, 61), fill=GREEN)
    draw.text((width - 172, 47), "OFFLINE · READ ONLY", font=font(12, True), fill=TEXT)


LANES = (
    ("INSTRUCTIONS", PURPLE, ("AGENTS.md", "override", "32 KiB")),
    ("SKILLS & TOOLS", CYAN, ("release-check", "MCP: docs", "duplicate")),
    ("HOOKS & RULES", AMBER, ("PreToolUse", "deny rm", "merged")),
    ("PERMISSIONS", RED, (":workspace", "network off", "legacy wins")),
)


def draw_lanes(
    draw: ImageDraw.ImageDraw,
    width: int,
    height: int,
    active_lane: int | None,
    revealed: int,
) -> None:
    left, gap = 48, 14
    lane_width = (width - 96 - gap * 3) // 4
    top, bottom = 150, height - 66
    for index, (title, color, nodes) in enumerate(LANES):
        x = left + index * (lane_width + gap)
        outline = color if active_lane == index else "#263a54"
        draw.rounded_rectangle(
            (x, top, x + lane_width, bottom),
            radius=18,
            fill=PANEL,
            outline=outline,
            width=2,
        )
        draw.rectangle((x, top, x + lane_width, top + 5), fill=color)
        draw.text((x + 16, top + 20), title, font=font(12, True), fill=color)
        for node_index, node in enumerate(nodes):
            y = top + 62 + node_index * 76
            visible = node_index <= revealed
            fill = PANEL_2 if visible else "#0c192a"
            node_outline = color if active_lane == index and node_index == revealed else "#263a54"
            draw.rounded_rectangle(
                (x + 14, y, x + lane_width - 14, y + 54),
                radius=12,
                fill=fill,
                outline=node_outline,
                width=2 if node_outline == color else 1,
            )
            draw.ellipse(
                (x + 26, y + 20, x + 36, y + 30),
                fill=color if visible else "#33445a",
            )
            draw.text(
                (x + 46, y + 16),
                node if visible else "waiting…",
                font=font(13, True),
                fill=TEXT if visible else MUTED,
            )
            if node_index < len(nodes) - 1:
                draw.line(
                    (x + lane_width // 2, y + 54, x + lane_width // 2, y + 76),
                    fill="#33445a",
                    width=2,
                )


def make_social() -> Image.Image:
    image, draw = base_canvas(1200, 630)
    draw_header(draw, 1200, "Know exactly why a Codex source wins — before the session starts.")
    draw_lanes(draw, 1200, 630, 1, 2)
    rounded(draw, (48, 578, 696, 610), "#0d2431", 16)
    draw.text(
        (64, 585),
        "deterministic precedence · trust gates · redacted evidence",
        font=font(13, True),
        fill=CYAN,
    )
    draw.text((922, 585), "github.com/yuansays", font=font(12), fill=MUTED)
    return image


def make_demo() -> list[Image.Image]:
    frames: list[Image.Image] = []
    for step in range(12):
        image, draw = base_canvas(960, 540)
        draw_header(draw, 960, "Fictional repository · schema v1 · no network")
        if step == 0:
            active, revealed = None, -1
        else:
            active = min((step - 1) // 3, 3)
            revealed = min((step - 1) % 3, 2)
        draw_lanes(draw, 960, 540, active, revealed)
        status = (
            "Scanning static declarations…"
            if active is None
            else f"Explaining {LANES[active][0].title()} · source {revealed + 1}/3"
        )
        color = MUTED if active is None else LANES[active][1]
        draw.text((48, 503), status, font=font(13, True), fill=color)
        frames.append(image)
    return frames


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    make_social().save(OUT / "social-preview.png", optimize=True)
    frames = make_demo()
    frames[0].save(
        OUT / "demo.gif",
        save_all=True,
        append_images=frames[1:],
        duration=[1200] + [1500] * 11,
        loop=0,
        optimize=True,
        disposal=2,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
