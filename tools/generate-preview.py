"""Regenerate the wide banner and square messaging icon with Python 3 and Pillow (development only)."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


def font(size, bold=False):
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for name in candidates:
        if Path(name).is_file():
            return ImageFont.truetype(name, size)
    return ImageFont.load_default(size=size)


image = Image.new("RGB", (1200, 630), "#000000")
draw = ImageDraw.Draw(image)
blue = "#3b82f6"
draw.rounded_rectangle((80, 112, 192, 224), radius=22, outline=blue, width=7)
draw.ellipse((118, 150, 154, 186), outline=blue, width=6)
draw.line((136, 168, 136, 140), fill=blue, width=6)
draw.line((136, 168, 160, 182), fill=blue, width=6)
draw.line((136, 168, 112, 182), fill=blue, width=6)
draw.line((192, 142, 203, 142), fill=blue, width=7)
draw.line((192, 194, 203, 194), fill=blue, width=7)
draw.text((76, 280), "vault.miszori.dev", font=font(84, bold=True), fill="#ffffff")
draw.text((80, 400), "Encrypted file and secret sharing system.", font=font(38), fill="#a1a1aa")
image.save(Path(__file__).resolve().parents[1] / "web" / "share-preview.png", optimize=True)


scale = 32
image = Image.new("RGB", (64 * scale, 64 * scale), "#000000")
draw = ImageDraw.Draw(image)
blue = "#3b82f6"


def box(*coordinates):
    return tuple(int(value * scale) for value in coordinates)


def stroke(start, end):
    draw.line([box(*start), box(*end)], fill=blue, width=int(3.5 * scale))
    for x, y in (start, end):
        draw.ellipse(box(x - 1.75, y - 1.75, x + 1.75, y + 1.75), fill=blue)


draw.rounded_rectangle(box(10, 12, 50, 52), radius=8 * scale, outline=blue, width=int(3.5 * scale))
draw.ellipse(box(23, 25, 37, 39), outline=blue, width=int(3.5 * scale))
stroke((30, 32), (30, 21))
stroke((30, 32), (39, 37))
stroke((30, 32), (21, 37))
stroke((50, 22), (54, 22))
stroke((50, 42), (54, 42))
image = image.resize((1024, 1024), Image.Resampling.LANCZOS)
image.save(Path(__file__).resolve().parents[1] / "web" / "share-icon.png", optimize=True)
