"""Regenerate the square messaging icon with Python 3 and Pillow (development only)."""
from pathlib import Path
from PIL import Image, ImageDraw


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
image.save(Path(__file__).resolve().parents[1] / "web" / "share-preview.png", optimize=True)
