"""Regenerate the generic public PNG with Python 3 and Pillow (development only)."""
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
draw.line([(80, 200), (80, 124), (120, 124), (138, 142), (194, 142), (194, 200), (80, 200)], fill=blue, width=7, joint="curve")
draw.text((76, 280), "drive.miszori.dev", font=font(84, bold=True), fill="#ffffff")
draw.text((80, 400), "You have received an encrypted package.", font=font(38), fill="#a1a1aa")
image.save(Path(__file__).resolve().parents[1] / "web" / "share-preview.png", optimize=True)
