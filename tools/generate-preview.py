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
draw.rounded_rectangle((80, 112, 192, 224), radius=22, outline=blue, width=7)
draw.ellipse((118, 150, 154, 186), outline=blue, width=6)
draw.line((136, 168, 136, 140), fill=blue, width=6)
draw.line((136, 168, 160, 182), fill=blue, width=6)
draw.line((136, 168, 112, 182), fill=blue, width=6)
draw.line((192, 142, 203, 142), fill=blue, width=7)
draw.line((192, 194, 203, 194), fill=blue, width=7)
draw.text((76, 280), "vault.miszori.dev", font=font(84, bold=True), fill="#ffffff")
draw.text((80, 400), "You have received an encrypted package.", font=font(38), fill="#a1a1aa")
image.save(Path(__file__).resolve().parents[1] / "web" / "share-preview.png", optimize=True)
