#!/usr/bin/env python3
"""Generate the site's responsive previews from the original screenshots.

Requires Pillow with WebP support. Run from any directory after replacing a
source screenshot; commit the resulting previews with the screenshot change.
"""
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
WIDTHS = {
    "leaving-mobile": (320, 540, 810),
    "leaving": (640, 1160, 2320),
    "kept": (480, 800, 1200),
    "manage-library": (480, 800, 1200),
}


def main():
    destination = ROOT / "site" / "assets"
    destination.mkdir(exist_ok=True)
    for name, widths in WIDTHS.items():
        with Image.open(ROOT / "docs" / "screenshots" / f"{name}.png") as source:
            for width in widths:
                height = round(source.height * width / source.width)
                preview = source.convert("RGB").resize((width, height), Image.Resampling.LANCZOS)
                path = destination / f"{name}-{width}.webp"
                preview.save(path, "WEBP", quality=85, method=6)
                print(f"{path.relative_to(ROOT)}: {path.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
