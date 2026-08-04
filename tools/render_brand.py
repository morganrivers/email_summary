"""Render the Letterlock brand mark (envelope + padlock) into frontend/static.

    python -m tools.render_brand

Pillow is the only dependency. The geometry below is defined on a 512 square
and supersampled, so every emitted size comes from the same drawing.
"""

import sys

from PIL import Image, ImageChops, ImageDraw

from backend.paths import STATIC_DIR

SS = 4
REF = 512

NAVY = (15, 23, 48)
GOLD = (201, 161, 91)

PLATE_R = 0.22

# The wordmark and the app icon: a wide envelope sized to sit beside 19px type.
MARK_GEOMETRY = dict(
    envelope_w=415,
    envelope_h=250,
    corner_r=32,
    flap_w=30,
    flap_apex_dy=0,
    lock_scale=1.25,
    lock_dy=14,
    lock_gap=22,
)

# The favicon is a different drawing, not the mark shrunk. A tab renders it at
# 16px, where the flap lines and the clearance ring of the mark collapse into
# grey mush, so this one is squarer, drops the ring, and carries a padlock large
# enough to survive the downsample.
FAVICON_GEOMETRY = dict(
    envelope_w=440,
    envelope_h=300,
    corner_r=40,
    flap_w=36,
    flap_apex_dy=0,
    lock_scale=1.6,
    lock_dy=4,
    lock_gap=0,
)

# The titlebar mark is cropped to the envelope and emitted at twice its display
# height, so the page can size it against the type (see #titlebar .mark) without
# padding of ours changing what "14px tall" means.
MARK_H = 28


def draw_lock(draw, cx, cy, s, pad=0):
    assert s > 0, "lock scale must be positive"
    body_w, body_h, body_r = 122 * s, 88 * s, 26 * s
    body_bottom = cy + 79.5 * s
    body_top = body_bottom - body_h

    shackle_r = 34 * s
    shackle_w = 22 * s
    arc_cy = body_top - 26 * s
    outer_r = shackle_r + shackle_w / 2 + pad

    draw.arc(
        [cx - outer_r, arc_cy - outer_r, cx + outer_r, arc_cy + outer_r],
        start=180, end=360, fill=255, width=int(round(shackle_w + 2 * pad)),
    )
    leg_bottom = body_top + 12 * s + pad
    for sign in (-1, 1):
        x = cx + sign * shackle_r
        draw.rectangle(
            [x - shackle_w / 2 - pad, arc_cy, x + shackle_w / 2 + pad, leg_bottom],
            fill=255,
        )
    draw.rounded_rectangle(
        [cx - body_w / 2 - pad, body_top - pad,
         cx + body_w / 2 + pad, body_bottom + pad],
        radius=body_r + pad, fill=255,
    )


def build_alpha(envelope_w, envelope_h, corner_r, flap_w, flap_apex_dy,
                lock_scale, lock_dy, lock_gap):
    """Coverage mask for one drawing: a filled envelope with the flap fold and
    the padlock cut out of it. A positive lock_gap first adds a ring of body
    around the padlock, which is what keeps the cut-out readable where the
    padlock crosses the envelope edge."""
    assert envelope_w > 0 and envelope_h > 0, "envelope must have an extent"
    w = h = REF * SS
    cx, cy = w / 2, h / 2
    x0, x1 = cx - envelope_w * SS / 2, cx + envelope_w * SS / 2
    y0, y1 = cy - envelope_h * SS / 2, cy + envelope_h * SS / 2

    body = Image.new("L", (w, h), 0)
    ImageDraw.Draw(body).rounded_rectangle(
        [x0, y0, x1, y1], radius=corner_r * SS, fill=255)

    flap = Image.new("L", (w, h), 0)
    apex = (cx, cy + flap_apex_dy * SS)
    for corner in ((x0, y0), (x1, y0)):
        ImageDraw.Draw(flap).line([corner, apex], fill=255, width=int(flap_w * SS))
    ink = ImageChops.subtract(body, flap)

    lock_cy = cy + lock_dy * SS
    if lock_gap:
        ring = Image.new("L", (w, h), 0)
        draw_lock(ImageDraw.Draw(ring), cx, lock_cy, lock_scale * SS,
                  pad=lock_gap * SS)
        ink = ImageChops.lighter(ink, ImageChops.multiply(ring, body))

    lock = Image.new("L", (w, h), 0)
    draw_lock(ImageDraw.Draw(lock), cx, lock_cy, lock_scale * SS)
    ink = ImageChops.subtract(ink, lock)

    return ink.resize((REF, REF), Image.LANCZOS)


def compose(alpha, glyph_color, plate_color=None, plate_radius=PLATE_R):
    assert alpha.size == (REF, REF), "alpha must be the reference square"
    glyph = Image.new("RGBA", (REF, REF), glyph_color + (0,))
    glyph.putalpha(alpha)
    if plate_color is None:
        return glyph

    mask = Image.new("L", (REF * SS, REF * SS), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, REF * SS - 1, REF * SS - 1],
        radius=int(plate_radius * REF * SS), fill=255,
    )
    plate = Image.new("RGBA", (REF, REF), plate_color + (255,))
    plate.putalpha(mask.resize((REF, REF), Image.LANCZOS))
    return Image.alpha_composite(plate, glyph)


def scaled(image, size):
    assert size > 0, "size must be positive"
    return image.resize((size, size), Image.LANCZOS)


def cropped_mark(glyph, height):
    """The bare glyph trimmed to the envelope and scaled to a given height. The
    square canvas is the icon's, not the wordmark's: leaving its margins in
    would make the page size the padding rather than the envelope."""
    box = glyph.getbbox()
    assert box is not None, "glyph is empty"
    trimmed = glyph.crop(box)
    width = round(trimmed.width * height / trimmed.height)
    return trimmed.resize((width, height), Image.LANCZOS)


def main():
    assert STATIC_DIR.is_dir(), f"missing static dir: {STATIC_DIR}"
    mark_alpha = build_alpha(**MARK_GEOMETRY)
    plated = compose(mark_alpha, GOLD, NAVY)
    square = compose(mark_alpha, GOLD, NAVY, plate_radius=0.0)
    # Navy on transparency: the tab strip supplies the background, so the icon
    # is the symbol itself rather than a tile of ours sitting in the strip.
    tab = compose(build_alpha(**FAVICON_GEOMETRY), NAVY)

    written = []
    scaled(tab, 48).save(STATIC_DIR / "favicon.ico",
                         sizes=[(16, 16), (32, 32), (48, 48)])
    written.append("favicon.ico")

    for name, image, size in (
        ("favicon-32.png", tab, 32),
        ("icon-512.png", plated, 512),
        ("apple-touch-icon.png", square, 180),
    ):
        scaled(image, size).save(STATIC_DIR / name)
        written.append(name)

    mark = cropped_mark(compose(mark_alpha, GOLD), MARK_H)
    mark.save(STATIC_DIR / "mark.png")
    written.append("mark.png")

    for name in written:
        print("wrote", STATIC_DIR / name)
    print(f"mark.png is {mark.width}x{mark.height}; "
          f"display it at {round(mark.width / 2)}x{round(mark.height / 2)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
