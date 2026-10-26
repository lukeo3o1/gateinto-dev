"""Generate the Gateinto app icon: gateinto.svg, gateinto.ico and an optional preview sheet.

Usage: python logo.py OUT_DIR [SHEET_PNG]
Requires pycairo. Uses no network.
"""

import io
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

import cairo

TILE = (0x26, 0x2B, 0x36)
DOOR = (0x0C, 0x0E, 0x13)
ARCH = (0xFF, 0xFF, 0xFF)
EYES = (0xFF, 0xC9, 0x4A)


@dataclass(frozen=True)
class Geometry:
    inset: float
    radius: float
    stroke: float
    left: float
    right: float
    crown: float
    foot: float
    eye_dx: float
    eye_y: float
    eye_rx: float
    eye_ry: float
    bend: float | None = None
    round_caps: bool = True
    round_eyes: bool = True


def master(size):
    k = size / 48
    return Geometry(
        inset=2 * k,
        radius=11 * k,
        stroke=4.5 * k,
        left=13 * k,
        right=35 * k,
        crown=23 * k,
        foot=40 * k,
        eye_dx=3.7 * k,
        eye_y=27 * k,
        eye_rx=2.2 * k,
        eye_ry=3 * k,
    )


SNAPPED = {"round_caps": False, "round_eyes": False}

TUNED = {
    16: Geometry(
        inset=1,
        radius=3.5,
        stroke=2,
        left=4,
        right=12,
        crown=8,
        foot=14,
        eye_dx=1.5,
        eye_y=9,
        eye_rx=0.5,
        eye_ry=1,
        bend=3,
        **SNAPPED,
    ),
    20: Geometry(
        inset=1,
        radius=4.5,
        stroke=2,
        left=5,
        right=15,
        crown=10,
        foot=17,
        eye_dx=2,
        eye_y=11.5,
        eye_rx=1,
        eye_ry=1.5,
        bend=4,
        **SNAPPED,
    ),
    24: Geometry(
        inset=1,
        radius=5.5,
        stroke=2,
        left=7,
        right=17,
        crown=11,
        foot=21,
        eye_dx=2,
        eye_y=13.5,
        eye_rx=1,
        eye_ry=1.5,
        bend=4,
        **SNAPPED,
    ),
    32: Geometry(
        inset=1,
        radius=7.5,
        stroke=3,
        left=8.5,
        right=23.5,
        crown=15,
        foot=28,
        eye_dx=2.5,
        eye_y=18,
        eye_rx=1.5,
        eye_ry=2,
        bend=6,
        **SNAPPED,
    ),
}

SIZES = [16, 20, 24, 32, 40, 48, 64, 256]


def geometry(size):
    return TUNED.get(size) or master(size)


def rgb(c):
    return tuple(v / 255 for v in c)


def hexcolor(c):
    return "#" + bytes(c).hex()


def tile(ctx, size, g):
    lo, hi = g.inset, size - g.inset
    r = g.radius
    ctx.new_sub_path()
    ctx.arc(hi - r, lo + r, r, -math.pi / 2, 0)
    ctx.arc(hi - r, hi - r, r, 0, math.pi / 2)
    ctx.arc(lo + r, hi - r, r, math.pi / 2, math.pi)
    ctx.arc(lo + r, lo + r, r, math.pi, 3 * math.pi / 2)
    ctx.close_path()


def arch(ctx, g, inset):
    left, right = g.left + inset, g.right - inset
    half = (g.right - g.left) / 2
    bend = (half if g.bend is None else g.bend) - inset
    top = g.crown - half + inset
    ctx.move_to(left, g.foot)
    ctx.arc(left + bend, top + bend, bend, math.pi, 3 * math.pi / 2)
    ctx.arc(right - bend, top + bend, bend, 3 * math.pi / 2, 2 * math.pi)
    ctx.line_to(right, g.foot)


def eye(ctx, g, cx):
    if not g.round_eyes:
        ctx.rectangle(cx - g.eye_rx, g.eye_y - g.eye_ry, 2 * g.eye_rx, 2 * g.eye_ry)
        return
    ctx.save()
    ctx.translate(cx, g.eye_y)
    ctx.scale(g.eye_rx, g.eye_ry)
    ctx.arc(0, 0, 1, 0, 2 * math.pi)
    ctx.restore()


def draw(ctx, size, g):
    tile(ctx, size, g)
    ctx.set_source_rgb(*rgb(TILE))
    ctx.fill()

    # The doorway reaches under the stroke so the anti-aliased inner edge blends into it, not the tile.
    arch(ctx, g, g.stroke / 4)
    ctx.close_path()
    ctx.set_source_rgb(*rgb(DOOR))
    ctx.fill()

    arch(ctx, g, 0)
    ctx.set_source_rgb(*rgb(ARCH))
    ctx.set_line_width(g.stroke)
    cap = cairo.LINE_CAP_ROUND if g.round_caps else cairo.LINE_CAP_BUTT
    ctx.set_line_cap(cap)
    ctx.set_line_join(cairo.LINE_JOIN_ROUND)
    ctx.stroke()

    centre = (g.left + g.right) / 2
    for cx in (centre - g.eye_dx, centre + g.eye_dx):
        eye(ctx, g, cx)
        ctx.set_source_rgb(*rgb(EYES))
        ctx.fill()


def render(size):
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ctx = cairo.Context(surface)
    ctx.set_antialias(cairo.ANTIALIAS_GRAY)
    draw(ctx, size, geometry(size))
    surface.flush()
    return surface


def straight_bgra(surface):
    size = surface.get_width()
    stride = surface.get_stride()
    data = bytes(surface.get_data())
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            b, g, r, a = data[y * stride + 4 * x : y * stride + 4 * x + 4]
            if a:
                b, g, r = (min(255, (v * 255 + a // 2) // a) for v in (b, g, r))
            row += bytes((b, g, r, a))
        rows.append(bytes(row))
    return rows


def dib(surface):
    size = surface.get_width()
    rows = straight_bgra(surface)
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = b"".join(reversed(rows))
    mask_stride = ((size + 31) // 32) * 4
    mask = bytearray()
    for row in reversed(rows):
        bits = bytearray(mask_stride)
        for x in range(size):
            if row[4 * x + 3] == 0:
                bits[x // 8] |= 0x80 >> (x % 8)
        mask += bits
    return header + pixels + bytes(mask)


def png(surface):
    out = io.BytesIO()
    surface.write_to_png(out)
    return out.getvalue()


def ico(sizes):
    images = [(size, png(render(size)) if size >= 256 else dib(render(size))) for size in sizes]
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = len(head) + 16 * len(images)
    entries, blobs = b"", b""
    for size, blob in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
        blobs += blob
    return head + entries + blobs


def svg():
    g = master(48)
    side = 48 - 2 * g.inset
    radius = (g.right - g.left) / 2
    inner = radius - g.stroke / 2
    centre = (g.left + g.right) / 2
    rise = g.foot - g.crown
    eyes = "\n".join(
        f'  <ellipse cx="{cx:g}" cy="{g.eye_y:g}" rx="{g.eye_rx:g}" ry="{g.eye_ry:g}" fill="{hexcolor(EYES)}"/>'
        for cx in (round(centre - g.eye_dx, 6), round(centre + g.eye_dx, 6))
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="256" height="256">
  <rect x="{g.inset:g}" y="{g.inset:g}" width="{side:g}" height="{side:g}" rx="{g.radius:g}" fill="{hexcolor(TILE)}"/>
  <path d="M{g.left + g.stroke / 2:g} {g.foot:g}V{g.crown:g}a{inner:g} {inner:g} 0 0 1 {2 * inner:g} 0v{rise:g}z" fill="{hexcolor(DOOR)}"/>
  <path d="M{g.left:g} {g.foot:g}V{g.crown:g}a{radius:g} {radius:g} 0 0 1 {2 * radius:g} 0v{rise:g}" fill="none" stroke="{hexcolor(ARCH)}" stroke-width="{g.stroke:g}" stroke-linecap="round" stroke-linejoin="round"/>
{eyes}
</svg>
"""


def sheet(path):
    zoom = 8
    small = [16, 20, 24, 32, 40, 48, 64]
    pad = 24
    band = 64 * zoom + 2 * pad
    width = sum(s * zoom for s in small[:4]) + 5 * pad + 256 + pad
    height = 2 * band
    out = cairo.ImageSurface(cairo.FORMAT_RGB24, width, height)
    ctx = cairo.Context(out)
    for i, bg in enumerate([(0xF3, 0xF3, 0xF3), (0x20, 0x20, 0x20)]):
        top = i * band
        ctx.set_source_rgb(*rgb(bg))
        ctx.rectangle(0, top, width, band)
        ctx.fill()
        x = pad
        for size in small[:4]:
            ctx.save()
            ctx.translate(x, top + pad)
            ctx.scale(zoom, zoom)
            source = cairo.SurfacePattern(render(size))
            source.set_filter(cairo.FILTER_NEAREST)
            ctx.set_source(source)
            ctx.paint()
            ctx.restore()
            x += size * zoom + pad
        y = top + pad + 32 * zoom + pad
        x = pad
        for size in small:
            ctx.set_source_surface(render(size), x, y)
            ctx.paint()
            x += size + pad
        ctx.set_source_surface(render(256), width - 256 - pad, top + pad)
        ctx.paint()
    out.write_to_png(str(path))


def main():
    out = Path(sys.argv[1])
    (out / "gateinto.svg").write_text(svg())
    (out / "gateinto.ico").write_bytes(ico(SIZES))
    if len(sys.argv) > 2:
        sheet(Path(sys.argv[2]))


if __name__ == "__main__":
    main()
