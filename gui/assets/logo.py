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

TOP = (0x0A, 0x6B, 0xC7)
BOTTOM = (0x00, 0x52, 0x9E)
MARK = (0xFF, 0xFF, 0xFF)


@dataclass(frozen=True)
class Geometry:
    inset: float
    radius: float
    stroke: float
    left: float
    right: float
    crown: float
    foot: float


def master(size):
    k = size / 16
    return Geometry(
        inset=1 * k,
        radius=3.5 * k,
        stroke=1.5 * k,
        left=5 * k,
        right=11 * k,
        crown=7 * k,
        foot=12 * k,
    )


TUNED = {
    16: Geometry(inset=1, radius=3, stroke=2, left=5, right=11, crown=7, foot=12),
    20: Geometry(inset=1, radius=4, stroke=2, left=6, right=14, crown=9, foot=15),
    24: Geometry(inset=1, radius=5, stroke=2, left=7, right=17, crown=11, foot=18),
    32: Geometry(inset=2, radius=6.5, stroke=3, left=9.5, right=22.5, crown=15, foot=23.5),
}

SIZES = [16, 20, 24, 32, 40, 48, 64, 256]


def geometry(size):
    return TUNED.get(size) or master(size)


def rgb(c):
    return tuple(v / 255 for v in c)


def draw(ctx, size, g):
    lo, hi = g.inset, size - g.inset
    w = hi - lo
    r = g.radius
    ctx.new_sub_path()
    ctx.arc(hi - r, lo + r, r, -math.pi / 2, 0)
    ctx.arc(hi - r, hi - r, r, 0, math.pi / 2)
    ctx.arc(lo + r, hi - r, r, math.pi / 2, math.pi)
    ctx.arc(lo + r, lo + r, r, math.pi, 3 * math.pi / 2)
    ctx.close_path()
    fill = cairo.LinearGradient(0, lo, 0, lo + w)
    fill.add_color_stop_rgb(0, *rgb(TOP))
    fill.add_color_stop_rgb(1, *rgb(BOTTOM))
    ctx.set_source(fill)
    ctx.fill()

    cx = (g.left + g.right) / 2
    radius = (g.right - g.left) / 2
    ctx.move_to(g.left, g.foot)
    ctx.line_to(g.left, g.crown)
    ctx.arc(cx, g.crown, radius, math.pi, 2 * math.pi)
    ctx.line_to(g.right, g.foot)
    ctx.set_source_rgb(*rgb(MARK))
    ctx.set_line_width(g.stroke)
    ctx.set_line_cap(cairo.LINE_CAP_ROUND)
    ctx.set_line_join(cairo.LINE_JOIN_ROUND)
    ctx.stroke()


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
    g = master(16)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="256" height="256">
  <defs>
    <linearGradient id="fill" x1="0" y1="{g.inset:g}" x2="0" y2="{16 - g.inset:g}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#{bytes(TOP).hex()}"/>
      <stop offset="1" stop-color="#{bytes(BOTTOM).hex()}"/>
    </linearGradient>
  </defs>
  <rect x="{g.inset:g}" y="{g.inset:g}" width="{16 - 2 * g.inset:g}" height="{16 - 2 * g.inset:g}" rx="{g.radius:g}" fill="url(#fill)"/>
  <path d="M{g.left:g} {g.foot:g}V{g.crown:g}a3 3 0 0 1 6 0V{g.foot:g}" fill="none" stroke="#{bytes(MARK).hex()}" stroke-width="{g.stroke:g}" stroke-linecap="round" stroke-linejoin="round"/>
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
