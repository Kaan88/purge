# Regenerates Purge's app icon: python -I gen_icon.py <out-dir>
"""Purge's app icon (chosen 2026-11-25): a violet rounded square with a white P whose bowl holds an
undo arrow, cut out in the tile's colour. Removal you can take back.

Pure Python, no packages: signed-distance shapes, 6x6 supersampling, PNG-in-ICO. Writes Purge.ico
(16..256) and Purge.png (256) into <out-dir>. Below 32 px the arrow is left out: at that size it
would be a smudge, and the plain P reads better.
"""
import math, struct, sys, zlib

TOP_LEFT = (0x55, 0x2A, 0xC2)      # deep violet
BOTTOM_RIGHT = (0xA9, 0x8A, 0xF9)  # light violet


def sd_box(x, y, cx, cy, hw, hh, r):
    qx, qy = abs(x - cx) - hw + r, abs(y - cy) - hh + r
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def sd_segment(x, y, ax, ay, bx, by, w):
    px, py, dx, dy = x - ax, y - ay, bx - ax, by - ay
    h = max(0.0, min(1.0, (px * dx + py * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - dx * h, py - dy * h) - w


def sd_triangle_left(x, y, tip_x, base_x, cy, half):
    # Isosceles triangle pointing left: tip at (tip_x, cy), base vertical at base_x.
    if x > base_x:
        return max(x - base_x, abs(y - cy) - half)
    t = (x - tip_x) / (base_x - tip_x)
    edge = abs(y - cy) - half * max(t, 0.0)
    slope = math.hypot(1.0, half / (base_x - tip_x))
    return max(edge / slope, tip_x - x)


def sd_arc_right(x, y, cx, cy, r, w):
    # The right half of a ring of radius r, stroke half-width w, ends rounded.
    if x >= cx:
        return abs(math.hypot(x - cx, y - cy) - r) - w
    return min(math.hypot(x - cx, y - (cy - r)), math.hypot(x - cx, y - (cy + r))) - w


def shade(u, v, arrow):
    tile = sd_box(u, v, 0.5, 0.5, 0.44, 0.44, 0.2)
    if tile > 0:
        return None
    t = max(0.0, min(1.0, (u + v) / 2 * 1.1 - 0.05))
    bg = tuple(TOP_LEFT[i] + (BOTTOM_RIGHT[i] - TOP_LEFT[i]) * t for i in range(3))
    # The letter is drawn shifted right (and a hair down) of its own box: the stem's mass pulls
    # it left, so its optical centre sits right of the geometric one.
    u, v = u - 0.02, v - 0.01
    stem = sd_box(u, v, 0.32, 0.49, 0.085, 0.30, 0.065)
    # The bowl's round right side, and a block that carries its flat top and bottom edges into the
    # stem, so the top of the P is one piece (no dip where the bowl's curve meets the stem).
    bowl = min(sd_box(u, v, 0.50, 0.41, 0.265, 0.22, 0.215),
               sd_box(u, v, 0.40, 0.41, 0.165, 0.22, 0.065))
    p = min(stem, bowl)
    if arrow:
        head = sd_triangle_left(u, v, 0.335, 0.455, 0.36, 0.09)
        shaft = sd_segment(u, v, 0.44, 0.36, 0.56, 0.36, 0.04)
        curl = sd_arc_right(u, v, 0.56, 0.445, 0.085, 0.04)
        p = max(p, -min(head, shaft, curl))
    return bg, p <= 0


def render(size, ss=6):
    arrow = size >= 32
    out = bytearray()
    for py in range(size):
        out.append(0)
        for px in range(size):
            r = g = b = a = 0.0
            for sy in range(ss):
                for sx in range(ss):
                    u = (px + (sx + 0.5) / ss) / size
                    v = (py + (sy + 0.5) / ss) / size
                    s = shade(u, v, arrow)
                    if s is None:
                        continue
                    (cr, cg, cb), white = s
                    if white:
                        cr = cg = cb = 255.0
                    r, g, b, a = r + cr, g + cg, b + cb, a + 1
            n = ss * ss
            if a:
                out += bytes((round(r / a), round(g / a), round(b / a), round(255 * a / n)))
            else:
                out += b"\0\0\0\0"
    return bytes(out)


def png(size, raw):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main(out_dir):
    sizes = [16, 20, 24, 32, 40, 48, 64, 256]
    images = {s: png(s, render(s)) for s in sizes}
    head = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries, blobs = b"", b""
    for s in sizes:
        data = images[s]
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        blobs += data
    with open(f"{out_dir}/Purge.ico", "wb") as f:
        f.write(head + entries + blobs)
    with open(f"{out_dir}/Purge.png", "wb") as f:
        f.write(images[256])
    for s in (16, 24, 32, 48):
        with open(f"{out_dir}/preview-{s}.png", "wb") as f:
            f.write(images[s])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
