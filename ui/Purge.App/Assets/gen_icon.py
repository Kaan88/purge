# Regenerates Purge.ico / Purge.png (placeholder icon): python -I gen_icon.py Purge.ico Purge.png
"""Draws Purge's placeholder app icon (rounded square, gradient, white 'P' with a sparkle) as a multi-size ICO.
Pure Python: signed-distance shapes, 4x4 supersampling, PNG-in-ICO."""
import math, struct, sys, zlib

def sd_round_rect(x, y, cx, cy, hw, hh, r):
    qx, qy = abs(x - cx) - hw + r, abs(y - cy) - hh + r
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r

def sd_ring_right(x, y, cx, cy, r_out, r_in):
    # Right half of a ring (the bowl of the P) plus straight top/bottom arms back to the stem.
    if x >= cx:
        d = math.hypot(x - cx, y - cy)
        return max(d - r_out, r_in - d)
    # left of centre: horizontal bars at top and bottom of the bowl
    top = sd_round_rect(x, y, cx - 0.08, cy - (r_out + r_in) / 2, 0.08, (r_out - r_in) / 2, 0)
    bot = sd_round_rect(x, y, cx - 0.08, cy + (r_out + r_in) / 2, 0.08, (r_out - r_in) / 2, 0)
    return min(top, bot)

def sd_sparkle(x, y, cx, cy, s):
    dx, dy = abs(x - cx) / s, abs(y - cy) / s
    # four-point star: |x|^0.5 + |y|^0.5 <= 1
    v = math.sqrt(dx) + math.sqrt(dy)
    return (v - 1) * s * 0.5

def shade(u, v):
    """u, v in [0,1]. Returns RGBA floats."""
    d_bg = sd_round_rect(u, v, 0.5, 0.5, 0.46, 0.46, 0.2)
    if d_bg > 0:
        return (0, 0, 0, 0)
    t = (u + v) / 2
    c1, c2 = (0x25, 0x63, 0xEB), (0x14, 0xB8, 0xA6)
    r, g, b = (c1[i] + (c2[i] - c1[i]) * t for i in range(3))
    stem = sd_round_rect(u, v, 0.355, 0.5, 0.075, 0.27, 0.035)
    bowl = sd_round_rect(u, v, 0.47, 0.39, 0.19, 0.16, 0.16)
    counter = sd_round_rect(u, v, 0.50, 0.39, 0.06, 0.055, 0.055)
    p = max(min(stem, bowl), -counter)
    sp = sd_sparkle(u, v, 0.70, 0.70, 0.12)
    if min(p, sp) <= 0:
        return (1, 1, 1, 1)
    return (r / 255, g / 255, b / 255, 1)

def render(size, ss=4):
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            acc = [0.0] * 4
            for sy in range(ss):
                for sx in range(ss):
                    c = shade((x + (sx + 0.5) / ss) / size, (y + (sy + 0.5) / ss) / size)
                    a = c[3]
                    acc[0] += c[0] * a; acc[1] += c[1] * a; acc[2] += c[2] * a; acc[3] += a
            n = ss * ss
            a = acc[3] / n
            if a > 0:
                row += bytes([round(acc[0] / acc[3] * 255), round(acc[1] / acc[3] * 255), round(acc[2] / acc[3] * 255), round(a * 255)])
            else:
                row += bytes(4)
        rows.append(bytes(row))
    raw = b"".join(rows)
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))

sizes = [16, 20, 24, 32, 40, 48, 64, 256]
pngs = [render(s) for s in sizes]
out = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
for s, p in zip(sizes, pngs):
    out += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(p), offset)
    offset += len(p)
out += b"".join(pngs)
open(sys.argv[1], "wb").write(out)
open(sys.argv[2], "wb").write(pngs[sizes.index(64)])
print("ok", len(out))
