#!/usr/bin/env python3
"""Render the SecDash icon (shield with bar chart) to PNG at every size DSM uses.

Pure Python (zlib + struct) so it runs anywhere. Output:
  PACKAGE_ICON.PNG (64), PACKAGE_ICON_256.PNG, package/ui/images/secdash_<n>.png
"""
import math
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP = (0x1E, 0x3A, 0x8A)     # indigo
BOTTOM = (0x0F, 0x76, 0x6E)  # teal
WHITE = (0xFF, 0xFF, 0xFF)
SS = 4                       # supersampling per axis


def in_rounded_square(x, y, r=0.22):
    dx = max(abs(x - 0.5) - (0.5 - r), 0)
    dy = max(abs(y - 0.5) - (0.5 - r), 0)
    return dx * dx + dy * dy <= r * r


def in_shield(x, y):
    top, bottom, half = 0.17, 0.86, 0.30
    if y < top or y > bottom:
        return False
    v = (y - top) / (bottom - top)
    if v < 0.5:
        w = half
    else:
        t = (v - 0.5) / 0.5
        w = half * math.cos(t * math.pi / 2) ** 0.8
    return abs(x - 0.5) <= w


def in_bars(x, y):
    base = 0.66
    for cx, h in ((0.40, 0.14), (0.50, 0.26), (0.60, 0.20)):
        if abs(x - cx) <= 0.035 and base - h <= y <= base:
            return True
    return False


def pixel(x, y):
    if not in_rounded_square(x, y):
        return None
    if in_shield(x, y) and not in_bars(x, y):
        return WHITE
    return tuple(int(a + (b - a) * y) for a, b in zip(TOP, BOTTOM))


def render(n):
    rows = []
    for py in range(n):
        row = bytearray([0])
        for px in range(n):
            acc = [0, 0, 0]
            hits = 0
            for sy in range(SS):
                for sx in range(SS):
                    c = pixel((px + (sx + 0.5) / SS) / n, (py + (sy + 0.5) / SS) / n)
                    if c:
                        hits += 1
                        for i in range(3):
                            acc[i] += c[i]
            if hits:
                row += bytes(int(a / hits) for a in acc) + bytes([hits * 255 // (SS * SS)])
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows), 9)

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


def main():
    out = {
        os.path.join(ROOT, "PACKAGE_ICON.PNG"): 64,
        os.path.join(ROOT, "PACKAGE_ICON_256.PNG"): 256,
    }
    for n in (16, 24, 32, 48, 64, 72, 256):
        out[os.path.join(ROOT, "package", "ui", "images", "secdash_%d.png" % n)] = n
    for path, n in out.items():
        with open(path, "wb") as f:
            f.write(render(n))
        print("wrote", os.path.relpath(path, ROOT))


if __name__ == "__main__":
    main()
