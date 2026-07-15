"""Generate the placeholder app icon (RGBA PNG) using only the stdlib.

Dark rounded square with a teal 'Q' lattice dot pattern — stand-in until
there's real brand art.
"""

import struct
import zlib
import math
import os

SIZE = 512


def make_pixels():
    px = bytearray()
    cx = cy = SIZE / 2
    corner = 110
    for y in range(SIZE):
        for x in range(SIZE):
            # rounded-rect mask
            dx = max(corner - x, x - (SIZE - corner), 0)
            dy = max(corner - y, y - (SIZE - corner), 0)
            inside = (dx * dx + dy * dy) <= corner * corner
            if not inside:
                px += b"\x00\x00\x00\x00"
                continue
            r, g, b = 8, 11, 16
            d = math.hypot(x - cx, y - cy)
            # ring of the Q
            if 130 < d < 180:
                r, g, b = 47, 212, 182
            # tail of the Q
            if 0 < (x - cx) < 150 and 0 < (y - cy) < 150 and abs((x - cx) - (y - cy)) < 26:
                r, g, b = 47, 212, 182
            px += bytes((r, g, b, 255))
    return bytes(px)


def write_png(path, pixels):
    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    raw = b"".join(
        b"\x00" + pixels[y * SIZE * 4 : (y + 1) * SIZE * 4] for y in range(SIZE)
    )
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "src-tauri", "icons")
    os.makedirs(out_dir, exist_ok=True)
    write_png(os.path.join(out_dir, "icon.png"), make_pixels())
    print("wrote", os.path.join(out_dir, "icon.png"))
