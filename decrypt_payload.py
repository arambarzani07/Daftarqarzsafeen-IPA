#!/usr/bin/env python3
import base64
import json
import re
import struct
import sys
from pathlib import Path

MASK32 = 0xFFFFFFFF

def rotl(v, n):
    return ((v << n) & MASK32) | (v >> (32 - n))

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]; s[b] = rotl(s[b], 7)

def chacha_block(key, counter, nonce):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("bad key/nonce length")
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))
    work = state.copy()
    for _ in range(10):
        qr(work, 0, 4, 8, 12)
        qr(work, 1, 5, 9, 13)
        qr(work, 2, 6, 10, 14)
        qr(work, 3, 7, 11, 15)
        qr(work, 0, 5, 10, 15)
        qr(work, 1, 6, 11, 12)
        qr(work, 2, 7, 8, 13)
        qr(work, 3, 4, 9, 14)
    return struct.pack("<16I", *[((work[i] + state[i]) & MASK32) for i in range(16)])

def crypt(data, key, nonce):
    out = bytearray(len(data))
    counter = 1
    for off in range(0, len(data), 64):
        stream = chacha_block(key, counter, nonce)
        counter += 1
        chunk = data[off:off + 64]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ stream[i]
    return bytes(out)

def nonce_for(group, part):
    n = group * 100 + part + 1
    return b"\x00" * 8 + struct.pack("<I", n)

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: decrypt_payload.py <32-byte-key-hex>")
    key = bytes.fromhex(sys.argv[1])
    if len(key) != 32:
        raise SystemExit("invalid key length")

    rx = re.compile(r"g(\d{2})p(\d{2})\.b64$")
    by_group = {}
    for path in sorted(Path("payload").glob("g??p??.b64")):
        m = rx.fullmatch(path.name)
        if not m:
            continue
        g, p = int(m.group(1)), int(m.group(2))
        by_group.setdefault(g, []).append((p, path))

    expected_groups = list(range(14))
    if sorted(by_group) != expected_groups:
        raise SystemExit(f"payload groups mismatch: {sorted(by_group)}")

    restored = 0
    restored_paths = set()
    for group in expected_groups:
        pieces = []
        expected_part = 0
        for part, path in sorted(by_group[group]):
            if part != expected_part:
                raise SystemExit(f"group {group}: expected part {expected_part}, got {part}")
            expected_part += 1
            cipher = base64.b64decode(path.read_text().strip())
            plain = crypt(cipher, key, nonce_for(group, part))
            pieces.append(plain.decode("ascii"))
        obj = json.loads("".join(pieces))
        if obj.get("group") != group:
            raise SystemExit(f"group marker mismatch: {group}")
        for item in obj["files"]:
            rel = item["path"]
            if rel in restored_paths:
                raise SystemExit(f"duplicate restored path: {rel}")
            restored_paths.add(rel)
            dst = Path(rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(base64.b64decode(item["data"]))
            dst.chmod(int(item.get("mode", "100644"), 8) & 0o777)
            restored += 1

    if restored != 85:
        raise SystemExit(f"expected 85 files, restored {restored}")

    main_screen = Path("source/lib/screens/main_screen.dart").read_text()
    if "Icons.refresh_rounded" not in main_screen:
        raise SystemExit("final refresh icon missing")
    if "Icons.search_rounded" not in main_screen:
        raise SystemExit("final search icon missing")
    if "IconData(0xe514, fontFamily: 'MaterialIcons')" in main_screen:
        raise SystemExit("stale search glyph mapping remains")
    if main_screen.count("tooltip: 'نوێکردنەوە'") != 1:
        raise SystemExit("refresh action count mismatch")
    if main_screen.count("tooltip: 'گەڕان'") != 1:
        raise SystemExit("search action count mismatch")

    print(f"restored {restored} encrypted production files")
    print("final AppBar contract verified: one refresh + one search")

if __name__ == "__main__":
    main()
