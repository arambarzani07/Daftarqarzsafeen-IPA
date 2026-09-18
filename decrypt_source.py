#!/usr/bin/env python3
import glob, hashlib, hmac, json, os
from pathlib import Path

key_hex = os.environ.get("SOURCE_KEY_HEX", "").strip()
if len(key_hex) != 128:
    raise SystemExit("SOURCE_KEY_HEX must contain 64 bytes")
key = bytes.fromhex(key_hex)
enc_key, mac_key = key[:32], key[32:]

def stream_xor(data: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    pos = 0
    counter = 0
    while pos < len(data):
        block = hmac.new(
            enc_key,
            nonce + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        take = min(32, len(data) - pos)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += take
        counter += 1
    return bytes(out)

records = []
for manifest_path in sorted(glob.glob("manifests/batch*.json")):
    with open(manifest_path, "r", encoding="utf-8") as f:
        records.extend(json.load(f)["files"])

if len(records) != 85:
    raise SystemExit(f"Expected 85 encrypted build inputs, found {len(records)}")

for item in records:
    path = item["path"]
    nonce = bytes.fromhex(item["nonce"])
    cipher = Path(item["blob"]).read_bytes()
    mac_input = path.encode("utf-8") + b"\0" + nonce + cipher
    actual = hmac.new(mac_key, mac_input, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, item["tag"]):
        raise SystemExit(f"HMAC verification failed: {path}")
    plain = stream_xor(cipher, nonce)
    if len(plain) != item["size"]:
        raise SystemExit(f"Size verification failed: {path}")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(plain)

print(f"Decrypted and authenticated {len(records)} production files")
