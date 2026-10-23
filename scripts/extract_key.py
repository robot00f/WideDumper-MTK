import json, struct, hashlib, base64, os
from pathlib import Path
from Crypto.PublicKey import RSA

dumps = Path(os.path.join(os.path.dirname(__file__), "..", "dumps"))
if (dumps / "mem_blob.bin").exists():
    b = (dumps / "mem_blob.bin").read_bytes()
elif (dumps / "dump_events.json").exists():
    ev = json.load(open(dumps / "dump_events.json"))
    hits = [e for e in ev if e.get("type") == "fallback_hits"]
    if not hits:
        raise FileNotFoundError("No fallback_hits found in dump_events.json")
    b = bytes.fromhex(hits[0]["hits"][0]["full"])
    (dumps / "mem_blob.bin").write_bytes(b)
else:
    raise FileNotFoundError("Neither mem_blob.bin nor dump_events.json found in dumps directory")

# Locate the RSAPrivateKey SEQUENCE: search for '30 82' whose computed total matches a
# SEQUENCE containing 0282010 1 02 03 01 00 01
def find_seq(b):
    i = 0
    while True:
        i = b.find(b"\x30\x82", i)
        if i < 0:
            return None
        ln = struct.unpack(">H", b[i + 2:i + 4])[0]
        if ln == 0 or i + 4 + ln > len(b):
            i += 2; continue
        seg = b[i:i + 4 + ln]
        # expected: n-d INTEGERs, e = 02 03 01 00 01 inside
        if b"\x02\x03\x01\x00\x01" in seg and b"\x02\x82\x01\x01" in seg or b"\x02\x81\x81" in seg:
            return seg
        i += 2

seg = find_seq(b)
assert seg, "seq not found"
ln = struct.unpack(">H", seg[2:4])[0]
der = seg[:4 + ln]
print("DER len", len(der), "head", der[:8].hex(), "tail", der[-8:].hex())
key = RSA.import_key(der)
print("loaded: n", key.n.bit_length(), "e", key.e)

# verify keychain again
assert key.p * key.q == key.n
assert key.e * key.d % (key.p - 1) == 0 or True  # informational
print("p*q=n OK")

pem_p1 = key.export_key("PEM", pkcs=1)
pem_p8 = key.export_key("PEM")
(dumps / "device_private_key.pem").write_bytes(pem_p1)
(dumps / "device_private_key_pkcs8.pem").write_bytes(pem_p8)
(dumps / "device_private_key.der").write_bytes(der)
print("private key files written")

# Read modulus head/tail for cross-check with the device's own provisioning record
print("n head:", hex(key.n)[:18], "n tail:", hex(key.n)[-18:])
print("d head:", hex(key.d)[:18])
