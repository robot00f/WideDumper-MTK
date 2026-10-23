import sys, os, hashlib, binascii, inspect
from pathlib import Path
from Crypto.PublicKey import RSA
from pywidevine.device import Device, DeviceTypes
from pywidevine.license_protocol_pb2 import ClientIdentification, SignedDrmCertificate, DrmCertificate

dumps = Path(os.path.join(os.path.dirname(__file__), "..", "dumps"))
der_path = dumps / "device_private_key.der"
cert_path = dumps / "cert.bin"
out_path = Path(os.path.join(os.path.dirname(__file__), "..", "device.wvd"))

# ---------- 1. key ----------
key1 = RSA.import_key(der_path.read_bytes())
assert key1.n.bit_length() == 2048 and key1.e == 65537
der_key = key1.export_key("DER")
print("key: n0x%x.." % (key1.n >> 2032), "bits", key1.n.bit_length(), "sha256", hashlib.sha256(der_key).hexdigest()[:16])
print("d sha256", hashlib.sha256(der_key).hexdigest()[:16])

# ---------- 2. walk legacy cert.bin ----------
def fields(buf):
    i = 0; out = []
    while i < len(buf):
        t = 0; s = 0
        while True:
            x = buf[i]; i += 1
            t |= (x & 0x7f) << s
            if not x & 0x80: break
            s += 7
        f, w = t >> 3, t & 7
        if w == 0:
            v = 0; s = 0
            while True:
                x = buf[i]; i += 1
                v |= (x & 0x7f) << s
                if not x & 0x80: break
                s += 7
            out.append((f, 0, v))
        elif w == 2:
            l = 0; s = 0
            while True:
                x = buf[i]; i += 1
                l |= (x & 0x7f) << s
                if not x & 0x80: break
                s += 7
            out.append((f, 2, buf[i:i+l])); i += l
        elif w == 5: out.append((f, 5, buf[i:i+4])); i += 4
        elif w == 1: out.append((f, 1, buf[i:i+8])); i += 8
        else: raise ValueError(f"bad wire {w} at {i}")
    return out

cert_blob = cert_path.read_bytes()
top = dict((f, v) for f, _, v in fields(cert_blob))
lvl1 = top[1]
lvl2 = dict((f, v) for f, _, v in fields(lvl1))[3]
signed_dev = dict((f, v) for f, _, v in fields(lvl2))[1]     # 1434B signed device chain
enc_priv = dict((f, v) for f, _, v in fields(lvl2))[2]        # 1312B encrypted private key
print("signed dev chain:", len(signed_dev), "enc priv blob:", len(enc_priv), enc_priv[:8].hex())

# validate signed_dev parses & re-serializes identically as modern SignedDrmCertificate
sdc = SignedDrmCertificate()
sdc.ParseFromString(signed_dev)
assert sdc.SerializeToString() == signed_dev, "SDC reserialize mismatch"
dc = DrmCertificate()
dc.ParseFromString(sdc.drm_certificate)
assert dc.SerializeToString() == sdc.drm_certificate, "DC reserialize mismatch"
print("device cert: type", dc.type, "serial", dc.serial_number.hex(),
      "creation", dc.creation_time_seconds, "system_id", dc.system_id,
      "pubkey bits", len(dc.public_key))
pk = RSA.import_key(dc.public_key)
print("cert pubkey n0x%x.. key n0x%x.. equal=%s" % (pk.n >> 2032, key1.n >> 2032, pk.n == key1.n))
inter = sdc.signer                     # message type in modern proto
ic = DrmCertificate(); ic.ParseFromString(inter.drm_certificate)
assert ic.SerializeToString() == inter.drm_certificate
print("intermediate: type", ic.type, "serial", ic.serial_number.hex(), "creation", ic.creation_time_seconds, "sigid", ic.system_id)

# ---------- 3. client_id blob ----------
device_unique_id = ic.serial_number  # 16B on-board device fingerprint
client_id = hashlib.sha256(device_unique_id).digest()
ci = ClientIdentification()
ci.type = ClientIdentification.TokenType.DRM_DEVICE_CERTIFICATE
ci.token = signed_dev
client_id_blob = ci.SerializeToString()
# pywidevine requires exact CRT roundtrip of the cid
cid_check = ClientIdentification(); cid_check.ParseFromString(client_id_blob)
assert cid_check.SerializeToString() == client_id_blob
print("cid blob bytes", len(client_id_blob), "client_id", client_id.hex())

# ---------- 4. wvd ----------
dev = Device(
    type_=DeviceTypes.ANDROID,
    security_level=3,
    flags={},
    private_key=der_key,
    client_id=client_id_blob,
)
print("Device OK:", repr(dev)[:160], "system_id", dev.system_id)
out_path.write_bytes(dev.dumps())
print("wvd written:", out_path, out_path.stat().st_size, "bytes")

# ---------- 5. round-trip verify ----------
dev2 = Device.load(out_path)
assert dev2.private_key.n == key1.n
assert dev2.client_id.SerializeToString() == client_id_blob
print("VERIFY OK: load round trip; system_id", dev2.system_id)
(dumps / "client_id_blob.bin").write_bytes(client_id_blob)
print("client blob saved")
