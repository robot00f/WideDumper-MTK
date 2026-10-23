from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
from pywidevine.license_protocol_pb2 import WidevinePsshData, SignedMessage, LicenseRequest, SignedDrmCertificate, DrmCertificate
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA1, SHA256
import hashlib
import os
import sys
from pathlib import Path

BASE = Path(os.path.join(os.path.dirname(__file__), ".."))
device_path = sys.argv[1] if len(sys.argv) > 1 else BASE / "device.wvd"
dumps_dir = BASE / "dumps"
dumps_dir.mkdir(exist_ok=True)

dev = Device.load(device_path)
cdm = Cdm.from_device(dev)
sid = cdm.open()
w = WidevinePsshData()
w.key_ids.append(bytes.fromhex("3b1e80494397fef03ea7667cf1fec82d"))
from pymp4.parser import Box
from construct import Container
pssh = PSSH(Box.build(Container(type=b"pssh", version=0, flags=0, system_ID=PSSH.SystemId.Widevine, init_data=w.SerializeToString())))
ch = cdm.get_license_challenge(sid, pssh, "STREAMING")
dumps_dir.joinpath("test_challenge.bin").write_bytes(ch)
print("challenge saved:", len(ch), "bytes")

sm = SignedMessage(); sm.ParseFromString(ch)
lr = LicenseRequest(); lr.ParseFromString(sm.msg)
print("LicenseRequest.type:", lr.type)
print("client_id token len:", len(lr.client_id.token))

sdc = SignedDrmCertificate(); sdc.ParseFromString(lr.client_id.token)
dcm = DrmCertificate(); dcm.ParseFromString(sdc.drm_certificate)
print("challenge device cert serial:", dcm.serial_number.hex(), "sysid", dcm.system_id)

# --- verify device cert's RSA signature using the INTERMEDIATE pubkey ---
# NOTE: 'signer' is a message field (not bytes) in the modern proto
ikey = None
try:
    ic = DrmCertificate(); ic.ParseFromString(sdc.signer.drm_certificate)
    ikey = RSA.import_key(ic.public_key)
except Exception:
    pass
for hname, h in (("SHA1", SHA1), ("SHA256", SHA256)):
    try:
        pkcs1_15.new(ikey).verify(h.new(sdc.drm_certificate), sdc.signature)
        print(f"device cert signature verified with intermediate key ({hname}): OK")
        break
    except Exception:
        pass
else:
    print("device cert signature did not verify with intermediate (standard pkcs1)")

# --- verify SignedMessage signature (PSS) with OUR device private key ---
data = sm.msg + len(sm.msg).to_bytes(4, "big")
for hname, h in (("SHA1", SHA1), ("SHA256", SHA256)):
    try:
        pss.new(dev.private_key).verify(h.new(data), sm.signature)
        print(f"SignedMessage PSS {hname} signature verified with our device key: OK")
        break
    except Exception as ex:
        last = str(ex)
else:
    print("SignedMessage PSS verify failed:", last)

# --- also try over the plain msg / msg only ---
for name, blob in (("msg only", sm.msg),):
    for hname, h in (("SHA1", SHA1), ("SHA256", SHA256)):
        try:
            pss.new(dev.private_key).verify(h.new(blob), sm.signature)
            print(f"SignedMessage PSS {hname} over {name}: OK")
            break
        except Exception:
            pass
cdm.close(sid)
print("VERIFICATION COMPLETE")
