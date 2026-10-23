import json, struct, os

ev = json.load(open(os.path.join(os.path.dirname(__file__), "..", "dumps", "dump_events.json")))
hit = [e for e in ev if e.get("type") == "fallback_hits"][0]["hits"][0]
b = bytes.fromhex(hit["full"])  # starts at hitAddr - 0x600
BASE_OFF = 0x600  # offset of hit within b

# find DER SEQUENCE start: search backwards from ESEQ (=BASE_OFF) for '02 81 81' (n header) then '30 81'
eseq = b.find(bytes.fromhex("020301000102820100"))
assert eseq == BASE_OFF
# n INTEGER header expected at eseq - 132 or eseq - 131 (02 82 01 01)
n_hdr_off = b.find(bytes.fromhex("02820101"), eseq - 400)  # n INTEGER (257-byte)

def read_int(buf, off):
    assert buf[off] == 0x02, buf[off]
    l = buf[off + 1]
    j = off + 2
    if l == 0x81:
        l = buf[j]; j += 1
    elif l == 0x82:
        l = struct.unpack(">H", buf[j:j + 2])[0]; j += 2
    return buf[j:j + l], j + l

n_int, after_n = read_int(b, n_hdr_off)
e_int, after_e = read_int(b, after_n)
d_int, after_d = read_int(b, after_e)
p_int, after_p = read_int(b, after_d)
q_int, after_q = read_int(b, after_p)
dp_int, after_dp = read_int(b, after_q)
dq_int, after_dq = read_int(b, after_dp)
qi_int, after_qi = read_int(b, after_dq)

n = int.from_bytes(n_int, "big")
e = int.from_bytes(e_int, "big")
d = int.from_bytes(d_int, "big")
p = int.from_bytes(p_int, "big")
q = int.from_bytes(q_int, "big")
dp = int.from_bytes(dp_int, "big")
dq = int.from_bytes(dq_int, "big")
qi = int.from_bytes(qi_int, "big")

print("n bits", n.bit_length(), "e", e, "d bits", d.bit_length())
print("p*q == n:", p * q == n)
print("d==dp:", d % (p - 1) == dp, "d==dq:", d % (q - 1) == dq)
print("dp ok:", dp * e % (p - 1) == 1, "dq ok:", dq * e % (q - 1) == 1, "qi ok:", qi * q % p == 1)

# save full DER up to qInv end for records
der = b[n_hdr_off - 4: after_qi]
open(os.path.join(os.path.dirname(__file__), "..", "dumps", "private_key.der"), "wb").write(der)
print("DER bytes saved:", len(der), "head", der[:8].hex())

# also save the whole 4608 region for forensics
open(os.path.join(os.path.dirname(__file__), "..", "dumps", "mem_blob.bin"), "wb").write(b)
print("blob saved")
