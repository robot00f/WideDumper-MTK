# Tutorial: Extracting Widevine L3 Key from an Android Device (Frida + Ghidra + pywidevine)

> ⚠️ **Strictly for Educational and Research Purposes.** Extracting DRM keys is subject to service terms and applicable local regulations. Use ONLY on YOUR OWN test device.

> **Final Objective:** Produce a `device.wvd` (pywidevine) containing the RSA private provisioning key of the device, dumped directly from the `mediaserver` process in RAM.

Tested hardware: Widevine CDM **L3_0** on MediaTek MT6582 with Android 5.0.2 (LG G3 Stylus D690).
RVAs of `libwvdrmengine.so` change per build; if targeting a different build, recalculate offsets in Ghidra.

---

## 1. Why Hooking into RAM Is Required

Files on disk **cannot** be used directly:

| File in `/data/mediadrm/IDM1013/` | Content | Issue |
|---|---|---|
| `L3/cert.bin` | Certificate chain (`DeviceCertificate` + intermediate) + 1312 B encrypted blob | The private key is encrypted with a key derived from **`ay64.dat`** |
| `ay64.dat` | Key that encrypts the blob | Protected by MTK hardware (TEE); cannot be decrypted within user space |

**The only window** where the RSA private key exists in **plaintext in memory** is in the `onLeave` callback of the routine responsible for `LoadDeviceRSAKey` inside `libwvdrmengine.so`; it resides there only for microseconds.

### Internal Function Map in `libwvdrmengine.so` (Reference for Reproducing Analysis)

| RVA (offset) | Obfuscated Function | Role |
|---|---|---|
| `+0x538cd` | **`_oecc19`** | Loads and decrypts the RSA private key (`LoadDeviceRSAKey`) → **the winning hook target** |
| `+0x53904` | `_oecc36` | Signs the manifest with the key |
| `+0x58cd4` | `_lcc20` | Dispatcher to the `ulns/nvpds` VM (AES-128 with LCG tables decrypted per invocation) |
| `+0x5cfdc`/`+0x5db0c` | `nvpds` / `ulns` | Obfuscated bytecode interpreter (bypassed; direct RAM scan worked reliably) |

> The VM de-virtualization was bypassed because a simple scan using the DER pattern across **rw-** pages around `_oecc19.onLeave` was sufficient to locate the key.

---

## 2. Environment Setup

### 2.1. Clone Artifacts from the Device

```powershell
adb shell "su -c 'cp /data/mediadrm/IDM1013/L3/cert.bin /sdcard/cert.bin && chmod 644 /sdcard/cert.bin'"
adb pull /sdcard/cert.bin dumps\cert.bin
adb shell "cp /data/mediadrm/IDM1013/ay64.dat /sdcard/ay64.dat && chmod 644 /sdcard/ay64.dat"
adb pull /sdcard/ay64.dat dumps\ay64.dat
```

> ⚠️ **Do not delete** `cert.bin` — if deleted, device provisioning is lost and a new provisioning cycle will be required.

### 2.2. Frida Server

```powershell
adb push frida-server-16.x-android-arm /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c 'nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'"
```

### 2.3. PC Setup

```powershell
pip install -r requirements.txt
```

Requires `frida`, `pycryptodome`, `pywidevine>=1.9.0`, `pymp4`, `construct`, and `protobuf`.
`pywidevine 1.9.0` includes `license_protocol_pb2` with `ClientIdentification`, `SignedDrmCertificate`, `DrmCertificate`, and `Device.loads()/dumps()` for WVD v2.

---

## 3. Capturing the Key in RAM

### 3.1. `scripts\trigger_media.js` — The Headless Trigger

Frida RPC script that drives MediaDrm within the host process (`android.process.media`):

- `step1()` → Opens `MediaDrm(Widevine)` and calls `openSession`. If it fails, retrieves `getProvisionRequest()` and transmits it to the PC (base64url-encoded signed request).
- `step2(respB64)` → Invokes `provideProvisionResponse([...])` with the server response and returns to `openSession`.
- `step3(psshHex)` → Once the session is open, executes `getKeyRequest(sid, init_data, 'video/mp4', 1, opts)`.

Completely device-agnostic; accepts any arbitrary PSSH init data.

### 3.2. `scripts\hook_key_dumper.js` — The Core Hook

The heart of the extractor. It performs three key operations:

1. **Self-arms upon library loading**: Intercepts `android_dlopen_ext`, waiting for lazy loading of `libwvdrmengine.so`. Prior to this, `Module.findBaseAddress` returns `null`.
2. **Hooks `_oecc19`** at `base + 0x538cd`:
   - `onEnter`: Saves pointer to the 128-byte encrypted RSA blob (`this.cipher = args[1]`).
   - `onLeave`: Executes a **512 KB window scan** with `Memory.scanSync` searching for the RSA DER header:
     `02 03 01 00 01 02 82 01` (INTEGER len=3 with **e=65537**; followed by `INTEGER len=257` for **n**).
   - **Fallback**: If not found in the window, scans all **rw-** pages in the process using the same pattern (the path that succeeded in practice).
3. Upon a match, sends a 0x1200-byte hexdump around the hit (`hit - 0x600 .. hit + 0x1200`) to the host via `send({type:'fallback_hits', hits:[...]})`.

### 3.3. `scripts\runner.py` — The Orchestrator

1. Resolves PID for `mediaserver` (and fallback hosts `android.process.media`, `com.lge.drmservice`, `drmserver`) via `adb shell ps` (PID changes on each restart).
2. Injects `hook_key_dumper.js` and awaits the "armed" event.
3. Injects `trigger_media.js` into the host process.
4. Invokes `step1()` **twice**: first to force `dlopen` of the DRM engine (arming hooks); second to capture target memory.
5. Invokes `step3(PSSH)` 4 times across sample headers.
6. Saves captured memory events to `dumps\dump_events.json`.

### 3.4. Execution

```powershell
python scripts\runner.py
```

Expected output in `dumps\dump_events.json`:

```json
{ "type": "fallback_hits", "hits": [ { "addr": "abcdef01", "full": "<4608 bytes hex>" } ] }
```

> 💡 If the key is not dumped on the first run: **it is a race condition**. Kill `mediaserver`
> (`adb shell "su -c 'kill -9 <pid>'"`), force a media scan broadcast to restart it, and re-run.
> This pipeline is designed to be idempotent.

---

## 4. Decoding the Key — `scripts\extract_key.py`

From the memory blob `fallback_hits[0].hits[0].full` (base = `address - 0x600`), searches and extracts a clean `RSAPrivateKey` SEQUENCE:

- Identifies `30 82 …` whose length encompasses `0203010001` (e) and `02820101`/`028181` (n).
- Imports via PyCryptodome's `RSA.import_key` and verifies consistency.
- Exports `dumps\device_private_key.der` + `dumps\device_private_key.pem` (PKCS#1) + `_pkcs8.pem`.

```powershell
python scripts\extract_key.py
```

Additionally, `scripts\parse_keys.py` conducts independent integer validation (`n, e, d, p, q, dP, dQ, qInv`) ensuring `p * q == n`.

---

## 5. Building the .wvd — `scripts\build_wvd.py`

TWO components are required:
- The extracted RSA private key (`dumps\device_private_key.der`).
- The **ClientIdentification** (device certificate chain from `cert.bin`).

Pipeline in `build_wvd.py`:

1. **Loads DER private key** and enforces `n=2048`, `e=65537`.
2. **Parses legacy `cert.bin`** hierarchically:
   - `top[1]`: 2759 → `top[1][3]`: 2752 → **inner[1]** = 1434 bytes of `SignedDeviceCertificate` (maps 1-to-1 to modern `SignedDrmCertificate`).
   - `inner[2]` (1312 B) is the encrypted private key blob — **ignored**, as the key is supplied from RAM.
3. **Constructs modern `ClientIdentification`**:
   ```python
   ClientIdentification(type=TokenType.DRM_DEVICE_CERTIFICATE,
                        token=<signed_device_chain 1434B verbatim>)
   ```
4. Verifies exact serialization roundtrip required by `pywidevine`.
5. Packages via `Device(type_=ANDROID, security_level=3, private_key=der, client_id=cid)` and exports via `.dumps()`.

```powershell
python scripts\build_wvd.py         # → device.wvd
```

---

## 6. Verification — `scripts\verify_device.py`

1. Loads `device.wvd` via `pywidevine.cdm.Cdm.from_device`.
2. Constructs a Widevine v0 PSSH with test key IDs.
3. Invokes `cdm.get_license_challenge(sid, pssh, 'STREAMING')` → generates ~2037 bytes.
4. Parses `SignedMessage` → `LicenseRequest` (validating device certificate serial and system ID).
5. **Verifies PSS-SHA1 signature of `SignedMessage` against the extracted key** — confirming that the private key successfully signs challenges.

```powershell
python scripts\verify_device.py
```

---

## 7. Troubleshooting / Common Pitfalls

| Issue | Cause | Solution |
|---|---|---|
| `fallback_hits` does not appear | Memory race condition | Terminate `mediaserver` via `kill -9` and re-run runner |
| Hook does not arm | DRM library is lazily loaded | The `android_dlopen_ext` hook handles this; do not replace with a static base address |
| `cert.bin` missing | Provisioning wiped | Re-run provisioning rollback: `provideProvisionResponse()` (`step2`) — DO NOT delete files |
| `Device.load` fails | Protobuf byte mismatch | Ensure `build_wvd.py` preserves verbatim token bytes |

---

## Credits & Acknowledgments

- **Architecture, Reverse Engineering & Automation:** Researched and developed with **Gemini 3.8 Flash** & **OpenCode (GLM-5.3-Flash)**.
- **RE Tooling:** Ghidra for disassembly of `libwvdrmengine.so` and obfuscated RVA mapping.
- **Dynamic Instrumentation:** Frida for `Interceptor.attach` + `Memory.scanSync`.
- **Cryptography & Packaging:** `pywidevine` (v1.9.0) and `pycryptodome` for WVD v2 serialization and PSS-SHA1 signature validation.

## Disclaimer

Strictly for educational and research purposes. Do not redistribute extracted device keys (`.gitignore` excludes `dumps/`, `*.der`, `*.wvd`). Keys are unique to the physical hardware and logged by licensing CDMs.
