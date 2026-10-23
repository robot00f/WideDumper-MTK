# WideDumper-MTK (Frida + Ghidra + pywidevine)

**English** | [Versión en español](README_ES.md)

> ⚠️ **Strictly for Educational and Research Purposes.** Extracting DRM keys is subject to service terms and applicable local regulations. This project was developed for technical diagnostic research, architecture auditing, and understanding L3 CDM implementations on personal test hardware.

Complete step-by-step technical guide available in **[TUTORIAL.md](TUTORIAL.md)** (or in Spanish in **[TUTORIAL_ES.md](TUTORIAL_ES.md)**).

## Overview

Extracts the **2048-bit RSA private provisioning key** of an Android device running Widevine L3 directly from the `mediaserver` process in **RAM** (bypassing disk encryption) and packages it alongside its certificate chain into a functional [pywidevine](https://github.com/DevL1dee/pywidevine) `.wvd` device file.

## Repository Structure

```
github_release/
├── README.md                  # Main project documentation (English)
├── README_ES.md               # Project documentation (Spanish)
├── TUTORIAL.md                # In-depth technical walkthrough (English)
├── TUTORIAL_ES.md             # In-depth technical walkthrough (Spanish)
├── requirements.txt           # Python dependencies
├── .gitignore                 # Prevents leaking device keys or dumps
├── LICENSE                    # MIT License
├── dumps/                     # Local folder for extracted artifacts (gitignored)
└── scripts/
    ├── trigger_media.js       # Headless MediaDrm RPC trigger via Frida
    ├── hook_key_dumper.js     # _oecc19 hook + memory window DER scanner
    ├── runner.py              # Orchestrator (PID resolution, hook injection, event logger)
    ├── extract_key.py         # Carves and validates RSAPrivateKey structures from memory
    ├── parse_keys.py          # Big integer parsing and mathematical validation (p·q == n)
    ├── build_wvd.py           # Assembles device.wvd (pywidevine v2, ANDROID, L3)
    └── verify_device.py       # PSS-SHA1 offline license challenge verification
```

## Requirements

- **Rooted** Android device with Widevine L3 support (tested on MediaTek MT6582 / Android 5.0.2).
- Host machine (Windows / Linux / macOS) with Python 3.10+.
- `adb` available in system PATH (or set via `ADB_PATH` environment variable).
- `frida-server` (compatible with device architecture, e.g., 16.x) running on the target device.
- `Ghidra` (optional, for recalculating `_oecc19` RVA on different builds of `libwvdrmengine.so`).

## Installation

```powershell
pip install -r requirements.txt
```

## Quick Start

```powershell
# 1. Pull cert.bin from device (DO NOT delete from phone)
adb shell "su -c 'cp /data/mediadrm/IDM1013/L3/cert.bin /sdcard/cert.bin && chmod 644 /sdcard/cert.bin'"
adb pull /sdcard/cert.bin dumps\cert.bin

# 2. Capture private key in RAM
python scripts\runner.py                 # → saves dumps\dump_events.json

# 3. Extract and validate RSA private key
python scripts\extract_key.py            # → creates dumps\device_private_key.{der,pem}

# 4. Build pywidevine device file (.wvd)
python scripts\build_wvd.py              # → generates device.wvd

# 5. Cryptographic verification (PSS-SHA1 challenge)
python scripts\verify_device.py
```

## Expected Outputs

| File | Content / Purpose |
|---|---|
| `dumps\dump_events.json` | Captured Frida events containing the target memory slice |
| `dumps\device_private_key.der` / `.pem` / `_pkcs8.pem` | RSA private key exported in 3 standard formats |
| `dumps\client_id_blob.bin` | Device `ClientIdentification` protobuf token |
| `device.wvd` | Pywidevine CDM device file ready for `Device.load()` |

## Technical Notes

- **Race Condition Handling:** The decrypted RSA key is present in memory within `libwvdrmengine.so` only for microseconds during session provisioning. If memory scanning does not register a hit on the first run, restart `mediaserver` and re-run `runner.py`.
- **Porting to Other Devices/ROMs:** The hook RVA (`_oecc19` at `+0x538cd`) is specific to the examined MT6582 build. For other devices, open `libwvdrmengine.so` in Ghidra and locate the provisioning decryption function that takes the encrypted key blob and produces plaintext RSA parameters.

## Credits & Acknowledgments

- **Architecture, Reverse Engineering & Automation:** Researched and developed with **Gemini 3.8 Flash** & **OpenCode (GLM-5.3-Flash)**.
- **Workflow & Foundations:** Adapted from the Frida + Ghidra reverse engineering pipeline for Android Widevine L3 (LG G3 Stylus D690 / MTK MT6582).

## License

Released under the [MIT License](LICENSE).
