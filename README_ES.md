# WideDumper-MTK (Frida + Ghidra + pywidevine)

[English Version](README.md) | **Español**

> ⚠️ **Uso 100% educativo y de investigación.** La extracción de claves Widevine está sujeta a los términos de servicio correspondientes y regulaciones aplicables. Este proyecto fue desarrollado para fines de auditoría técnica, diagnóstico y comprensión de la arquitectura de un CDM de nivel L3 en hardware propio.

Tutorial técnico detallado paso a paso en **[TUTORIAL_ES.md](TUTORIAL_ES.md)** (o en inglés en **[TUTORIAL.md](TUTORIAL.md)**).

## Descripción

Extrae la **clave privada RSA (2048-bit)** de aprovisionamiento de un dispositivo Android con Widevine L3 (obtenida directamente desde la memoria RAM del proceso `mediaserver`, no desde disco) y la empaqueta junto con su cadena de certificados en un archivo `.wvd` compatible con [`pywidevine`](https://github.com/DevL1dee/pywidevine).

## Estructura del Repositorio

```
github_release/
├── README.md                  # Documentación principal en inglés
├── README_ES.md               # Documentación en español
├── TUTORIAL.md                # Guía técnica paso a paso en inglés
├── TUTORIAL_ES.md             # Guía técnica paso a paso en español
├── requirements.txt           # Dependencias Python
├── .gitignore                 # Exclusión de volcados y claves del dispositivo
├── LICENSE                    # Licencia MIT
├── dumps/                     # Directorio local para artefactos (ignorado en Git)
└── scripts/
    ├── trigger_media.js       # Disparador headless MediaDrm por RPC (Frida)
    ├── hook_key_dumper.js     # Hook en _oecc19 + window scan DER en RAM
    ├── runner.py              # Orquestador (resuelve PIDs, inyecta hooks, guarda dump_events.json)
    ├── extract_key.py         # Recorta y valida la estructura RSAPrivateKey en memoria
    ├── parse_keys.py          # Conversor de enteros y verificación matemática p·q == n
    ├── build_wvd.py           # Ensambla device.wvd (pywidevine v2, ANDROID, L3)
    └── verify_device.py       # Genera challenge PSS-SHA1 y verifica la firma criptográfica
```

## Requisitos

- Dispositivo Android con **acceso root** y soporte Widevine L3 (probado en MediaTek MT6582 / Android 5.0.2).
- PC con Windows / Linux / macOS y Python 3.10+.
- `adb` en el PATH del sistema (o variable de entorno `ADB_PATH` apuntando al binario).
- `frida-server` (versión compatible con tu dispositivo, ej. 16.x) ejecutándose en el móvil.
- `Ghidra` (opcional, para recalcular el RVA de `_oecc19` si se utiliza una compilación distinta de `libwvdrmengine.so`).

## Instalación

```powershell
pip install -r requirements.txt
```

## Uso Rápido

```powershell
# 1. Obtener cert.bin del dispositivo (NO eliminar del móvil)
adb shell "su -c 'cp /data/mediadrm/IDM1013/L3/cert.bin /sdcard/cert.bin && chmod 644 /sdcard/cert.bin'"
adb pull /sdcard/cert.bin dumps\cert.bin

# 2. Capturar la clave privada en memoria RAM
python scripts\runner.py                 # → genera dumps\dump_events.json

# 3. Extraer y validar la clave RSA en DER / PEM
python scripts\extract_key.py            # → genera dumps\device_private_key.{der,pem}

# 4. Construir el archivo de dispositivo pywidevine (.wvd)
python scripts\build_wvd.py              # → genera device.wvd

# 5. Verificación criptográfica (PSS-SHA1 challenge)
python scripts\verify_device.py
```

## Artefactos Generados

| Archivo | Contenido / Función |
|---|---|
| `dumps\dump_events.json` | Eventos capturados por Frida con el bloque de memoria |
| `dumps\device_private_key.der` / `.pem` / `_pkcs8.pem` | Clave privada RSA en 3 formatos estándar |
| `dumps\client_id_blob.bin` | Protobuf `ClientIdentification` del dispositivo |
| `device.wvd` | Archivo CDM compatible con `pywidevine.device.Device.load()` |

## Consideraciones Técnicas

- **Condición de carrera:** La clave privada RSA reside en memoria descifrada dentro de `libwvdrmengine.so` únicamente durante microsegundos durante la carga de sesión. Si la búsqueda no detecta el bloque en el primer intento, reinicia `mediaserver` y vuelve a ejecutar `runner.py`.
- **Adaptación a otros SoCs / ROMs:** El RVA del hook (`_oecc19` en `+0x538cd`) corresponde a la compilación analizada para MT6582. Para otros dispositivos, inspecciona `libwvdrmengine.so` en Ghidra identificando la rutina de inicialización de aprovisionamiento RSA.

## Créditos y Agradecimientos

- **Arquitectura, Ingeniería Inversa y Automatización:** Investigado y desarrollado con **Gemini 3.8 Flash** y **OpenCode (GLM-5.3-Flash)**.
- **Flujo y Fundamentos:** Adaptado del pipeline de ingeniería inversa con Frida + Ghidra sobre Android Widevine L3 (LG G3 Stylus D690 / MTK MT6582).

## Licencia

Distribuido bajo licencia MIT. Consulta [LICENSE](LICENSE) para más detalles.
