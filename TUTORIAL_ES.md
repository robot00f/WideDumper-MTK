# Tutorial: Extraer la clave Widevine L3 de un dispositivo Android (Frida + Ghidra + pywidevine)

> ⚠️ **Uso 100% educativo/investigación.** Extraer claves Widevine viola los ToS de Google y de
> cualquier proveedor de contenido DRM. Úsalo SOLO en TU dispositivo.

> **Objetivo final:** producir un `device.wvd` (pywidevine) con la clave privada RSA del
> *provisioning* del dispositivo, obtenida directamente del proceso `mediaserver` en RAM.

 Hardware probado: CDM Widevine **L3_0** en un MediaTek MT6582 con Android 5.0.2.
 Los RVAs de `libwvdrmengine.so` cambian por build; si tu lib es otra, recalcúlalos en Ghidra.

---

## 1. ¿Por qué hay que hookear en RAM?

Los archivos en disco **no** sirven directamente:

| Archivo en `/data/mediadrm/IDM1013/` | Contenido | Problema |
|---|---|---|
| `L3/cert.bin` | Cadena de certificados (`DeviceCertificate` + intermediario) + blob cifrado de 1312 B | La clave privada está cifrada con una clave de **`ay64.dat`** |
| `ay64.dat` | Clave que cifra el blob | Protegida por el hardware MTK (TEE); no descifrable en el proceso |

**La única ventana** en la que la clave RSA existe en **texto claro en memoria** es en el
`onLeave` de la función que hace `LoadDeviceRSAKey` en `libwvdrmengine.so`; dura microsegundos.

### Mapper interno de `libwvdrmengine.so` (referencia para reproducir el análisis)

| RVA (offset) | Función ofuscada | Papel |
|---|---|---|
| `+0x538cd` | **`_oecc19`** | Carga y descifra la clave privada RSA (`LoadDeviceRSAKey`) → **punto de gancho ganador** |
| `+0x53904` | `_oecc36` | Firma el manifesto con la clave |
| `+0x58cd4` | `_lcc20` | Dispatcher hacia la VM `ulns/nvpds` (AES-128 con tablas LCG descifradas por llamada) |
| `+0x5cfdc`/`+0x5db0c` | `nvpds` / `ulns` | Intérprete de bytecode ofuscado (descartado; el scan directo funcionó mejor) |

> El enfoque anti-ofuscación de la VM se abandona porque un *scan* simple del patrón DER
> en las páginas **rw-** alrededor de `_oecc19.onLeave` basta para ver la clave.

---

## 2. Preparar el entorno

### 2.1. Clonar los artefactos del dispositivo

```powershell
adb shell "su -c 'cp /data/mediadrm/IDM1013/L3/cert.bin /sdcard/cert.bin && chmod 644 /sdcard/cert.bin'"
adb pull /sdcard/cert.bin dumps\cert.bin
adb shell "cp /data/mediadrm/IDM1013/ay64.dat /sdcard/ay64.dat && chmod 644 /sdcard/ay64.dat"
adb pull /sdcard/ay64.dat dumps\ay64.dat
```

> ⚠️ **No borrar** `cert.bin` — si lo borras, la provisión vigente se pierde y necesitas una nueva.

### 2.2. Frida-server

```powershell
adb push frida-server-16.x-android-arm /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c 'nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'"
```

### 2.3. PC

```
pip install -r requirements.txt
```

Requiere `frida`, `pycryptodome`, `pywidevine>=1.9.0`, `pymp4`, `construct` y `protobuf`.
`pywidevine 1.9.0` ya trae `license_protocol_pb2` con `ClientIdentification`,
`SignedDrmCertificate`, `DrmCertificate`, y `Device.loads()/dumps()` para WVD v2.

---

## 3. Capturar la clave en RAM

### 3.1. `scripts\trigger_media.js` — el disparador

RPC de Frida que moviliza MediaDrm en el proceso host (`android.process.media`):

- `step1()` → abre `MediaDrm`(Widevine) y llama `openSession`. Si falla, saca
`getProvisionRequest()` y lo manda al PC (base64url del *signed request*).
- `step2(respB64)` → llama `provideProvisionResponse([...])` con la respuesta del servidor y vuelve a `openSession`.
- `step3(psshHex)` → ya con la sesión abierta, hace `getKeyRequest(sid, init_data, 'video/mp4', 1, opts)`.

No hardcodea nada del dispositivo; acepta el PSSH arbitrario que le pases.

### 3.2. `scripts\hook_key_dumper.js` — el gancho ganador

El corazón del extractor. Hace tres cosas:

1. **Se auto-arma cuando se carga la lib**: intercepta `android_dlopen_ext`, se queda esperando
   hasta que se dlopen de `libwvdrmengine.so` (lazy). Antes de eso la `findBaseAddress` vuelve `null`.
2. **Hook en `_oecc19`** frontal (`base + 0x538cd`):
   - `onEnter`: guarda el puntero al blob cifrado de 128 bytes RSA sin descifrar (`this.cipher = args[1]`).
   - `onLeave`: hace un **scan de ventana de 512 KB** circundante con `Memory.scanSync` buscando el
     patrón DER de clave RSA: `02 03 01 00 01 02 82 01` (INTEGER(len=3) con **e=65537**;
     a partir de ahí un `INTEGER(len=257)` = **n**).
   - **Fallback**: si en la ventana no aparece, recorre todas las páginas **rw-** del proceso y
     busca el mismo patrón (es el camino que funcionó en la práctica).
3. En cuanto ve el hit, envía un hexdump de 0x1200 bytes alrededor (`hit - 0x600 .. hit + 0x1200`)
   al PC vía `send({type:'fallback_hits', hits:[...]})`.

### 3.3. `scripts\runner.py` — el orquestador

1. Resuelve el PID del `mediaserver` (y de hosts altern hormonal `android.process.media`,
   `com.lge.drmservice`, `drmserver`) con `adb shell ps` (el PID cambia con cada reinicio).
2. Carga `hook_key_dumper.js` y espera al evento "armed".
3. Carga `trigger_media.js` en el proceso host.
4. Llama `step1()` **dos veces**: la primera para forzar el `dlopen` de la lib (dispara el gancho); la segunda para capturar de verdad.
5. Llama `step3(PSSH)` 4 veces.
6. Guarda todo en `dumps\dump_events.json`.

### 3.4. Correr

```powershell
python scripts\runner.py
```

Lo que buscas en la salida:

```json
{ "type": "fallback_hits", "hits": [ { "addr": "abcdef01", "full": "<4608 bytes hex>" } ] }
```

> 💡 Si no sale la clave al primer intento: **es una carrera**. Mata `mediaserver`
> (`adb shell "su -c 'kill -9 <pid>'"`), forzá un *media-scan* para volver a levantarlo, y re-corre.
> Este pipeline se diseñó para ser idempotente.

---

## 4. Decodificar la clave — `scripts\extract_key.py`

A partir del blob `fallback_hits[0].hits[0].full` (base = `address - 0x600`) busca y recorta un
`RSAPrivateKey` SEQUENCE limpio:

- Encuentra un `30 82 …` cuyo tamaño abarque `0203010001` (e) también vale `02820101`/`028181` (n).
- Hace `RSA.import_key` de pycryptodome y verifica consistencia.
- Escribe `dumps\device_private_key.der` + `dumps\device_private_key.pem` (PKCS#1) + `_pkcs8.pem`.

```powershell
python scripts\extract_key.py
```

Además `scripts\parse_keys.py` hace un parseo independiente de los INTEGERs
(`n, e, d, p, q, dP, dQ, qInv`) con verificación `p * q == n`.

---

## 5. Construir el .wvd — `scripts\build_wvd.py`

Se necesitan DOS piezas:
- la clave RSA ya extraída (`dumps\device_private_key.der`)
- el **ClientIdentification** (your cert chain from `cert.bin`)

Al hairdo de `build_wvd.py`:

1. **Carga la clave DER** y exige `n=2048`, `e=65537`.
2. **Explores el legacy `cert.bin`** con un parser mínimo de protobuf (por niveles):
   - `top[1]`: 2759 → `top[1][3]`: 2752 → **inner[1]** = 1434 B de `SignedDeviceCertificate`
     (map 1-1 a moderno `SignedDrmCertificate`, campo 3 `signer` es un mensaje y no bytes moderno).
   - Y el **inner[2]** (1312 B) es la clave privada cifrada — **NO se usa**; aquí la clave la sacamos de la memoria.
3. **Arma el `ClientIdentification`** moderno:
   ```python
   ClientIdentification(type=TokenType.DRM_DEVICE_CERTIFICATE,
                        token=<signed_device_chain 1434B verbatim>)
   ```
   (el campo `client_id` de "bytes" NO existe en la proto moderna; solo `type` + `token`.)
4. Verifica la igualdad de re-serialización exacta que exige pywidevine.
5. Empaqueta con `Device(type_=ANDROID, security_level=3, private_key=der, client_id=cid)` y llama a `.dumps()`.

```powershell
python scripts\build_wvd.py         # → device.wvd
```

---

## 6. Verificación — `scripts\verify_device.py`

1. Carga `device.wvd` con `pywidevine.cdm.Cdm.from_device`.
2. Construye un PSSH Widevine v0 con una `key_id` de prueba (tomada de tu material de referencia).
3. Llama a `cdm.get_license_challenge(sid, pssh, 'STREAMING')` → produce ~2037 bytes.
4. Parsea el `SignedMessage` → `LicenseRequest` (y valida que dentro venga el `DeviceCertificate`
   con el serial y el system_id que corresponden al dispositivo).
5. **Verifica la firma PSS-SHA1 del `SignedMessage` contra la clave extraída** — el escenario real
   de uso es que tu clave privada queda integrada en el flujo de firma del challenge.
6. Opcionalmente intenta verificar la firma del `DeviceCertificate` con la clave pública del
   intermediario (el padding legacy no siempre es std-PKCS#1; es solo informativa).

```powershell
python scripts\verify_device.py
```

> 💡 Prueba end-to-end real: manda el challenge a un license server con el producto que ya
> Armamos (no se incluye aquí; sider etc.)

---

## 7. Pipes / troubleshooting

| Problema | Causa | Solución |
|---|---|---|
| `fallback_hits` no aparece | carreras de memoria | reinicia `mediaserver` con `kill -9`; re-corre runner |
| hook no se arma | la lib siempre dlopen lazy | el hook de `android_dlopen_ext` lo maneja; no lo sustituyas por fixed-base |
| `cert.bin` no presente | mediaserver borró la provisión | re-corre la rollback: `provideProvisionResponse()` (step2) — NO borrar archivos |
| el PSSH que usaste cambia | usa cualquier de tus key_id de prueba | `step3` acepta cualquier hex de init_data |
| `Device.load` falla | pywidevine exige bytes.ser-de-serial-exactos en protobuf | `build_wvd.py` deja el `client_id` sin rehidratar → el assert lo detecta |

---

## Créditos y Agradecimientos

- **Arquitectura, Ingeniería Inversa y Automatización:** Investigado y desarrollado con **Gemini 3.8 Flash** y **OpenCode (GLM-5.3-Flash)**.
- **Herramientas de RE:** Ghidra para desensamblar `libwvdrmengine.so` y hallar las RVAs ofuscadas.
- **Instrumentación dinámica:** Frida para el hook con `Interceptor.attach` + `Memory.scanSync`.
- **Criptografía y empaquetado:** `pywidevine` (v1.9.0) y `pycryptodome` para la serialización de WVD v2 y validación de firmas PSS-SHA1.

## Disclaimer

Uso educativo/investigación solamente. **No** redistribuyas claves extraídas reales
(¡por eso el `.gitignore` excluye `dumps/`, `*.der`, `*.wvd`!). Las claves son
specificas a dispositivo y quedan registradas en CDM-side.
