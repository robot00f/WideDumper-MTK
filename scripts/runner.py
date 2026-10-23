import frida, subprocess, time, json, os
ADB = os.environ.get("ADB_PATH", "adb")

def fprint(*a): print(*a, flush=True)

def fresh_pid(name):
    outp = subprocess.run([ADB, "shell", "ps"], capture_output=True, text=True).stdout
    for line in outp.splitlines():
        cols = line.split()
        if len(cols) < 9: continue
        last = cols[-1]
        if last == name or last.endswith("/" + name):
            return int(cols[1])
    return None

HOOK = open(os.path.join(os.path.dirname(__file__), "hook_key_dumper.js"), encoding="utf-8").read()

events = []
def on_msg(src):
    def h(m, d):
        pl = m.get('payload')
        if m.get('type') == 'send' and isinstance(pl, dict):
            events.append(dict(pl, src=src))
            t = pl.get('type')
            if t == 'dispatch':
                fprint('DISPATCH fn50rva={} fn90rva={} r1rva={}'.format(pl.get('fn50rva'), pl.get('fn90rva'), pl.get('r1')))
            elif t in ('dispatch_hit', 'oecc36_enter'):
                fprint(pl)
    return h

dev = frida.get_usb_device()
s = None
for attempt in range(6):
    pid = fresh_pid("mediaserver")
    fprint("attempt", attempt, "mediaserver pid", pid)
    if not pid:
        time.sleep(1.5); continue
    try:
        s = dev.attach(pid)
        sc = s.create_script(HOOK)
        sc.on('message', on_msg('mediaserver'))
        sc.load()
        armed = False
        for _ in range(40):
            if any(e.get('type') == 'info' for e in events):
                armed = True
                break
            time.sleep(0.25)
        if not armed:
            fprint("warn: hooks not armed in time")
        break
    except Exception as e:
        fprint("attach failed", type(e).__name__, e)
        time.sleep(1.5)
if s is None:
    raise SystemExit("mediaserver attach failed")

TRIGGER_JS = open(os.path.join(os.path.dirname(__file__), "trigger_media.js"), encoding="utf-8").read()
sc2 = None
for attempt in range(6):
    outp = subprocess.run([ADB, "shell", "ps"], capture_output=True, text=True).stdout
    pid2 = None
    for name in ("android.process.media", "com.lge.drmservice", "drmserver"):
        pid2 = None
        for line in outp.splitlines():
            cols = line.split()
            if len(cols) < 9: continue
            if cols[-1] == name:
                pid2 = int(cols[1]); break
        if pid2:
            try:
                s2 = dev.attach(pid2)
                sc2 = s2.create_script(TRIGGER_JS)
                sc2.on('message', on_msg('trigger'))
                sc2.load()
                break
            except Exception as e:
                fprint("trigger attach fail", name, e)
    if sc2: break
    time.sleep(1.5)

fprint("trigger host ready")
PSSH_HEX = '000000327073736800000000edef8ba979d64acea3c827dcd51d21ed0000001212103b1e80494397fef03ea7667cf1fec82d'
exp2 = getattr(sc2, "exports_sync", None) or sc2.exports
try:
    exp2.step1()          # throwaway: loads engine lib -> dlopen hook arms
    time.sleep(3)
    exp2.step1()          # real captured session
    time.sleep(2)
    for i in range(4):
        exp2.step3(PSSH_HEX)
        time.sleep(0.5)
except Exception as e:
    fprint("trigger err", e)
time.sleep(2)

os.makedirs(os.path.join(os.path.dirname(__file__), "..", "dumps"), exist_ok=True)
with open(os.path.join(os.path.dirname(__file__), "..", "dumps", "dump_events.json"), "w") as f:
    json.dump(events, f)
fprint("saved events:", len(events))
