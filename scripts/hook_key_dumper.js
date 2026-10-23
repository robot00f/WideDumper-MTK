'use strict';

var MOD = 'libwvdrmengine.so';
var base = null;
var PAT = [0, 2, 0x03, 1, 0, 1, 2, 0x82, 1, 0];

function addrHex(p) { var v = ptr(p).toString(16); return ('00000000' + v).slice(-8); }
function hx(ptrX, len) {
  if (ptrX.isNull() || len <= 0) return '';
  try {
    var u8 = new Uint8Array(Memory.readByteArray(ptrX, len));
    var h = '';
    for (var i = 0; i < u8.length; i++) h += ('0' + u8[i].toString(16)).slice(-2);
    return h;
  } catch (e) { return 'ERR' + e; }
}
function findSeq(buf, pat) {
  for (var i = 0; i + pat.length <= buf.length; i++) {
    if (buf[i] !== pat[0]) continue;
    var ok = true;
    for (var j = 1; j < pat.length; j++) { if (buf[i + j] !== pat[j]) { ok = false; break; } }
    if (ok) return i;
  }
  return -1;
}

function windowScan(focus, before, span, label, sentOnce) {
  try {
    var lo = focus.sub(before);
    var buf = new Uint8Array(Memory.readByteArray(lo, span));
    var i = findSeq(buf, PAT);
    if (i >= 0) {
      var hita = lo.add(i);
      var k = 'w' + label + addrHex(hita);
      if (!sentOnce[k]) {
        sentOnce[k] = 1;
        send({ type: 'key_hit', via: label, focus: addrHex(focus), hitAddr: addrHex(hita), full: hx(hita.sub(0x600), 0x1200) });
        return true;
      }
    }
  } catch (e) {}\n  return false;
}

function fallbackScan(sentOnce) {
  var hits = [];
  try {
    var ranges = Process.enumerateRanges('rw-');
    for (var i2 = 0; i2 < ranges.length && hits.length < 8; i2++) {
      var r = ranges[i2];
      if (r.size > 40 * 1024 * 1024) continue;
      try {
        var m = Memory.scanSync(r.base, r.size, '02 03 01 00 01 02 82 01');
        for (var j2 = 0; j2 < m.length; j2++) {
          var a = m[j2].address;
          var k = 'f' + addrHex(a);
          if (!sentOnce[k]) {
            sentOnce[k] = 1;
            hits.push({ addr: addrHex(a), full: hx(a.sub(0x600), 0x1200) });
          }
          if (hits.length >= 8) break;
        }
      } catch (e) {}\n    }
  } catch (e) {}\n  if (hits.length) send({ type: 'fallback_hits', hits: hits });
}

function ensureArmed() {
  if (base) return true;
  base = Module.findBaseAddress(MOD);
  if (!base || base.isNull()) return false;
  var sentOnce = {};

  Interceptor.attach(base.add(0x538cd), { // _oecc19 LoadDeviceRSAKey
    onEnter: function (args) {
      this.cipher = args[1];
      send({ type: 'oecc19_enter', a0: addrHex(args[0]), a1: addrHex(args[1]), a2: addrHex(args[2]), beforeFull: hx(args[1], 1312) });
    },
    onLeave: function () {
      send({ type: 'stage', dbg: 'o19.leave' });
      var done = windowScan(this.cipher, 0x40000, 0x80000, 'o19', sentOnce);
      if (!done) fallbackScan(sentOnce);
    }
  });
  send({ type: 'info', msg: 'armed' });
  return true;
}

var pollTimer = setInterval(function () { ensureArmed(); }, 250);
var dl = Module.findExportByName(null, 'android_dlopen_ext');
if (dl !== null) {
  Interceptor.attach(dl, {
    onEnter: function (args) {
      try {
        if (args[0] && !args[0].isNull()) {
          var p = Memory.readUtf8String(args[0]);
          this.isEngine = p && p.indexOf('libwvdrmengine') >= 0;
        }
      } catch (e) {}\n    },
    onLeave: function () { if (this.isEngine) ensureArmed(); }
  });
}
rpc.exports = { stop: function () { clearInterval(pollTimer); return 'ok'; } };
