'use strict';

var DEFAULT_PSSH = '000000327073736800000000edef8ba979d64acea3c827dcd51d21ed0000001212103b1e80494397fef03ea7667cf1fec82d';
var WIDEVINE_UUID = 'edef8ba9-79d6-4ace-a3c8-27dcd51d21ed';

function log(m) { send({ tag: 'trigger', msg: '' + m }); }

var md = null, sid = null;

function xorLoop() {}

rpc.exports = {
    // fase 1: hell provisioning request al PC
    step1: function () {
        return Java.perform(function () {
            try {
                var MediaDrm = Java.use('android.media.MediaDrm');
                md = MediaDrm.$new(Java.use('java.util.UUID').fromString(WIDEVINE_UUID));
                log('MediaDrm OK');
                try { sid = md.openSession(); log('openSession OK len=' + sid.length); }
                catch (e) {
                    log('openSession -> ' + e.toString().split('\n')[0]);
                    var pr = md.getProvisionRequest();
                    // getData() ya viene como texto base64url (signedRequest)
                    var JString = Java.use('java.lang.String');
                    var reqStr = JString.$new(pr.getData(), 'UTF-8').toString();
                    log('prov req (texto) len=' + reqStr.length);
                    send({ tag: 'provreq', url: pr.getDefaultUrl(), req: reqStr });
                    return 'provreq-sent';
                }
                return 'session-open';
            } catch (err) {
                log('FATAL step1 ' + err);
                return 'err';
            }
        });
    },

    // fase 2: el PC manda la respuesta base64; seguimos con openSession/getKeyRequest
    step2: function (respB64, respUrlText) {
        return Java.perform(function () {
            try {
                var JString = Java.use('java.lang.String');
                var textBytes = JString.$new(respB64).getBytes('UTF-8');
                log('prov resp json len=' + textBytes.length + ', provideProvisionResponse...');

                var attempts = [
                    ['providerResponse(json)', function () { md.provideProvisionResponse(textBytes); }]
                ];
                var last = null;
                for (var i = 0; i < attempts.length; i++) {
                    try {
                        attempts[i][1]();
                        log('EXITO: ' + attempts[i][0]);
                        break;
                    } catch (ae) {
                        last = attempts[i][0] + ' -> ' + ae.toString().split('\n')[0];
                        log('fallo: ' + last);
                    }
                }
                if (last != null && i == attempts.length) throw new Error(last);

                sid = md.openSession();
                log('openSession OK len=' + sid.length);
                return 'provisioned';
            } catch (err) {
                log('FATAL step2 ' + err);
                md = null;
                return 'err ' + err.toString().split('\n')[0];
            }
        });
    },

    // fase 3: getKeyRequest con PSSH
    step3: function (psshHex) {
        return Java.perform(function () {
            try {
                if (!md || !sid) return 'no-session';
                var data = [];
                for (var k = 0; k < psshHex.length; k += 2) data.push(parseInt(psshHex.substr(k, 2), 16));
                var init = Java.array('byte', data);
                var opt = Java.use('java.util.HashMap').$new();
                var req = md.getKeyRequest(sid, init, 'video/mp4', 1, opt);
                log('getKeyRequest OK len=' + req.length);
                var out = '';
                for (var j = 0; j < req.length; j++) {
                    var v = req[j] & 0xff;
                    out += (v < 16 ? '0' : '') + v.toString(16);
                }
                send({ tag: 'keyrequest', h: out });
                return 'ok';
            } catch (err) {
                log('FATAL step3 ' + err);
                return 'err';
            }
        });
    }
};
