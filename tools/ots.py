#!/usr/bin/env python3
"""Bitcoin-Zeitstempel (OpenTimestamps) für Release-Dateien: stamp, upgrade, verify.

Braucht nur `pip install opentimestamps` (die Kernbibliothek); der Kommandozeilenclient `ots` ist nicht nötig und
läuft unter Windows mit neueren Python-Versionen nicht (python-bitcoinlib findet OpenSSL nicht). Die Prüfung der
Bitcoin-Bestätigung geht hier über die öffentliche Blockstream-API; sie ersetzt nicht die Prüfung mit dem
Standardclient (`ots verify`) oder auf https://opentimestamps.org, ist aber unabhängig von diesem Repository.

    python tools/ots.py stamp SHA256SUMS            # erzeugt SHA256SUMS.ots (zunächst ausstehend)
    python tools/ots.py upgrade SHA256SUMS.ots      # holt die Bitcoin-Bestätigung (nach Stunden)
    python tools/ots.py verify SHA256SUMS SHA256SUMS.ots

Gesendet wird nur ein Hash (SHA-256 über die Datei, gemischt mit einem Zufallswert), nie der Dateiinhalt.
"""
import datetime
import hashlib
import json
import os
import sys
import urllib.request

from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import StreamDeserializationContext, StreamSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, make_merkle_tree

CALENDARS = [
    'https://a.pool.opentimestamps.org',
    'https://b.pool.opentimestamps.org',
    'https://a.pool.eternitywall.com',
    'https://ots.btc.catallaxy.com',
]
# Kalender, bei denen upgrade nachfragen darf (die Adresse steht in der .ots-Datei; unbekannte Adressen werden ignoriert)
WHITELIST = CALENDARS + [
    'https://alice.btc.calendar.opentimestamps.org',
    'https://bob.btc.calendar.opentimestamps.org',
    'https://finney.calendar.eternitywall.com',
    'https://btc.calendar.catallaxy.com',
]
EXPLORER = 'https://blockstream.info/api'


def walk(stamp):
    yield stamp
    for sub in stamp.ops.values():
        yield from walk(sub)


def load(path):
    with open(path, 'rb') as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def save(fts, path):
    with open(path, 'wb') as f:
        fts.serialize(StreamSerializationContext(f))


def is_complete(fts):
    return any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in fts.timestamp.all_attestations())


def stamp(path):
    out = path + '.ots'
    if os.path.exists(out):
        sys.exit('%s existiert schon, nichts überschrieben.' % out)
    with open(path, 'rb') as fd:
        fts = DetachedTimestampFile.from_fd(OpSHA256(), fd)
    root = fts.timestamp.ops.add(OpAppend(os.urandom(16))).ops.add(OpSHA256())
    tip = make_merkle_tree([root])
    ok = 0
    for url in CALENDARS:
        try:
            tip.merge(RemoteCalendar(url).submit(tip.msg, timeout=20))
            print('Kalender angenommen:', url)
            ok += 1
        except Exception as e:  # noqa: BLE001 - jeder Kalender darf einzeln ausfallen
            print('Kalender nicht erreichbar oder abgelehnt:', url, '(%s)' % type(e).__name__)
    if ok == 0:
        sys.exit('Kein Kalender hat den Hash angenommen, keine Datei geschrieben.')
    if ok < 2:
        print('Warnung: nur ein Kalender hat angenommen.')
    save(fts, out)
    print('Geschrieben: %s (%d von %d Kalendern). Bitcoin-Bestätigung folgt nach Stunden: upgrade.' % (out, ok, len(CALENDARS)))


def upgrade(path):
    fts = load(path)
    if is_complete(fts):
        print('Schon vollständig (Bitcoin-Bestätigung enthalten).')
        return
    changed = False
    for sub in list(walk(fts.timestamp)):
        for att in list(sub.attestations):
            if isinstance(att, PendingAttestation) and att.uri in WHITELIST:
                try:
                    sub.merge(RemoteCalendar(att.uri).get_timestamp(sub.msg, timeout=20))
                    changed = True
                except Exception as e:  # noqa: BLE001
                    print('Noch nicht bestätigt bei %s (%s)' % (att.uri, getattr(e, 'reason', type(e).__name__)))
    if changed and is_complete(fts):
        save(fts, path)
        print('Aktualisiert: Bitcoin-Bestätigung enthalten.')
    elif changed:
        save(fts, path)
        print('Aktualisiert, aber noch ohne Bitcoin-Bestätigung.')
    else:
        print('Keine Änderung: noch nicht in einem Bitcoin-Block bestätigt. Später erneut versuchen.')


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode()


def verify(path, ots):
    fts = load(ots)
    digest = hashlib.sha256(open(path, 'rb').read()).digest()
    if digest != fts.file_digest:
        sys.exit('FALSCH: Der Hash der Datei passt nicht zum Zeitstempel.')
    print('Dateihash passt zum Zeitstempel (SHA-256 %s).' % digest.hex())
    confirmed = False
    for msg, att in fts.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            print('Ausstehend bei Kalender:', att.uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            block_hash = fetch('%s/block-height/%d' % (EXPLORER, att.height)).strip()
            info = json.loads(fetch('%s/block/%s' % (EXPLORER, block_hash)))
            if bytes.fromhex(info['merkle_root'])[::-1] == msg:
                print('BESTÄTIGT: Bitcoin-Block %d (%s), Zeit %s UTC' % (
                    att.height, block_hash, datetime.datetime.fromtimestamp(info['timestamp'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')))
                confirmed = True
            else:
                print('FALSCH: Der Merkle-Root von Block %d passt nicht.' % att.height)
    if not confirmed:
        print('Noch keine Bitcoin-Bestätigung in der Datei (upgrade ausführen, wenn Stunden vergangen sind).')


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'stamp' and len(sys.argv) == 3:
        stamp(sys.argv[2])
    elif cmd == 'upgrade' and len(sys.argv) == 3:
        upgrade(sys.argv[2])
    elif cmd == 'verify' and len(sys.argv) == 4:
        verify(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
