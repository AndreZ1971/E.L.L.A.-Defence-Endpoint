#!/usr/bin/env python3
"""Schreibt SHA256SUMS fuer den Inhalt eines Git-Standes (Release-Pruefsummen).

Die Pruefsummen werden aus dem Archiv des Standes gebildet, mit LF-Zeilenenden (und CRLF nur fuer
*.ps1, wie .gitattributes es verlangt). Das ist byteweise dasselbe, was GitHub als ZIP eines Tags
ausliefert (geprueft am Tag 0.1.0-draft.2: 97 Dateien, alle identisch). SHA256SUMS und
SHA256SUMS.sig selbst werden nicht aufgenommen.

Aufruf (im Repository-Wurzelordner):
    python tools/make-checksums.py [REF]        # Standard: HEAD
"""
import hashlib
import io
import subprocess
import sys
import tarfile

ref = sys.argv[1] if len(sys.argv) > 1 else 'HEAD'
archive = subprocess.run(
    ['git', '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', ref],
    capture_output=True, check=True).stdout

entries = []
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    for member in tar.getmembers():
        if not member.isfile() or member.name in ('SHA256SUMS', 'SHA256SUMS.sig'):
            continue
        entries.append((member.name, hashlib.sha256(tar.extractfile(member).read()).hexdigest()))

entries.sort()
with open('SHA256SUMS', 'w', encoding='utf-8', newline='\n') as out:
    for name, digest in entries:
        out.write(f'{digest}  {name}\n')
print(f'SHA256SUMS: {len(entries)} Dateien aus {ref}')
