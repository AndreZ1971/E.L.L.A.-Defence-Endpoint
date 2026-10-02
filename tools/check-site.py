"""Gleicht jede Zahl der Projektseite (data-check="...") mit dem Repository ab.

Weicht eine Zahl ab, endet das Skript mit Fehler und die Seite wird nicht veröffentlicht.
Aufruf: python tools/check-site.py
"""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent


def read(rel):
    return (root / rel).read_text(encoding="utf-8-sig")


def count(rel, pattern):
    return len(re.findall(pattern, read(rel), flags=re.M))


spec = "SPEC.md"
evidence = read("docs/EVIDENCE.md")
errata = evidence.split("## Errata", 1)[1]
evidence_rows = re.findall(r"^\| E-\d+\b.*$", evidence, flags=re.M)

expected = {
    "requirements": count(spec, r"^\| \*\*EDEP-[A-Z]+-\d+\*\* \|"),
    "sources": count(spec, r"^\| Q-\d+\s+\|"),
    "bypasses": count(spec, r"^\| \*\*B-\d+\*\* \|"),
    "tests": count("conformance/README.md", r"^\| T-[A-Z]+-\d+[a-z]?\s+\|"),
    "errata": len(re.findall(r"^\| \d{4}-\d{2}-\d{2}\s+\|", errata, flags=re.M)),
    "evidence-total": len(evidence_rows),
    "evidence-open": sum(1 for r in evidence_rows if "⏳" in r),
    "audit-items": count("baseline/L1/EdepAudit.ps1", r"^    '(?:EDEP|AUD)-[A-Z0-9-]+' = @\{"),
    "l1-checks": len(set(re.findall(r"'(EDEP-[A-Z]+-\d+)'", read("baseline/L1/EdepL1.Checks.ps1")))),
}

errors = 0
fix = "--fix" in sys.argv  # nur lokal, nach Prüfung der Änderung; die CI läuft ohne --fix
for page in ["site/index.html", "site/en/index.html"]:
    html = read(page)
    if fix:
        def _sync(m):
            key = m.group(2)
            return m.group(1) + str(expected[key]) if key in expected else m.group(0)
        fixed = re.sub(r'(data-check="([a-z0-9-]+)"\s*>\s*)\d+', _sync, html)
        if fixed != html:
            (root / page).write_text(fixed, encoding="utf-8", newline="\n")
            print(f"angepasst: {page}")
            html = fixed
    found = re.findall(r'data-check="([a-z0-9-]+)"\s*>\s*(\d+)', html)
    keys = {k for k, _ in found}
    for key in expected:
        if key not in keys:
            print(f"FEHLT   {page}: data-check=\"{key}\"")
            errors += 1
    for key, value in found:
        if key not in expected:
            print(f"UNBEKANNT {page}: {key}")
            errors += 1
        elif int(value) != expected[key]:
            print(f"FALSCH  {page}: {key} = {value}, Repository = {expected[key]}")
            errors += 1

    # Zusage der Seite: keine externen Ressourcen (Schriften, Skripte, Stylesheets, Bilder, Frames).
    external = re.findall(
        r'<(?:script|link|img|source|iframe|video|audio)\b[^>]*\b(?:src|href|srcset)\s*=\s*"(https?:)?//[^"]*"',
        html, flags=re.I)
    if re.search(r'@import|url\(\s*["\']?https?:', read("site/style.css"), flags=re.I) or external:
        print(f"EXTERN  {page}: externe Ressource eingebunden")
        errors += 1

for key, value in expected.items():
    print(f"{key:15} {value}")
print("OK" if not errors else f"{errors} Abweichung(en)")
sys.exit(1 if errors else 0)
