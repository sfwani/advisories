#!/usr/bin/env python3
"""Rebuild this repository from the public GitHub Advisory Database.

Every page here mirrors an advisory that is already published, fixed, and
credited. Nothing is written from local research notes, so nothing unpublished
can leak in: if the GHSA is not live and not credited, it does not appear.
"""

import os
import pathlib
import re
import sys

import requests

USER = os.environ.get("ADVISORY_CREDIT_USER", "sfwani")
ROOT = pathlib.Path(__file__).resolve().parent.parent
API = "https://api.github.com"


def session():
    s = requests.Session()
    s.headers.update({"User-Agent": "sfwani-advisories", "Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def credited_ids(s):
    r = s.get("https://github.com/advisories", params={"query": f"credit:{USER}"}, timeout=30)
    r.raise_for_status()
    pattern = r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
    return list(dict.fromkeys(re.findall(pattern, r.text)))


def fetch(s, ghsa_id):
    r = s.get(f"{API}/advisories/{ghsa_id}", timeout=30)
    if r.status_code != 200:
        print(f"skip {ghsa_id}: HTTP {r.status_code}", file=sys.stderr)
        return None
    a = r.json()
    if a.get("withdrawn_at") or not a.get("published_at"):
        print(f"skip {ghsa_id}: not published", file=sys.stderr)
        return None
    return a


def page(a):
    name = a.get("cve_id") or a["ghsa_id"]
    cvss = a.get("cvss") or {}
    cwes = ", ".join(f"{c['cwe_id']} ({c['name']})" for c in a.get("cwes") or []) or "n/a"
    lines = [
        f"# {name}",
        "",
        f"**{a['summary'].strip()}**",
        "",
        "| | |",
        "|:--|:--|",
        f"| Advisory | [{a['ghsa_id']}]({a.get('html_url')}) |",
        f"| CVE | {a.get('cve_id') or 'not assigned'} |",
        f"| Severity | {(a.get('severity') or '').capitalize()} ({cvss.get('score')}) |",
        f"| CVSS vector | `{cvss.get('vector_string') or 'n/a'}` |",
        f"| CWE | {cwes} |",
        f"| Published | {(a.get('published_at') or '')[:10]} |",
        "",
        "### Affected versions",
        "",
        "| Package | Ecosystem | Vulnerable | Fixed in |",
        "|:--|:--|:--|:--|",
    ]
    for v in a.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        lines.append(
            f"| `{pkg.get('name', 'n/a')}` | {pkg.get('ecosystem', 'n/a')} | "
            f"{v.get('vulnerable_version_range') or 'n/a'} | {v.get('first_patched_version') or 'n/a'} |"
        )
    lines += ["", "## Details", "", (a.get("description") or "").strip(), ""]

    refs = [r for r in (a.get("references") or []) if r != a.get("html_url")]
    if refs:
        lines += ["## References", ""] + [f"* {r}" for r in refs] + [""]
    return "\n".join(lines)


def index(entries):
    lines = [
        "# Advisories",
        "",
        "Security advisories I reported that are published, fixed, and credited in the",
        "[GitHub Advisory Database](https://github.com/advisories?query=credit%3Asfwani).",
        "Each page carries the full root cause analysis, the vulnerable code, reproduction",
        "steps, and the fix, exactly as published in the advisory.",
        "",
        "Only published advisories appear here. Reports still in coordinated disclosure are",
        "not listed, named, or hinted at until the maintainer ships a fix and the advisory",
        "goes live.",
        "",
        "| Advisory | Project | CVSS | Class | Writeup |",
        "|:--|:--|:--|:--|:--|",
    ]
    for e in entries:
        lines.append(
            f"| [{e['name']}]({e['url']}) | `{e['package']}` | {e['score']:.1f} {e['severity']} "
            f"| {e['cwe']} | [read]({e['path']}) |"
        )
    lines += [
        "",
        "Reported by [@sfwani](https://github.com/sfwani). Rebuilt with `python scripts/build.py`.",
        "",
    ]
    return "\n".join(lines)


def main():
    s = session()
    ids = credited_ids(s)
    print(f"credited advisories: {len(ids)}", file=sys.stderr)

    entries = []
    for ghsa_id in ids:
        a = fetch(s, ghsa_id)
        if not a:
            continue
        packages = sorted({v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")})
        package = packages[0] if packages else "misc"
        name = a.get("cve_id") or a["ghsa_id"]
        rel = f"{package}/{name}.md"
        out = ROOT / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(page(a), encoding="utf-8")
        score = (a.get("cvss") or {}).get("score")
        entries.append({
            "name": name,
            "url": a.get("html_url"),
            "package": package,
            "score": score if isinstance(score, (int, float)) else 0.0,
            "severity": (a.get("severity") or "").capitalize(),
            "cwe": (a.get("cwes") or [{}])[0].get("cwe_id", "n/a"),
            "path": rel,
        })

    if not entries:
        raise SystemExit("nothing published, refusing to write an empty index")
    entries.sort(key=lambda e: (-e["score"], e["package"]))
    (ROOT / "README.md").write_text(index(entries), encoding="utf-8")
    print(f"wrote {len(entries)} advisory pages", file=sys.stderr)


if __name__ == "__main__":
    main()
