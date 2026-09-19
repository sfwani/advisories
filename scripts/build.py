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
SITE = "https://sfwani.github.io"


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


def extra_repo_advisories():
    """Repository level advisories: published and credited, but never forwarded
    to the global database, so the credit search cannot find them.

    Format: one "owner/repo GHSA-id" per line, blank lines and # comments ignored.
    """
    path = ROOT / "advisories.txt"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) == 2:
            out.append((parts[0], parts[1]))
    return out


def fetch_repo_level(s, repo, ghsa_id):
    """Only returns an advisory that is published and where USER credit is accepted."""
    r = s.get(f"{API}/repos/{repo}/security-advisories/{ghsa_id}", timeout=30)
    if r.status_code != 200:
        print(f"skip {ghsa_id}: HTTP {r.status_code}", file=sys.stderr)
        return None
    a = r.json()
    if a.get("state") != "published" or a.get("withdrawn_at"):
        print(f"skip {ghsa_id}: state={a.get('state')}", file=sys.stderr)
        return None
    accepted = any(
        (c.get("user") or {}).get("login") == USER and c.get("state") == "accepted"
        for c in a.get("credits_detailed") or []
    )
    if not accepted:
        print(f"skip {ghsa_id}: credit not accepted", file=sys.stderr)
        return None
    a.setdefault("html_url", f"https://github.com/{repo}/security/advisories/{ghsa_id}")
    a["_repo"] = repo
    return a


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


def short_package(name):
    if name.startswith("@"):
        return name
    for sep in ("/", ":"):
        if sep in name:
            name = name.rsplit(sep, 1)[-1]
    return name


def dir_slug(name):
    """Filesystem safe directory name for a package. @budibase/server -> budibase."""
    if name.startswith("@"):
        return name[1:].split("/", 1)[0]
    return short_package(name).replace("/", "-")


# Kept in step with the same table in sfwani/sfwani and sfwani.github.io.
# GHSA-pqxw-g93w-hj9x was published High with no CVSS score and no vector, in
# v3 or v4, so nothing upstream can supply one. This vector is derived by hand
# from the advisory's own text and computes to 9.0. Always rendered as mine,
# never as the published figure.
SELF_ASSESSED = {
    "GHSA-pqxw-g93w-hj9x": {
        "score": 9.0,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
}


def cvss_of(a):
    """Return (score, vector, self_assessed) for one advisory payload."""
    cvss = a.get("cvss") or {}
    score, vector = cvss.get("score"), cvss.get("vector_string")
    if not vector:
        v3 = (a.get("cvss_severities") or {}).get("cvss_v3") or {}
        score, vector = score if score is not None else v3.get("score"), v3.get("vector_string")
    if isinstance(score, (int, float)) and vector:
        return float(score), vector, False
    sa = SELF_ASSESSED.get(a.get("ghsa_id"))
    if sa:
        return sa["score"], sa["vector"], True
    return (float(score) if isinstance(score, (int, float)) else None), vector, False


def page(a):
    name = a.get("cve_id") or a["ghsa_id"]
    cvss = a.get("cvss") or {}
    cwes = ", ".join(f"{c['cwe_id']} ({c['name']})" for c in a.get("cwes") or []) or "n/a"
    slug = (a.get("cve_id") or a["ghsa_id"]).lower()
    score, vector, self_assessed = cvss_of(a)
    sev = (a.get("severity") or "").capitalize()
    if score is None:
        sev_cell, vec_cell = f"{sev} (no CVSS score published)", "`not published`"
    elif self_assessed:
        sev_cell = f"{sev} ({score:.1f}, self-assessed)"
        vec_cell = f"`{vector}` (self-assessed)"
    else:
        sev_cell, vec_cell = f"{sev} ({score})", f"`{vector}`"
    lines = [
        f"# {name}",
        "",
        f"*Canonical version: <{SITE}/advisories/{slug}/>*",
        "",
        f"**{a['summary'].strip()}**",
        "",
        "| | |",
        "|:--|:--|",
        f"| Advisory | [{a['ghsa_id']}]({a.get('html_url')}) |",
        f"| CVE | {a.get('cve_id') or 'not assigned'} |",
        f"| Severity | {sev_cell} |",
        f"| CVSS vector | {vec_cell} |",
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
            f"| [{e['name']}]({e['url']}) | `{short_package(e['package'])}` "
            f"| {(f"{e['score']:.1f}{'*' if e['self_assessed'] else ''} {e['severity']}") if e['score'] is not None else e['severity']} "
            f"| {e['cwe']} | [read]({e['path']}) |"
        )
    lines += [
        "",
        "\\* Scored by me, not by the coordinating database: published with a severity but no "
        "CVSS score and no vector, in v3 or v4. The vector is on that advisory's own page."
        if any(e.get("self_assessed") for e in entries) else "",
        "Reported by [@sfwani](https://github.com/sfwani). Rebuilt with `python scripts/build.py`.",
        "",
    ]
    return "\n".join(lines)


def main():
    s = session()
    ids = credited_ids(s)
    print(f"credited advisories: {len(ids)}", file=sys.stderr)

    advisories = [(None, i) for i in ids]
    seen = set(ids)
    for repo, ghsa_id in extra_repo_advisories():
        if ghsa_id not in seen:
            advisories.append((repo, ghsa_id))
            seen.add(ghsa_id)

    entries = []
    for repo, ghsa_id in advisories:
        a = fetch_repo_level(s, repo, ghsa_id) if repo else fetch(s, ghsa_id)
        if not a:
            continue
        packages = sorted({v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")})
        package = short_package(packages[0]) if packages else (repo or "misc").split("/")[-1]
        name = a.get("cve_id") or a["ghsa_id"]
        rel = f"{dir_slug(package)}/{name}.md"
        out = ROOT / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(page(a), encoding="utf-8")
        score, _vector, self_assessed = cvss_of(a)
        entries.append({
            "name": name,
            "url": a.get("html_url"),
            "package": package,
            "score": score,
            "self_assessed": self_assessed,
            "severity": (a.get("severity") or "").capitalize(),
            "cwe": (a.get("cwes") or [{}])[0].get("cwe_id", "n/a"),
            "path": rel,
        })

    if not entries:
        raise SystemExit("nothing published, refusing to write an empty index")
    entries.sort(key=lambda e: (-(e["score"] if e["score"] is not None else -1), e["package"]))
    (ROOT / "README.md").write_text(index(entries), encoding="utf-8")
    print(f"wrote {len(entries)} advisory pages", file=sys.stderr)


if __name__ == "__main__":
    main()
