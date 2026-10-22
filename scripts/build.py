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
# Some advisories were published with a severity label but no CVSS score or
# vector (v3 or v4), so nothing upstream can supply one. These vectors are
# derived by hand and kept inside the band the maintainer assigned.
# GHSA-pqxw-g93w-hj9x computes to 8.1 (S:U), the exact vector GitHub assigned
# to CVE-2026-45675; GHSA-42mf-vpmr-gw5r (ag2, shell=True command-filter
# bypass to arbitrary OS command execution) computes to 9.8.
SELF_ASSESSED = {
    "GHSA-pqxw-g93w-hj9x": {
        "score": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "GHSA-42mf-vpmr-gw5r": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    # ag2ai/ag2, second advisory: published High with no CVSS vector. Path
    # traversal in DiskKnowledgeStore (startswith containment bypassed by a
    # prefix-sharing sibling). Score and vector taken verbatim from the
    # advisory's own CVSS line, inside the maintainer's High band.
    "GHSA-qrjx-72xx-xhmh": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    },
}

# Short, readable labels for the CWEs in this work, kept in step with the same
# map in sfwani/sfwani and sfwani.github.io so the Class column reads the same
# on every surface.
CWE_LABELS = {
    "CWE-22": "Path traversal",
    "CWE-78": "Command injection",
    "CWE-79": "Cross site scripting",
    "CWE-94": "Code injection",
    "CWE-200": "Information disclosure",
    "CWE-269": "Privilege escalation",
    "CWE-284": "Access control",
    "CWE-287": "Authentication bypass",
    "CWE-306": "Missing authentication",
    "CWE-321": "Hard-coded crypto key",
    "CWE-352": "Cross site request forgery",
    "CWE-362": "Race condition",
    "CWE-434": "Unrestricted upload",
    "CWE-502": "Unsafe deserialization",
    "CWE-639": "Insecure direct object reference",
    "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization",
    "CWE-653": "Improper isolation",
    "CWE-668": "Resource exposure",
    "CWE-918": "Server side request forgery",
    "CWE-1333": "Regex denial of service",
}


def cwe_label(cwe):
    if not cwe or cwe == "n/a":
        return "Other"
    name = CWE_LABELS.get(cwe)
    return f"{name} ({cwe})" if name else cwe


def _cvss_pick(obj, prefix):
    """A (score, vector) from one CVSS node, only if it is a real base score on
    the requested version. Guards against the 0.0 placeholder GitHub sometimes
    stores next to a vector it has not fully computed."""
    o = obj or {}
    s, v = o.get("score"), o.get("vector_string")
    if isinstance(s, (int, float)) and s > 0 and v and v.startswith(prefix):
        return float(s), v
    return None, None


def cvss_of(a):
    """Return (score, vector, self_assessed) for one advisory payload.

    Priority: a published CVSS v3.1 base score, then a deliberate self
    assessment, then a published CVSS v4.0 base score (GitHub increasingly
    scores on v4). The self assessment wins over v4 on purpose: a curated v3.1
    number inside the maintainer's band must not be replaced by a v4 vector a
    database added later. The top level `cvss` node can hold either version.
    """
    cvss = a.get("cvss") or {}
    sev = a.get("cvss_severities") or {}
    for obj in (cvss, sev.get("cvss_v3")):
        s, v = _cvss_pick(obj, "CVSS:3")
        if s:
            return s, v, False
    sa = SELF_ASSESSED.get(a.get("ghsa_id"))
    if sa:
        return sa["score"], sa["vector"], True
    for obj in (cvss, sev.get("cvss_v4")):
        s, v = _cvss_pick(obj, "CVSS:4")
        if s:
            return s, v, False
    return None, None, False


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
        sev_cell, vec_cell = f"{sev} ({score:.1f})", f"`{vector}`"
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
            f"| {f"{e['score']:.1f} {e['severity']}" if e['score'] is not None else e['severity']} "
            f"| {cwe_label(e['cwe'])} | [read]({e['path']}) |"
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
