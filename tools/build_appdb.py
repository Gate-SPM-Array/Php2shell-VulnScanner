#!/usr/bin/env python3
"""
Costruisce i file dati del database applicazioni (cartella data/) a partire da due sorgenti pubbliche:

  1. enthec/webappanalyzer (firme in formato Wappalyzer, GPL-3.0)
     https://github.com/enthec/webappanalyzer  ->  src/categories.json, src/technologies/*.json
  2. NCSC-NL/php2shell (inventario PHP2Shell in SPDX 3 + VEX, EUPL-1.2)
     https://github.com/NCSC-NL/php2shell      ->  software/spdx/PHP_Downstream_Inventory.spdx3.json

Uso (solo libreria standard, eseguire con `python3 -I`):

    git clone --depth 1 https://github.com/enthec/webappanalyzer  <dir>/webappanalyzer
    git clone --depth 1 --filter=blob:none --sparse https://github.com/NCSC-NL/php2shell <dir>/php2shell
    (cd <dir>/php2shell && git sparse-checkout set software/spdx)
    python3 -I tools/build_appdb.py --wappalyzer <dir>/webappanalyzer --ncsc <dir>/php2shell --out data

Produce: technologies.json, categories.json, ncsc_inventory.json, DATA-VERSION.txt,
LICENSE-webappanalyzer.txt, LICENSE-ncsc-nl.txt.

Dei dati Wappalyzer restano solo i campi verificabili passivamente da una risposta HTTP già scaricata:
headers, cookies, meta, html, scriptSrc (+ il vecchio nome "scripts"), url, certIssuer, implies, requires,
excludes. I selettori DOM semplici (tag[attr*='valore']) diventano espressioni regolari sull'HTML; js, css,
text, dns, xhr, probe, robots e tutto ciò che richiede un runtime JavaScript o richieste aggiuntive viene scartato.
I file di input sono dati non fidati: vengono solo letti e trasformati, mai eseguiti.

Questo script è il riferimento: src/PhpVulnScanner.Core/Apps/AppDbUpdater.cs ne è il porting in C# (pulsante "Aggiorna dati")
e produce byte per byte gli stessi file (stesso ordine delle chiavi, stesso escape di json.dump, stesso re.escape).
Ogni modifica qui va riportata lì; AppDbUpdaterTests confronta le due uscite su un input sintetico.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys

PASSIVE_LIST_FIELDS = ("html", "scriptSrc", "url", "certIssuer")
PASSIVE_DICT_FIELDS = ("headers", "cookies", "meta")
NCSC_BASE = "https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_"
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

# Applicazioni scritte in PHP alle quali le firme Wappalyzer non assegnano "implies": ["PHP"]: correzione locale,
# così il riconoscimento le conta come indizio di PHP (nomi esatti del database; le voci assenti vengono ignorate).
PHP_IMPLIES_FIXUPS = (
    "Matomo Analytics", "SuiteCRM", "Piwigo", "Invision Community", "Zen Cart", "WHMCS", "Elgg", "Tiki Wiki CMS Groupware",
    "Zend", "Pagekit", "Mahara", "Omeka", "Mautic", "Vtiger", "EspoCRM", "Bagisto", "HumHub", "Lychee", "Gallery", "Plesk",
)

VEX_STATUS = {
    "security_VexAffectedVulnAssessmentRelationship": "Affected",
    "security_VexFixedVulnAssessmentRelationship": "Fixed",
    "security_VexNotAffectedVulnAssessmentRelationship": "NotAffected",
    "security_VexUnderInvestigationVulnAssessmentRelationship": "UnderInvestigation",
}


def git_info(repo: str) -> tuple[str, str]:
    """Commit e data ISO del checkout (senza eseguire nulla dal repository: solo `git log`)."""
    try:
        out = subprocess.run(["git", "-C", repo, "log", "-1", "--format=%H %cI"], check=True,
                             capture_output=True, text=True).stdout.strip()
        commit, date = out.split(" ", 1)
        return commit, date
    except Exception as e:  # noqa: BLE001
        print(f"attenzione: impossibile leggere il commit di {repo}: {e}", file=sys.stderr)
        return "unknown", dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def as_dict_of_lists(v) -> dict[str, list[str]]:
    if not isinstance(v, dict):
        return {}
    out: dict[str, list[str]] = {}
    for k, val in v.items():
        if not isinstance(k, str):
            continue
        lst = as_list(val)
        if lst or val == "":
            out[k] = lst if lst else [""]
    return out


# ---- selettori DOM semplici -> regex HTML -------------------------------------------------------------------

SIMPLE_SELECTOR = re.compile(
    r"""^\s*([a-zA-Z][a-zA-Z0-9-]*)?\s*\[\s*([a-zA-Z_:][\w:.-]*)\s*(\*=|\^=|\$=|=)?\s*(?:'([^']*)'|"([^"]*)"|([^\]\s'"]+))?\s*\]\s*$"""
)


def split_top_level_commas(s: str) -> list[str]:
    parts, depth, cur, quote = [], 0, [], None
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch in "([":
            depth += 1
            cur.append(ch)
        elif ch in ")]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p for p in parts if p.strip()]


def selector_to_regex(sel: str) -> str | None:
    """`link[href*='/wp-content/']` -> regex sul sorgente HTML; None se il selettore non è di questa forma semplice."""
    m = SIMPLE_SELECTOR.match(sel)
    if not m:
        return None
    tag, attr, op, v1, v2, v3 = m.groups()
    value = v1 if v1 is not None else v2 if v2 is not None else v3
    tag_rx = re.escape(tag) if tag else "[a-zA-Z][a-zA-Z0-9-]*"
    attr_rx = re.escape(attr)
    if value is None:
        return rf"<{tag_rx}\b[^>]*\s{attr_rx}(?:[\s=>/]|$)"
    val_rx = re.escape(value)
    if op == "*=":
        return rf"<{tag_rx}\b[^>]*\s{attr_rx}=[\"']?[^\"'>]*{val_rx}"
    if op == "^=":
        return rf"<{tag_rx}\b[^>]*\s{attr_rx}=[\"']?{val_rx}"
    if op == "$=":
        return rf"<{tag_rx}\b[^>]*\s{attr_rx}=[\"']?[^\"'>]*{val_rx}[\"'\s>/]"
    if op == "=":
        return rf"<{tag_rx}\b[^>]*\s{attr_rx}=[\"']?{val_rx}[\"'\s>/]"
    return None


def dom_to_html_patterns(dom, stats: dict) -> list[str]:
    """Converte i selettori DOM semplici (senza condizioni su attributi/testo) in pattern HTML."""
    selectors: list[str] = []
    if isinstance(dom, str):
        selectors = [dom]
    elif isinstance(dom, list):
        selectors = [s for s in dom if isinstance(s, str)]
    elif isinstance(dom, dict):
        for sel, cond in dom.items():
            # solo "esiste": le condizioni su attributi, testo o proprietà richiedono un DOM reale
            if cond == "" or cond is None or (isinstance(cond, dict) and set(cond) <= {"exists"}):
                selectors.append(sel)
            else:
                stats["dom_skipped"] += 1
    out: list[str] = []
    for sel in selectors:
        for part in split_top_level_commas(sel):
            rx = selector_to_regex(part)
            if rx is None:
                stats["dom_skipped"] += 1
            else:
                stats["dom_converted"] += 1
                out.append(rx)
    return out


# ---- Wappalyzer -------------------------------------------------------------------------------------------------

def build_technologies(wapp_dir: str, stats: dict) -> tuple[dict, dict]:
    src = os.path.join(wapp_dir, "src")
    with open(os.path.join(src, "categories.json"), encoding="utf-8") as f:
        raw_cats = json.load(f)
    categories = {}
    for cid, c in raw_cats.items():
        if isinstance(c, dict) and isinstance(c.get("name"), str):
            categories[str(int(cid))] = c["name"]

    techs: dict[str, dict] = {}
    tdir = os.path.join(src, "technologies")
    for fn in sorted(os.listdir(tdir)):
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(tdir, fn), encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            continue
        for name, t in data.items():
            if not isinstance(name, str) or not isinstance(t, dict):
                continue
            if name in techs:
                stats["duplicates"] += 1
                continue
            entry: dict = {
                "cats": [int(c) for c in t.get("cats", []) if isinstance(c, int) or (isinstance(c, str) and c.isdigit())],
                "website": t.get("website", "") if isinstance(t.get("website"), str) else "",
            }
            if isinstance(t.get("cpe"), str) and t["cpe"]:
                entry["cpe"] = t["cpe"]
            for fld in PASSIVE_DICT_FIELDS:
                d = as_dict_of_lists(t.get(fld))
                if d:
                    entry[fld] = d
                    stats["patterns"] += sum(len(v) for v in d.values())
            for fld in PASSIVE_LIST_FIELDS:
                lst = as_list(t.get(fld))
                if fld == "scriptSrc":
                    lst = lst + [s for s in as_list(t.get("scripts")) if s not in lst]
                if fld == "html":
                    lst = lst + dom_to_html_patterns(t.get("dom"), stats)
                if lst:
                    entry[fld] = lst
                    stats["patterns"] += len(lst)
            for fld in ("implies", "requires", "excludes"):
                lst = as_list(t.get(fld))
                if fld == "implies" and name in PHP_IMPLIES_FIXUPS and not any(x.split("\\;")[0] == "PHP" for x in lst):
                    lst = lst + ["PHP"]
                    stats["php_fixups"] += 1
                if lst:
                    entry[fld] = lst
            techs[name] = entry
    return categories, dict(sorted(techs.items(), key=lambda kv: kv[0].lower()))


# ---- NCSC-NL ----------------------------------------------------------------------------------------------------

FIXED_CLAUSE_RX = re.compile(r"\b[Ff]ixed\b[^;:.]{0,40}?\bin\b([^;]{1,160})")
VERSION_TOKEN_RX = re.compile(r"(?<![\w.])\d+\.\d+(?:\.\d+)*(?:[-+][\w.]+)?(?![\w.]*\.\w)")
URL_RX = re.compile(r"https?://[^\s)\]]+")


def fixed_version(notes: str) -> str:
    """Numeri di versione citati nella frase "Fixed in …" (es. "8.5.12, 8.4.27, 8.3.36, 8.2.35" oppure "8.5.12-1")."""
    m = FIXED_CLAUSE_RX.search(notes)
    if not m:
        return ""
    clause = m.group(1)
    # la frase si ferma al primo punto seguito da spazio (fine frase), non ai punti dei numeri
    clause = re.split(r"\.\s", clause, maxsplit=1)[0]
    found: list[str] = []
    for v in VERSION_TOKEN_RX.findall(clause):
        if v not in found:
            found.append(v)
    return ", ".join(found[:4])


def comment_field(comment: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.*)$", comment or "", re.M)
    return m.group(1).strip() if m else ""


def ncsc_letter(name: str) -> str:
    ch = name.strip()[:1].lower()
    if ch.isdigit():
        return "0-9"
    if "a" <= ch <= "z":
        return ch
    return ""


def build_ncsc(ncsc_dir: str, stats: dict) -> list[dict]:
    path = os.path.join(ncsc_dir, "software", "spdx", "PHP_Downstream_Inventory.spdx3.json")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    graph = doc.get("@graph", doc if isinstance(doc, list) else [])
    by_id = {e.get("spdxId") or e.get("@id"): e for e in graph if isinstance(e, dict)}

    vex_by_pkg: dict[str, dict[str, dict]] = {}
    for e in graph:
        status = VEX_STATUS.get(e.get("type", ""))
        if not status:
            continue
        vuln = by_id.get(e.get("from"), {})
        cve = vuln.get("name") or ""
        if cve not in CVE_IDS:
            continue
        notes = (e.get("security_statusNotes") or e.get("security_impactStatement") or e.get("summary") or "").strip()
        fixed = fixed_version(notes) if status == "Fixed" else ""
        ref = ""
        for er in e.get("externalRef") or []:
            locs = er.get("locator") if isinstance(er, dict) else None
            if isinstance(locs, list) and locs:
                ref = locs[0]
                break
        if not ref:
            m = URL_RX.search(e.get("comment") or "")
            if m:
                ref = m.group(0).rstrip(".,")
        item = {"status": status}
        if fixed:
            item["fixedVersion"] = fixed
        if notes:
            item["note"] = notes[:300]
        if ref:
            item["reference"] = ref
        for pkg_id in e.get("to") or []:
            vex_by_pkg.setdefault(pkg_id, {})[cve] = item
            stats["vex"] += 1

    packages: list[dict] = []
    for e in graph:
        if e.get("type") != "software_Package" or not isinstance(e.get("name"), str):
            continue
        comment = e.get("comment") or ""
        aliases = [a.strip() for a in comment_field(comment, "Aliases").split(",") if a.strip()]
        url = ""
        for er in e.get("externalRef") or []:
            locs = er.get("locator") if isinstance(er, dict) else None
            if isinstance(locs, list) and locs and isinstance(locs[0], str):
                url = locs[0]
                break
        letter = ncsc_letter(e["name"])
        pkg = {
            "name": e["name"].strip(),
            "aliases": aliases,
            "category": comment_field(comment, "Category"),
            "url": url,
            "vex": vex_by_pkg.get(e.get("spdxId"), {}),
            "reference": (NCSC_BASE + letter + ".md") if letter else NCSC_BASE.rsplit("_", 1)[0] + ".md",
        }
        packages.append(pkg)
    packages.sort(key=lambda p: p["name"].lower())
    return packages


# ---- main -------------------------------------------------------------------------------------------------------

def dump(path: str, obj) -> int:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        f.write("\n")
    return os.path.getsize(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wappalyzer", required=True, help="checkout di enthec/webappanalyzer")
    ap.add_argument("--ncsc", required=True, help="checkout (anche sparse) di NCSC-NL/php2shell")
    ap.add_argument("--out", required=True, help="cartella data/ di destinazione")
    a = ap.parse_args()

    stats = {"patterns": 0, "duplicates": 0, "dom_converted": 0, "dom_skipped": 0, "vex": 0, "php_fixups": 0}
    os.makedirs(a.out, exist_ok=True)

    categories, techs = build_technologies(a.wappalyzer, stats)
    packages = build_ncsc(a.ncsc, stats)

    w_commit, w_date = git_info(a.wappalyzer)
    n_commit, n_date = git_info(a.ncsc)

    sizes = {
        "technologies.json": dump(os.path.join(a.out, "technologies.json"), techs),
        "categories.json": dump(os.path.join(a.out, "categories.json"), categories),
        "ncsc_inventory.json": dump(os.path.join(a.out, "ncsc_inventory.json"), packages),
    }
    with open(os.path.join(a.out, "DATA-VERSION.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"webappanalyzer {w_commit} {w_date} {len(techs)} technologies\n")
        f.write(f"ncsc-nl/php2shell {n_commit} {n_date} {len(packages)} packages {stats['vex']} vex\n")

    for src, dst in ((os.path.join(a.wappalyzer, "LICENSE"), "LICENSE-webappanalyzer.txt"),
                     (os.path.join(a.ncsc, "LICENSE"), "LICENSE-ncsc-nl.txt")):
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(a.out, dst))
        else:
            print(f"attenzione: licenza non trovata: {src}", file=sys.stderr)

    print(f"tecnologie: {len(techs)} (duplicati ignorati: {stats['duplicates']}), pattern passivi: {stats['patterns']}, "
          f"selettori DOM convertiti: {stats['dom_converted']}, scartati: {stats['dom_skipped']}, correzioni implies PHP: {stats['php_fixups']}")
    print(f"categorie: {len(categories)}; pacchetti NCSC-NL: {len(packages)}, asserzioni VEX: {stats['vex']}")
    for k, v in sizes.items():
        print(f"  {k}: {v:,} byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
