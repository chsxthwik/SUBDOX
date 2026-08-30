#!/usr/bin/env python3
"""
SUBDOX - subdomain takeover monitor.

Reads the CNAME map produced by dnsx (scripts/enum.sh), checks each host
against the can-i-take-over-xyz fingerprint database, flags dangling /
unclaimed services, sends Telegram alerts, and keeps state in SQLite so
every finding alerts exactly once.

Usage:
    python3 scan.py            # expects data/cnames.txt + data/subs-latest.txt
Environment:
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID   - required for alerts
    SUBDOX_HTTP_CAP                  - max HTTP checks per run (default 3000)
    SUBDOX_HTTP_WORKERS              - concurrent HTTP checks (default 32)
    SUBDOX_DNS_WORKERS               - concurrent DNS lookups (default 50)
    SUBDOX_DANGLING_ALERTS           - alert on unknown dangling CNAMEs (default 1)
    SUBDOX_NEW_SUB_ALERTS            - digest of newly seen subdomains (default 0)
"""

import concurrent.futures as cf
import ipaddress
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

import requests

try:
    import dns.resolver
except ImportError:
    sys.exit("missing dependency: pip install -r requirements.txt")

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "state.db")
CNAMES_FILE = os.path.join(DATA_DIR, "cnames.txt")
SUBS_FILE = os.path.join(DATA_DIR, "subs-latest.txt")
FP_PATH = os.path.join(ROOT, "fingerprints.json")
FP_URL = (
    "https://raw.githubusercontent.com/EdOverflow/"
    "can-i-take-over-xyz/master/fingerprints.json"
)

HTTP_CAP = int(os.environ.get("SUBDOX_HTTP_CAP", "3000"))
HTTP_WORKERS = int(os.environ.get("SUBDOX_HTTP_WORKERS", "32"))
DNS_WORKERS = int(os.environ.get("SUBDOX_DNS_WORKERS", "50"))
DANGLING_ALERTS = os.environ.get("SUBDOX_DANGLING_ALERTS", "1") == "1"
NEW_SUB_ALERTS = os.environ.get("SUBDOX_NEW_SUB_ALERTS", "0") == "1"
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------
# fingerprints
# --------------------------------------------------------------------------

def refresh_fingerprints():
    """Pull the latest fingerprint DB; fall back to the committed snapshot."""
    try:
        r = requests.get(FP_URL, timeout=20, headers={"User-Agent": UA})
        data = r.json()
        if r.ok and isinstance(data, list) and len(data) >= 40:
            with open(FP_PATH, "w") as f:
                json.dump(data, f, indent=1)
            return data, "upstream"
    except Exception:
        pass
    try:
        with open(FP_PATH) as f:
            return json.load(f), "local snapshot"
    except Exception:
        sys.exit("no usable fingerprint database (fetch failed and no local copy)")


def parse_fingerprint(raw):
    raw = (raw or "").strip()
    if raw.upper() == "NXDOMAIN" or raw.upper().startswith("NXDOMAIN"):
        return "nxdomain", None
    m = re.fullmatch(r"(?i)HTTP[_ ]STATUS\s*=\s*(\d{3})", raw)
    if m:
        return "http_status", int(m.group(1))
    return "body", raw


def body_alternatives(raw):
    parts = re.split(r"&#124;|` `|\|", raw)
    return [p.strip() for p in parts if p.strip()]


def body_match(raw, body):
    if not body:
        return False
    low = body.lower()
    for alt in body_alternatives(raw):
        try:
            if re.search(alt, body, re.IGNORECASE):
                return True
            continue
        except re.error:
            pass
        plain = alt.replace("\\.", ".")
        if plain.lower() in low:
            return True
    return False


def cname_suffix_match(entries, targets, ips):
    for entry in entries:
        entry = entry.strip().rstrip(".").lower()
        if not entry:
            continue
        try:
            ipaddress.ip_address(entry)
            if entry in ips:
                return True
            continue
        except ValueError:
            pass
        for t in targets:
            if t == entry or t.endswith("." + entry):
                return True
    return False


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def open_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute(
        "CREATE TABLE IF NOT EXISTS findings ("
        " key TEXT PRIMARY KEY, subdomain TEXT NOT NULL, service TEXT,"
        " severity TEXT, cname TEXT, evidence TEXT,"
        " first_seen TEXT, last_seen TEXT, alerts INTEGER DEFAULT 0)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS subs ("
        " host TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
    )
    return db


def track_subs(db, hosts, now):
    new = []
    cur = db.execute("SELECT host FROM subs")
    known = {row[0] for row in cur}
    fresh = [h for h in hosts if h not in known]
    db.executemany(
        "INSERT OR REPLACE INTO subs VALUES (?,?,?)",
        [(h, now, now) for h in fresh],
    )
    db.executemany(
        "UPDATE subs SET last_seen=? WHERE host=?",
        [(now, h) for h in hosts if h in known],
    )
    return fresh


# --------------------------------------------------------------------------
# input parsing
# --------------------------------------------------------------------------

DNSX_LINE = re.compile(r"^(\S+?)\.?\s+\[(CNAME|A|AAAA)\]\s+(.+)$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_dnsx(path):
    cname_map = {}
    a_map = {}
    if not os.path.exists(path):
        return cname_map, a_map, False
    with open(path) as f:
        for line in f:
            m = DNSX_LINE.match(ANSI.sub("", line.strip()))
            if not m:
                continue
            host = m.group(1).rstrip(".").lower()
            # dnsx brackets record values: host [CNAME] [target.example.com]
            rtype, value = m.group(2), m.group(3).split()[0].strip("[]").rstrip(".")
            if host == value:
                continue
            if rtype == "CNAME":
                cname_map.setdefault(host, [])
                if value not in cname_map[host]:
                    cname_map[host].append(value.lower())
            else:
                a_map.setdefault(host, [])
                if value not in a_map[host]:
                    a_map[host].append(value)
    return cname_map, a_map, True


def discover_cnames(hosts):
    """Fallback path: resolve CNAMEs ourselves when dnsx output is missing."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.timeout = 4
    resolver.lifetime = 6
    cname_map = {}

    def probe(host):
        try:
            ans = resolver.resolve(host, "CNAME")
            return host, [r.target.to_text().rstrip(".").lower() for r in ans]
        except Exception:
            return host, []

    with cf.ThreadPoolExecutor(DNS_WORKERS) as pool:
        for host, targets in pool.map(probe, hosts):
            if targets:
                cname_map[host] = targets
    return cname_map


def target_state(target):
    """Returns (dangling, ips): dangling is True/False/None (unknown)."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.timeout = 4
    resolver.lifetime = 6
    for rtype in ("A", "AAAA"):
        try:
            ans = resolver.resolve(target, rtype)
            return False, [r.to_text() for r in ans]
        except dns.resolver.NXDOMAIN:
            continue
        except Exception:
            return None, []
    return True, []


# --------------------------------------------------------------------------
# HTTP checks
# --------------------------------------------------------------------------

_session = requests.Session()


def http_check(host):
    for scheme in ("https", "http"):
        try:
            r = _session.get(
                f"{scheme}://{host}/",
                timeout=10,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": UA},
            )
            return {"status": r.status_code, "body": (r.text or "")[:20000]}
        except requests.RequestException:
            continue
    return None


# --------------------------------------------------------------------------
# alerts
# --------------------------------------------------------------------------

def telegram_send(text):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "no TELEGRAM_TOKEN / TELEGRAM_CHAT_ID configured"
    for attempt in range(3):
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": text,
                    "disable_web_page_preview": True,
                },
                timeout=15,
            )
            if r.ok:
                return True, "ok"
        except requests.RequestException:
            pass
    return False, "send failed after retries"


SEVERITY_TAG = {"high": "[TAKEOVER]", "medium": "[REVIEW]", "info": "[DANGLING]"}

# Body fingerprints this short / status-code-shaped ("404 Not Found") collide
# with plain nginx/cloudfront error pages. Trust them only when the CNAME
# also matches the provider; otherwise skip to avoid guaranteed false hits.
GENERIC_BODY = re.compile(r"(?i)^\d{3}\s*(error)?[a-z .!:-]{0,30}$")


def is_generic_body(raw):
    s = raw.strip()
    return len(s) <= 25 or bool(GENERIC_BODY.fullmatch(s))


def format_finding(f, seen):
    lines = [
        f"{SEVERITY_TAG.get(f['severity'], '[FINDING]')} {f['subdomain']}",
        f"Service: {f['service']}",
    ]
    if f["cname"]:
        lines.append(f"CNAME: {f['cname']}")
    lines.append(f"Proof: {f['evidence']}")
    lines.append(f"First seen: {seen}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    now = utcnow()
    fps, fp_source = refresh_fingerprints()
    fps = [e for e in fps if e.get("status") != "Not vulnerable"]
    print(f"[*] fingerprints: {len(fps)} active entries ({fp_source})")

    cname_map, a_map, from_dnsx = parse_dnsx(CNAMES_FILE)
    if not from_dnsx:
        hosts = []
        if os.path.exists(SUBS_FILE):
            with open(SUBS_FILE) as f:
                hosts = [l.strip().lower() for l in f if l.strip()]
        print(f"[*] no dnsx output found, resolving CNAMEs for {len(hosts)} hosts")
        cname_map = discover_cnames(hosts)
    cname_map = dict(sorted(cname_map.items()))
    print(f"[*] hosts with CNAME records: {len(cname_map)}")

    # decide which hosts need an HTTP fetch
    need_http = {}
    for host, targets in cname_map.items():
        ips = set(a_map.get(host, []))
        relevant = []
        for fp in fps:
            entries = fp.get("cname") or []
            if entries and not cname_suffix_match(entries, targets, ips):
                continue
            kind, _ = parse_fingerprint(fp.get("fingerprint"))
            if kind in ("body", "http_status"):
                relevant.append(fp)
        if relevant:
            need_http[host] = relevant

    # prioritise vulnerable-cname matches, then edge cases, then the rest
    def priority(host):
        statuses = {fp.get("status") for fp in need_http[host]}
        if "Vulnerable" in statuses:
            return 0
        if "Edge case" in statuses:
            return 1
        return 2

    http_hosts = sorted(need_http, key=lambda h: (priority(h), h))
    truncated = False
    if len(http_hosts) > HTTP_CAP:
        http_hosts = http_hosts[:HTTP_CAP]
        truncated = True
    print(f"[*] HTTP checks: {len(http_hosts)} hosts" + (" (capped)" if truncated else ""))

    http_results = {}
    if http_hosts:
        with cf.ThreadPoolExecutor(HTTP_WORKERS) as pool:
            for host, res in zip(http_hosts, pool.map(http_check, http_hosts)):
                http_results[host] = res

    db = open_db()
    all_hosts = []
    if os.path.exists(SUBS_FILE):
        with open(SUBS_FILE) as f:
            all_hosts = [l.strip().lower() for l in f if l.strip()]
    new_subs = track_subs(db, all_hosts, now)

    findings = []
    for host, targets in cname_map.items():
        ips = set(a_map.get(host, []))
        dangling, _tip = None, None
        for target in targets:
            dangling, tip = target_state(target)
            if dangling is not None:
                break
        cname_str = " -> ".join(targets)

        matched_fp = False
        for fp in fps:
            entries = fp.get("cname") or []
            if entries and not cname_suffix_match(entries, targets, ips):
                continue
            kind, val = parse_fingerprint(fp.get("fingerprint"))
            if (
                kind == "body"
                and not entries
                and is_generic_body(val)
            ):
                continue  # generic 404 text + no cname context = false positive
            hit = None
            if kind == "nxdomain" and dangling is True:
                hit = f"CNAME {cname_str} -> NXDOMAIN (dangling)"
            elif kind == "http_status":
                res = http_results.get(host)
                if res and res["status"] == val:
                    hit = f"HTTP status {res['status']} matches fingerprint"
            elif kind == "body":
                res = http_results.get(host)
                if res and body_match(val, res["body"]):
                    hit = (
                        f'body match "{body_alternatives(val)[0][:80]}" '
                        f"(HTTP {res['status']})"
                    )
            if hit:
                matched_fp = True
                status = fp.get("status", "Vulnerable")
                findings.append(
                    {
                        "subdomain": host,
                        "service": fp.get("service", "unknown"),
                        "severity": "high" if status == "Vulnerable" else "medium",
                        "cname": cname_str,
                        "evidence": hit,
                        "key": f"{host}|{fp.get('service')}|{kind}",
                    }
                )
                if status == "Vulnerable":
                    break

        if not matched_fp and dangling is True and DANGLING_ALERTS:
            findings.append(
                {
                    "subdomain": host,
                    "service": "unknown (dangling CNAME)",
                    "severity": "info",
                    "cname": cname_str,
                    "evidence": f"CNAME {cname_str} -> NXDOMAIN, "
                    "no fingerprint match; manual review",
                    "key": f"{host}|dangling",
                }
            )

    # persist + alert
    alerted, failed = 0, 0
    for f in findings:
        row = db.execute(
            "SELECT first_seen, alerts FROM findings WHERE key=?", (f["key"],)
        ).fetchone()
        if row:
            seen, alerts = row
            db.execute(
                "UPDATE findings SET last_seen=?, cname=?, evidence=? WHERE key=?",
                (now, f["cname"], f["evidence"], f["key"]),
            )
            if alerts > 0:
                continue  # already notified about this exact finding
        else:
            seen = now
            db.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,0)",
                (
                    f["key"],
                    f["subdomain"],
                    f["service"],
                    f["severity"],
                    f["cname"],
                    f["evidence"],
                    now,
                    now,
                ),
            )
        ok, err = telegram_send(format_finding(f, seen))
        if ok:
            alerted += 1
            db.execute("UPDATE findings SET alerts=alerts+1 WHERE key=?", (f["key"],))
        else:
            failed += 1
            print(f"[!] alert not sent for {f['subdomain']}: {err}")

    if NEW_SUB_ALERTS and new_subs:
        sample = "\n".join(new_subs[:100])
        more = f"\n... and {len(new_subs) - 100} more" if len(new_subs) > 100 else ""
        telegram_send(
            f"[NEW SUBS] {len(new_subs)} new subdomain(s) discovered:\n{sample}{more}"
        )

    db.execute(
        "INSERT OR REPLACE INTO meta VALUES ('last_run', ?)", (now,)
    )
    db.commit()
    db.close()

    # run report
    summary = (
        f"SUBDOX run {now}\n"
        f"  subdomains tracked : {len(all_hosts)}\n"
        f"  cname hosts        : {len(cname_map)}\n"
        f"  findings           : {len(findings)}\n"
        f"  telegram alerts    : {alerted} sent, {failed} failed\n"
        f"  new subdomains     : {len(new_subs)}"
    )
    print(summary)

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "last-scan.json"), "w") as f:
        json.dump(
            {
                "run_at": now,
                "subdomains_tracked": len(all_hosts),
                "cname_hosts": len(cname_map),
                "findings": findings,
            },
            f,
            indent=1,
        )

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(
                f"## SUBDOX run - {now}\n\n"
                f"| metric | value |\n|---|---|\n"
                f"| subdomains tracked | {len(all_hosts)} |\n"
                f"| hosts with CNAME | {len(cname_map)} |\n"
                f"| findings | {len(findings)} |\n"
                f"| alerts sent | {alerted} |\n"
                f"| new subdomains | {len(new_subs)} |\n"
            )
            for sev in ("high", "medium", "info"):
                for x in [x for x in findings if x["severity"] == sev]:
                    f.write(f"\n`{SEVERITY_TAG[sev]}` **{x['subdomain']}** "
                            f"({x['service']}): {x['evidence']}\n")

    print("[*] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
