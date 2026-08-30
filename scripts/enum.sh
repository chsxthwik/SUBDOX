#!/usr/bin/env bash
# SUBDOX - deep subdomain enumeration
#
# Pipeline: passive (subfinder) -> crt.sh fallback -> archive (gau)
#           -> brute force (dnsx A-resolution) -> permutations (perms.py)
#           -> CNAME capture (dnsx, includes unresolvable/dangling names)
#
# Outputs (relative to repo root):
#   data/subs-latest.txt   every unique candidate discovered
#   data/cnames.txt        dnsx CNAME/A map, consumed by scan.py
#
# Any single source may fail; the pipeline never dies because of it.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WORK="${SUBDOX_WORKDIR:-/tmp/SUBDOX-work}"
mkdir -p "$WORK" data
: > "$WORK/raw_subs.txt"

BRUTE_WORDLIST="${BRUTE_WORDLIST:-$WORK/brute.txt}"
[ -s "$BRUTE_WORDLIST" ] || BRUTE_WORDLIST="wordlists/core-brute.txt"
RESOLVERS_FILE="${RESOLVERS_FILE:-$WORK/resolvers.txt}"
[ -s "$RESOLVERS_FILE" ] || RESOLVERS_FILE="wordlists/resolvers-fallback.txt"
PERM_CAP="${SUBDOX_PERM_CAP:-200000}"

DOMAINS="$(sed 's/#.*//' domains.txt | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')"
if [ -z "$DOMAINS" ]; then
    echo "domains.txt has no active entries - add one, e.g. 'example.com'" >&2
    exit 1
fi
echo "[enum] targets: $(echo "$DOMAINS" | tr '\n' ' ')"

# ---- 1. passive sources (subfinder, -all aggregates everything) -----------
while IFS= read -r d; do
    [ -z "$d" ] && continue
    echo "[enum] passive: $d"
    subfinder -d "$d" -all -silent -timeout 30 >> "$WORK/raw_subs.txt" 2>/dev/null
done <<< "$DOMAINS"

# ---- 2. crt.sh fallback (best-effort) --------------------------------------
while IFS= read -r d; do
    [ -z "$d" ] && continue
    echo "[enum] crt.sh: $d"
    curl -sf --max-time 45 "https://crt.sh/?q=%25.${d}&output=json" 2>/dev/null \
        | python3 -c '
import json, sys
d = sys.argv[1]
try:
    rows = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for row in rows:
    for name in row.get("name_value", "").split("\n"):
        name = name.strip().lower().lstrip("*.").rstrip(".")
        if name and (name == d or name.endswith("." + d)):
            print(name)
' "$d" >> "$WORK/raw_subs.txt"
done <<< "$DOMAINS"

# ---- 3. archive / wayback (gau) --------------------------------------------
while IFS= read -r d; do
    [ -z "$d" ] && continue
    echo "[enum] archive: $d"
    timeout 300 gau --subs --threads 4 \
        --blacklist png,jpg,jpeg,gif,svg,css,js,woff,woff2,eot,ttf,ico,pdf \
        "$d" 2>/dev/null \
        | grep -Eo 'https?://[^/:?">]+' \
        | sed 's#https\?://##' \
        | grep -Ei "(^|\.)${d//./\\.}$" >> "$WORK/raw_subs.txt"
done <<< "$DOMAINS"

# ---- 4. normalize + dedupe --------------------------------------------------
python3 - "$WORK/raw_subs.txt" domains.txt > "$WORK/subs_norm.txt" <<'PY'
import re, sys

raw_path, domains_path = sys.argv[1], sys.argv[2]
roots = []
for line in open(domains_path):
    d = line.split("#")[0].strip().lower().rstrip(".")
    if d:
        roots.append(d)
seen = set()
for line in open(raw_path):
    h = line.strip().lower().rstrip(".")
    if not h or len(h) > 253 or "*" in h or " " in h:
        continue
    if not re.fullmatch(r"[a-z0-9._-]+", h):
        continue
    if h not in roots and not any(h.endswith("." + r) for r in roots):
        continue
    seen.add(h)
for h in sorted(seen):
    print(h)
PY
echo "[enum] normalized candidates: $(wc -l < "$WORK/subs_norm.txt")"

# ---- 5. brute force (dnsx A-resolution) -------------------------------------
# puredns/massdns was dropped: massdns ships no release binaries and puredns
# fails silently without it. dnsx handles the volume fine, and wildcard noise
# is harmless downstream - only CNAME-bearing names can trigger findings.
: > "$WORK/brute_alive.txt"
while IFS= read -r d; do
    [ -z "$d" ] && continue
    echo "[enum] brute force: $d"
    grep -E '^[A-Za-z0-9_-]+$' "$BRUTE_WORDLIST" | sed "s/$/.${d}/" \
        > "$WORK/brute_candidates_$d.txt"
    timeout 600 dnsx -l "$WORK/brute_candidates_$d.txt" -a -resp -silent -threads 250 \
        -retry 1 -timeout 3 -r "$RESOLVERS_FILE" -o "$WORK/brute_$d.txt" 2>/dev/null
    [ -f "$WORK/brute_$d.txt" ] \
        && cut -d' ' -f1 "$WORK/brute_$d.txt" | sed 's/\.$//' >> "$WORK/brute_alive.txt"
done <<< "$DOMAINS"
echo "[enum] brute-force hits: $(wc -l < "$WORK/brute_alive.txt" 2>/dev/null || echo 0)"

# ---- 6. permutations --------------------------------------------------------
python3 scripts/perms.py "$WORK/subs_norm.txt" "$PERM_CAP" > "$WORK/perms.txt" 2>/dev/null
echo "[enum] permutations: $(wc -l < "$WORK/perms.txt" 2>/dev/null || echo 0)"

# ---- 7. merge everything ----------------------------------------------------
sort -u "$WORK/subs_norm.txt" "$WORK/brute_alive.txt" "$WORK/perms.txt" 2>/dev/null \
    | grep -v '^$' > data/subs-latest.txt
echo "[enum] total candidate universe: $(wc -l < data/subs-latest.txt)"

# ---- 8. CNAME capture over the full universe --------------------------------
# dnsx (NOT puredns/massdns A-resolution) because a dangling CNAME often has
# no A record at all - A-only resolvers would silently drop takeover targets.
# A hard 15-min ceiling keeps the whole job well under the 35-min workflow
# timeout even on junk-heavy targets; a partial CNAME map is fine - scan.py
# only checks what's actually in it.
timeout 900 dnsx -l data/subs-latest.txt -cname -a -resp -silent -threads 250 \
    -retry 1 -timeout 3 -r "$RESOLVERS_FILE" -o data/cnames.txt 2>/dev/null
echo "[enum] CNAME records captured: $(wc -l < data/cnames.txt 2>/dev/null || echo 0)"

echo "[enum] done"
