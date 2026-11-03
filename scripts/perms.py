#!/usr/bin/env python3
"""
Generate level-1 permutations of known subdomains:
  dev.target.com, dev-api.target.com, api-dev.target.com, ...

Usage: perms.py <subs-file> <cap> [domains-file]
Prints one candidate per line. With a domains file, candidates are built under
those exact roots; otherwise the last two labels of each host are used.
"""
import os
import re
import sys

WORDS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "wordlists", "perms-words.txt"
)


def load_roots(domains_path):
    """Root domains from domains.txt (comments and blanks ignored)."""
    roots = []
    with open(domains_path) as f:
        for line in f:
            d = line.split("#")[0].strip().lower().rstrip(".")
            if d:
                roots.append(d)
    return roots


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: perms.py <subs-file> <cap> [domains-file]")
    subs_path, cap = sys.argv[1], int(sys.argv[2])

    with open(WORDS_PATH) as f:
        tokens = [
            w.strip().lower()
            for w in f
            if w.strip() and not w.startswith("#")
        ]

    labels = set()
    with open(subs_path) as f:
        for line in f:
            host = line.strip().lower().rstrip(".")
            if not host or "." not in host:
                continue
            first = host.split(".", 1)[0]
            # skip junk labels: numeric, too short, already a perm token
            if len(first) < 2 or first.isdigit() or first in tokens:
                continue
            if not re.fullmatch(r"[a-z0-9-]+", first):
                continue
            labels.add(first)
            if len(labels) > 20000:
                break

    out = set()
    for label in sorted(labels):
        for tok in tokens:
            out.add(f"{tok}-{label}")
            out.add(f"{label}-{tok}")
        out.add(label)  # keep the bare label as a candidate too
    perms = sorted(out)[:cap]

    if len(sys.argv) > 3:
        roots = set(load_roots(sys.argv[3]))
    else:
        roots = set()
        with open(subs_path) as f:
            for line in f:
                parts = line.strip().lower().rstrip(".").split(".")
                if len(parts) >= 2:
                    roots.add(".".join(parts[-2:]))
    for root in sorted(roots):
        for tok in tokens:
            print(f"{tok}.{root}")
        for p in perms:
            print(f"{p}.{root}")


if __name__ == "__main__":
    main()
