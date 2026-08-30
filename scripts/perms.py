#!/usr/bin/env python3
"""
Generate level-1 permutations of known subdomains:
  dev.target.com, dev-api.target.com, api-dev.target.com, ...

stdin/args: subs file, cap. Prints one candidate per line.
"""
import re
import sys

WORDS_PATH = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "..", "wordlists", "perms-words.txt"
)


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: perms.py <subs-file> <cap>")
    subs_path, cap = sys.argv[1], int(sys.argv[2])

    with open(WORDS_PATH) as f:
        tokens = [
            w.strip().lower()
            for w in f
            if w.strip() and not w.startswith("#")
        ]

    labels = set()
    for line in open(subs_path):
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

    roots = set()
    for line in open(subs_path):
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
