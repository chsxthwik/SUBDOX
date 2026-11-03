import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import scan  # noqa: E402


class ParseFingerprint(unittest.TestCase):
    def test_nxdomain(self):
        self.assertEqual(scan.parse_fingerprint("NXDOMAIN"), ("nxdomain", None))

    def test_http_status(self):
        self.assertEqual(scan.parse_fingerprint("HTTP_STATUS=404"), ("http_status", 404))

    def test_body(self):
        self.assertEqual(
            scan.parse_fingerprint("There isn't a GitHub Pages site here."),
            ("body", "There isn't a GitHub Pages site here."),
        )

    def test_empty(self):
        self.assertEqual(scan.parse_fingerprint(None), ("body", ""))


class BodyMatch(unittest.TestCase):
    def test_match_case_insensitive(self):
        self.assertTrue(scan.body_match("The specified bucket does not exist", "<Message>the Specified Bucket does not exist</Message>"))

    def test_generic_alternative_never_matches(self):
        self.assertFalse(scan.body_match("404 Not Found", "404 Not Found"))

    def test_alternatives(self):
        raw = "The specified bucket does not exist|There isn't a GitHub Pages site here"
        self.assertTrue(scan.body_match(raw, "<p>There isn't a GitHub Pages site here.</p>"))
        self.assertFalse(scan.body_match(raw, "all good"))

    def test_short_fingerprints_are_generic(self):
        self.assertTrue(scan.is_generic_body("NoSuchBucket"))
        self.assertFalse(scan.is_generic_body("The specified bucket does not exist"))

    def test_empty_body(self):
        self.assertFalse(scan.body_match("anything long enough here", ""))


class CnameSuffix(unittest.TestCase):
    def test_suffix(self):
        self.assertTrue(
            scan.cname_suffix_match(["github.io"], ["org.github.io"], set())
        )

    def test_no_partial_label_match(self):
        self.assertFalse(
            scan.cname_suffix_match(["github.io"], ["evilgithub.io"], set())
        )

    def test_ip_entry(self):
        self.assertTrue(scan.cname_suffix_match(["1.2.3.4"], [], {"1.2.3.4"}))
        self.assertFalse(scan.cname_suffix_match(["1.2.3.4"], [], {"5.6.7.8"}))


class ParseDnsx(unittest.TestCase):
    def test_parse(self):
        lines = (
            "a.example.com [\x1b[35mCNAME\x1b[0m] [\x1b[32mfoo.github.io\x1b[0m]\n"
            "a.example.com [\x1b[35mA\x1b[0m] [\x1b[32m1.2.3.4\x1b[0m]\n"
            "garbage line\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(lines)
            path = f.name
        try:
            cnames, a_map, found = scan.parse_dnsx(path)
        finally:
            os.unlink(path)
        self.assertTrue(found)
        self.assertEqual(cnames, {"a.example.com": ["foo.github.io"]})
        self.assertEqual(a_map, {"a.example.com": ["1.2.3.4"]})

    def test_missing_file(self):
        self.assertEqual(scan.parse_dnsx("/nonexistent/x"), ({}, {}, False))


class State(unittest.TestCase):
    def test_track_subs(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(scan, "DATA_DIR", d), mock.patch.object(
                scan, "DB_PATH", os.path.join(d, "state.db")
            ):
                db = scan.open_db()
                self.assertEqual(scan.track_subs(db, ["a.x.com", "b.x.com"], "t1"), ["a.x.com", "b.x.com"])
                self.assertEqual(scan.track_subs(db, ["a.x.com", "c.x.com"], "t2"), ["c.x.com"])
                row = db.execute("SELECT first_seen, last_seen FROM subs WHERE host='a.x.com'").fetchone()
                self.assertEqual(row, ("t1", "t2"))
                db.close()


class Resolve(unittest.TestCase):
    def test_targets_resolved_once(self):
        calls = []

        def fake(t):
            calls.append(t)
            return True, []

        with mock.patch.object(scan, "target_state", fake):
            out = scan.resolve_targets({"a": ["t.io"], "b": ["t.io", "u.io"]})
        self.assertEqual(sorted(calls), ["t.io", "u.io"])
        self.assertEqual(out["t.io"], (True, []))


class Format(unittest.TestCase):
    def test_format(self):
        text = scan.format_finding(
            {"severity": "high", "subdomain": "a.x.com", "service": "S", "cname": "c", "evidence": "e"},
            "now",
        )
        self.assertTrue(text.startswith("[TAKEOVER] a.x.com"))
        self.assertIn("CNAME: c", text)


class Perms(unittest.TestCase):
    def run_perms(self, *extra):
        with tempfile.TemporaryDirectory() as d:
            subs = os.path.join(d, "subs.txt")
            with open(subs, "w") as f:
                f.write("api.example.co.uk\nwww.example.co.uk\n")
            doms = os.path.join(d, "domains.txt")
            with open(doms, "w") as f:
                f.write("# comment\nexample.co.uk\n")
            args = [sys.executable, os.path.join(ROOT, "scripts", "perms.py"), subs, "50"]
            if extra:
                args.append(doms)
            return subprocess.run(args, capture_output=True, text=True, check=True).stdout.split()

    def test_uses_domains_file_roots(self):
        out = self.run_perms("domains")
        self.assertTrue(out)
        self.assertTrue(all(h.endswith(".example.co.uk") for h in out))

    def test_fallback_roots(self):
        out = self.run_perms()
        self.assertTrue(all(h.endswith(".co.uk") for h in out))


class Fingerprints(unittest.TestCase):
    def test_snapshot_is_valid(self):
        import json

        with open(os.path.join(ROOT, "fingerprints.json")) as f:
            data = json.load(f)
        self.assertGreaterEqual(len(data), 40)
        for e in data:
            self.assertIn("service", e)
            self.assertIn("fingerprint", e)


if __name__ == "__main__":
    unittest.main()
