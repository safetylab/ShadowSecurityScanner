"""The converter run end to end over the fixture directory."""

import json
import tempfile
import unittest
from pathlib import Path

from nse2pack.cli import main
from nse2pack.validate import validate_check, validate_pack

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# What the fixture set is expected to produce: what converts, what is refused and why.
EXPECT_CONVERTED = {
    "acarsd-info", "http-server-header", "vsftpd-banner",
    "http-config-backup", "snmp-sysdescr", "http-two-requests",
}
EXPECT_SKIPPED = {
    "http-brute": "exploitation",
    "http-vuln-cve2014-3704": "exploitation",
    "smb-os-discovery": "routing",
    "http-title": "untranslatable pattern",
    "http-git": "weak assertions",
}


def run(out: Path, *extra: str) -> int:
    return main([str(FIXTURES), "-o", str(out), "--source", "nse", "--quiet", *extra])


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)
        self.code = run(self.out, "--strict")
        self.report = json.loads((self.out / "report.json").read_text(encoding="utf-8"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_exit_code_is_clean(self):
        self.assertEqual(self.code, 0)

    def test_expected_scripts_convert(self):
        self.assertEqual({c["script"] for c in self.report["converted"]}, EXPECT_CONVERTED)

    def test_expected_scripts_are_refused_with_the_right_class(self):
        got = {s["script"]: s["kind"] for s in self.report["skipped"]}
        self.assertEqual(got, EXPECT_SKIPPED)

    def test_no_generation_errors(self):
        self.assertEqual([s for s in self.report["skipped"]
                          if s["kind"] == "generation error"], [])

    def test_every_pack_compiles_by_the_rules(self):
        for entry in self.report["packs"]:
            pack = json.loads((self.out / entry["file"]).read_text(encoding="utf-8"))
            with self.subTest(pack=entry["file"]):
                errors = validate_pack(pack)
                for check in pack["checks"]:
                    errors += validate_check(check)
                self.assertEqual(errors, [])

    def test_reports_are_written(self):
        self.assertTrue((self.out / "report.md").is_file())
        self.assertIn("Not converted", (self.out / "report.md").read_text(encoding="utf-8"))

    def test_ids_are_stable_and_output_deterministic(self):
        with tempfile.TemporaryDirectory() as second:
            run(Path(second))
            for entry in self.report["packs"]:
                first_text = (self.out / entry["file"]).read_text(encoding="utf-8")
                second_text = (Path(second) / entry["file"]).read_text(encoding="utf-8")
                self.assertEqual(first_text, second_text, entry["file"])

    def test_detect_is_preferred_over_an_invented_finding(self):
        packs = {e["file"]: json.loads((self.out / e["file"]).read_text(encoding="utf-8"))
                 for e in self.report["packs"]}
        checks = {c["id"]: c for pack in packs.values() for c in pack["checks"]}
        self.assertIn("detect", checks["acarsd-info"])
        self.assertNotIn("finding", checks["http-server-header"])

    def test_single_pack_mode(self):
        with tempfile.TemporaryDirectory() as single:
            run(Path(single), "--single")
            files = sorted(p.name for p in Path(single).glob("*.json"))
            self.assertEqual(files, ["nse-all.json", "report.json"])

    def test_min_marker_can_be_relaxed(self):
        with tempfile.TemporaryDirectory() as loose:
            run(Path(loose), "--min-marker", "5")
            report = json.loads((Path(loose) / "report.json").read_text(encoding="utf-8"))
            self.assertIn("http-git", {c["script"] for c in report["converted"]})
