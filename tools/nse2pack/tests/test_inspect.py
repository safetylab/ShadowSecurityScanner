"""--check: inspecting a pack that already exists."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from nse2pack.cli import main

def _find_examples():
    """The reference packs, wherever they sit in the repository."""
    for parent in Path(__file__).resolve().parents:
        for candidate in (parent / "examples",
                          parent / "docs" / "check-pack" / "examples"):
            if (candidate / "refusals.json").is_file():
                return candidate
    return Path("examples")


EXAMPLES = _find_examples()
FIXTURES = Path(__file__).resolve().parent / "fixtures"

GOOD = {
    "source": "demo", "version": 1, "api": 1,
    "plugin": {"id": "pack-demo", "name": "Demo", "category": "web"},
    "checks": [
        {"id": "a", "match": {"service": "http"},
         "steps": [{"http": {"path": "/x"}, "expect": {"body_all": ["MARKER-LONG"]}}],
         "finding": {"title": "t"}},
        {"id": "b", "match": {"service": "ftp", "ports": [21]},
         "steps": [{"tcp": {"send_b64": "", "recv_max": 256},
                    "expect": {"re": ["^220 "]}}],
         "detect": {"product": "vsftpd"}},
    ],
}


def check(*args) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(["--check", *args])
    return code, buffer.getvalue()


class TestCheck(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, pack: dict, name: str = "pack.json") -> Path:
        path = self.dir / name
        path.write_text(json.dumps(pack), encoding="utf-8")
        return path

    def test_a_good_pack_is_accepted(self):
        code, out = check(str(self._write(GOOD)))
        self.assertEqual(code, 0)
        self.assertIn("2 accepted, 0 dropped", out)

    def test_routing_is_reported(self):
        code, out = check(str(self._write(GOOD)))
        self.assertIn('1 check(s) inside the web sweep', out)
        self.assertIn("1 under this pack's own row", out)

    def test_verbose_prints_a_plan(self):
        code, out = check(str(self._write(GOOD)), "-v")
        self.assertIn("when service http → GET /x", out)
        self.assertIn("detect vsftpd", out)

    def test_unknown_field_refuses_the_whole_pack(self):
        pack = dict(GOOD, typo=1)
        code, out = check(str(self._write(pack)))
        self.assertEqual(code, 1)
        self.assertIn("the whole pack is refused", out)

    def test_duplicate_ids_are_caught(self):
        pack = json.loads(json.dumps(GOOD))
        pack["checks"][1]["id"] = "a"
        code, out = check(str(self._write(pack)), "--strict")
        self.assertEqual(code, 1)
        self.assertIn("appears 2 times", out)

    def test_broken_json_is_reported_not_raised(self):
        path = self.dir / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        code, out = check(str(path))
        self.assertEqual(code, 1)
        self.assertIn("cannot be read as a pack", out)

    def test_missing_file(self):
        code, out = check(str(self.dir / "nope.json"))
        self.assertEqual(code, 2)

    @unittest.skipUnless(EXAMPLES.is_dir(), "no examples/ directory alongside")
    def test_reference_refusals_are_all_dropped(self):
        code, out = check(str(EXAMPLES / "refusals.json"), "--strict")
        self.assertEqual(code, 1)
        self.assertIn("0 accepted, 9 dropped", out)

    def test_round_trip_from_conversion(self):
        out_dir = self.dir / "out"
        self.assertEqual(main([str(FIXTURES), "-o", str(out_dir), "--quiet"]), 0)
        packs = sorted(p for p in out_dir.glob("*.json") if p.name != "report.json")
        self.assertTrue(packs)
        code, out = check(*[str(p) for p in packs], "--strict")
        self.assertEqual(code, 0, out)
        self.assertNotIn("dropped", out.replace("0 dropped", ""))
