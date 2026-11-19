"""The compiler rules, checked against the reference corpus in examples/.

`refusals.json` in the materials repository holds nine deliberately invalid
checks, each with its own reason for refusal; the other packs, by their own
statement, compile without a single dropped check. That is an external measure
of this validator: it must refuse exactly the first and accept exactly the rest.
"""

import json
import unittest
from pathlib import Path

from nse2pack.validate import ROUTE_OWN, ROUTE_SWEEP, route_of, validate_check, validate_pack

def _find_examples():
    """The reference packs, wherever they sit in the repository."""
    for parent in Path(__file__).resolve().parents:
        for candidate in (parent / "examples",
                          parent / "docs" / "check-pack" / "examples"):
            if (candidate / "refusals.json").is_file():
                return candidate
    return Path("examples")


EXAMPLES = _find_examples()
CLEAN = ["template.json", "every-shape.json", "nmap-acarsd-info.json",
         "demo-three-checks.json", "my-cheks-tcp.json", "my-cheks-web.json"]


@unittest.skipUnless(EXAMPLES.is_dir(), "no examples/ directory alongside")
class TestReferenceCorpus(unittest.TestCase):
    def test_every_refusal_is_caught(self):
        pack = json.loads((EXAMPLES / "refusals.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_pack(pack), [])
        for check in pack["checks"]:
            with self.subTest(check=check["id"]):
                self.assertTrue(validate_check(check),
                                "check %s should have been refused" % check["id"])

    def test_good_packs_are_accepted(self):
        for name in CLEAN:
            path = EXAMPLES / name
            if not path.is_file():
                continue
            pack = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(pack=name):
                errors = validate_pack(pack)
                for check in pack["checks"]:
                    errors += validate_check(check)
                self.assertEqual(errors, [])


class TestRules(unittest.TestCase):
    def _check(self, **over):
        check = {"id": "x", "match": {"service": "http"},
                 "steps": [{"http": {"path": "/x"}, "expect": {"body_any": ["marker"]}}],
                 "finding": {"title": "t"}}
        check.update(over)
        return check

    def test_unknown_field_is_an_error(self):
        self.assertTrue(any("unknown field" in e
                            for e in validate_check(self._check(typo=1))))

    def test_empty_expectation(self):
        check = self._check(steps=[{"http": {"path": "/x"}, "expect": {}}])
        self.assertIn("an expectation that asserts nothing would match every reply",
                      validate_check(check))

    def test_lookahead_is_rejected_although_python_accepts_it(self):
        check = self._check(steps=[{"http": {"path": "/x"},
                                    "expect": {"re": ["(?=secret)"]}}])
        self.assertTrue(any("Perl syntax" in e for e in validate_check(check)))

    def test_placeholder_needs_an_earlier_capture(self):
        check = self._check(steps=[{"http": {"path": "/a?t={{tok}}"},
                                    "expect": {"body_any": ["marker"]}}])
        self.assertTrue(any("references capture" in e for e in validate_check(check)))

    def test_capture_needs_exactly_one_group(self):
        check = self._check(steps=[
            {"http": {"path": "/a"}, "expect": {"body_any": ["marker"]},
             "capture": [{"as": "tok", "re": "(a)(b)"}]},
            {"http": {"path": "/b?t={{tok}}"}, "expect": {"body_any": ["marker"]}}])
        self.assertTrue(any("need exactly 1" in e for e in validate_check(check)))

    def test_nine_steps_exceed_the_limit(self):
        step = {"http": {"path": "/x"}, "expect": {"body_any": ["marker"]}}
        self.assertTrue(any("the limit is 8" in e
                            for e in validate_check(self._check(steps=[step] * 9))))


class TestRoute(unittest.TestCase):
    def test_single_get_goes_into_the_sweep(self):
        check = {"steps": [{"http": {"path": "/x"}, "expect": {}}]}
        self.assertEqual(route_of(check)[0], ROUTE_SWEEP)

    def test_other_method_gets_its_own_row(self):
        check = {"steps": [{"http": {"path": "/x", "method": "OPTIONS"}, "expect": {}}]}
        route, why = route_of(check)
        self.assertEqual(route, ROUTE_OWN)
        self.assertIn("OPTIONS", why)

    def test_byte_transport_gets_its_own_row(self):
        check = {"steps": [{"tcp": {"send_b64": ""}, "expect": {}}]}
        self.assertEqual(route_of(check)[0], ROUTE_OWN)
