"""Translation of Lua patterns into RE2."""

import unittest

from nse2pack.luapat import Untranslatable, translate


class TestClasses(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(translate("%d+").pattern, "[0-9]+")
        self.assertEqual(translate("%a").pattern, "[A-Za-z]")
        self.assertEqual(translate("%w").pattern, "[0-9A-Za-z]")
        self.assertEqual(translate("%x").pattern, "[0-9A-Fa-f]")
        self.assertEqual(translate("%D").pattern, "[^0-9]")

    def test_class_inside_set(self):
        self.assertEqual(translate("[%d.]+").pattern, "[0-9.]+")

    def test_negated_class_inside_set_is_refused(self):
        with self.assertRaises(Untranslatable):
            translate("[%D]")

    def test_escaped_magic(self):
        self.assertEqual(translate("%.").pattern, "\\.")
        self.assertEqual(translate("%%").pattern, "%")


class TestQuantifiers(unittest.TestCase):
    def test_lazy_dash(self):
        # '-' after an atom is Lua's lazy quantifier, not a literal.
        self.assertEqual(translate("a-b").pattern, "a*?b")

    def test_leading_dash_is_literal(self):
        self.assertEqual(translate("-a").pattern, "-a")

    def test_dash_inside_set_is_a_range(self):
        self.assertEqual(translate("[a-z]").pattern, "[a-z]")


class TestDot(unittest.TestCase):
    def test_dot_gets_dotall(self):
        # In Lua '.' matches a newline too; in RE2 only under (?s).
        result = translate("a.b")
        self.assertTrue(result.dotall)
        self.assertEqual(result.pattern, "(?s)a.b")

    def test_escaped_dot_stays_literal(self):
        self.assertFalse(translate("a%.b").dotall)


class TestGoMagicCharacters(unittest.TestCase):
    def test_braces_and_pipe_are_literal_in_lua(self):
        self.assertEqual(translate("a{2}|b").pattern, "a\\{2\\}\\|b")

    def test_backslash_is_literal_in_lua(self):
        self.assertEqual(translate("a\\b").pattern, "a\\\\b")


class TestAnchors(unittest.TestCase):
    def test_anchors_only_at_the_edges(self):
        self.assertEqual(translate("^220 ").pattern, "^220 ")
        self.assertEqual(translate("a^b").pattern, "a\\^b")
        self.assertEqual(translate("a$b").pattern, "a\\$b")
        self.assertEqual(translate("ok$").pattern, "ok$")


class TestCaptures(unittest.TestCase):
    def test_group_count(self):
        self.assertEqual(translate("v([%d.]+)").groups, 1)
        self.assertEqual(translate("(%d+)%.(%d+)").groups, 2)

    def test_position_capture_is_refused(self):
        with self.assertRaises(Untranslatable):
            translate("()abc")


class TestRefusals(unittest.TestCase):
    def test_balanced_match(self):
        with self.assertRaises(Untranslatable):
            translate("%b<>")

    def test_frontier(self):
        with self.assertRaises(Untranslatable):
            translate("%f[%w]word")

    def test_backreference(self):
        with self.assertRaises(Untranslatable):
            translate("(a)%1")

    def test_empty(self):
        with self.assertRaises(Untranslatable):
            translate("")

    def test_unbalanced(self):
        with self.assertRaises(Untranslatable):
            translate("(abc")


class TestWorkedExample(unittest.TestCase):
    def test_acarsd_greedy_capture(self):
        # Lua's '.' swallows newlines, so an honest translation must carry (?s)
        # rather than pretend to be a Go dot. Writing `acarsd\t(.+)\t` as a Go
        # regexp would let a greedy capture run past the right delimiter.
        result = translate("acarsd\t(.-)\t")
        self.assertEqual(result.pattern, "(?s)acarsd\t(.*?)\t")
        self.assertEqual(result.groups, 1)
