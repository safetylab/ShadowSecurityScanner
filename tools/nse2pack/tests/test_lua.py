"""The Lua mini-parser: masking, block boundaries, call arguments."""

import unittest

from nse2pack.lua import block_end, call_args, find_calls, mask

SRC = '''
description = [[A long string with -- not a comment and an ( unbalanced paren]]
-- a real comment with ( and the word end in it
categories = {"safe", "discovery"}
action = function(host, port)
  local s = "a string holding end and ("
  for i = 1, 3 do
    if i == 2 then print(i) end
  end
  local r = http.get(host, port, "/x", {timeout = 5})
  return r
end
'''


class TestMask(unittest.TestCase):
    def setUp(self):
        self.masked, self.strings = mask(SRC)

    def test_length_is_preserved(self):
        self.assertEqual(len(self.masked), len(SRC))

    def test_comment_is_blanked(self):
        self.assertNotIn("a real comment", self.masked)

    def test_string_contents_are_blanked_but_quotes_stay(self):
        self.assertNotIn("a string holding", self.masked)
        self.assertIn('"', self.masked)

    def test_long_string_value(self):
        self.assertTrue(self.strings[0].value.startswith("A long string"))


class TestBlocks(unittest.TestCase):
    def test_block_end_ignores_end_in_strings_and_comments(self):
        masked, _ = mask(SRC)
        start = masked.index("action")
        end = block_end(masked, start)
        self.assertEqual(SRC[end - 3:end], "end")
        self.assertEqual(SRC[:end].count("function"), 1)


class TestCalls(unittest.TestCase):
    def test_arguments_are_split_at_top_level_only(self):
        masked, _ = mask(SRC)
        call = find_calls(SRC, masked, "http.get")[0]
        args = [SRC[a:b].strip() for a, b in call.args]
        self.assertEqual(args, ["host", "port", '"/x"', "{timeout = 5}"])

    def test_unclosed_call_is_skipped(self):
        text = "x = f(1, 2"
        masked, _ = mask(text)
        self.assertEqual(find_calls(text, masked, "f"), [])

    def test_nested_parens(self):
        text = 'y = g(h(1, 2), "a")'
        masked, _ = mask(text)
        call = find_calls(text, masked, "g")[0]
        self.assertEqual([text[a:b].strip() for a, b in call.args], ["h(1, 2)", '"a"'])
