"""The little bit of Lua parsing that reading an NSE script needs.

A real interpreter is out of the question, and unnecessary: the check-pack
format only ever takes a few shapes of script. Exactly three things are needed —

1. get strings and comments out of the way, so that searching the code does not
   trip over brackets and keywords inside literals;
2. find the end of a ``function … end`` block;
3. split a call's argument list and tell a string literal from a variable.

One trick runs through the module: ``mask`` returns text of the same length with
the contents of strings and comments blanked out. Structure is found in the
masked text, values are read from the original at the same offsets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "StringLiteral", "mask", "block_end", "call_args", "find_calls",
    "Call", "statement_start", "line_of",
]


@dataclass(frozen=True)
class StringLiteral:
    start: int     # index of the opening quote in the original text
    end: int       # index just past the closing one
    value: str     # the decoded value


_LONG_OPEN = re.compile(r"\[(=*)\[")

_SHORT_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
    "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'", "\n": "\n",
}


def _unescape(raw: str) -> str:
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            break
        nxt = raw[i + 1]
        if nxt in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[nxt])
            i += 2
        elif nxt == "x":
            out.append(chr(int(raw[i + 2:i + 4], 16)))
            i += 4
        elif nxt == "z":
            i += 2
            while i < n and raw[i].isspace():
                i += 1
        elif nxt.isdigit():
            j = i + 1
            digits = ""
            while j < n and raw[j].isdigit() and len(digits) < 3:
                digits += raw[j]
                j += 1
            out.append(chr(int(digits)))
            i = j
        else:
            out.append(nxt)
            i += 2
    return "".join(out)


def mask(text: str) -> tuple[str, list[StringLiteral]]:
    """Text of the same length without string or comment contents, plus the strings."""
    out = list(text)
    strings: list[StringLiteral] = []
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]

        if ch == "-" and text.startswith("--", i):
            m = _LONG_OPEN.match(text, i + 2)
            if m:                                   # long comment
                close = "]" + m.group(1) + "]"
                end = text.find(close, m.end())
                end = n if end < 0 else end + len(close)
                blank(i, end)
                i = end
            else:                                   # line comment
                end = text.find("\n", i)
                end = n if end < 0 else end
                blank(i, end)
                i = end
            continue

        if ch in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch or text[j] == "\n":
                    break
                j += 1
            value = _unescape(text[i + 1:j])
            end = min(j + 1, n)
            strings.append(StringLiteral(i, end, value))
            blank(i + 1, j)
            i = end
            continue

        m = _LONG_OPEN.match(text, i)
        if m:                                       # long string [[...]]
            close = "]" + m.group(1) + "]"
            end = text.find(close, m.end())
            if end < 0:
                end, body_end = n, n
            else:
                body_end = end
                end = end + len(close)
            strings.append(StringLiteral(i, end, text[m.end():body_end]))
            blank(m.end(), body_end)
            i = end
            continue

        i += 1

    return "".join(out), strings


_WORD = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_OPENERS = {"function", "if", "do"}


def block_end(masked: str, start: int) -> int:
    """Index just past the ``end`` that closes the block opened at ``start``."""
    depth = 0
    for m in _WORD.finditer(masked, start):
        word = m.group(0)
        if word in _OPENERS:
            depth += 1
        elif word == "end":
            depth -= 1
            if depth == 0:
                return m.end()
    return len(masked)


def _match_paren(masked: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(masked)):
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def call_args(text: str, masked: str, open_idx: int) -> tuple[list[tuple[int, int]], int]:
    """Argument boundaries of a call and the index of its closing paren."""
    close = _match_paren(masked, open_idx)
    if close < 0:
        return [], -1
    inner = masked[open_idx + 1:close]
    args: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for i, ch in enumerate(inner):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append((open_idx + 1 + start, open_idx + 1 + i))
            start = i + 1
    if inner.strip():
        args.append((open_idx + 1 + start, open_idx + 1 + len(inner)))
    return [(a, b) for a, b in args], close


@dataclass(frozen=True)
class Call:
    name: str                       # the call as written: "http.get", "socket:send"
    start: int                      # index where the name begins
    open_idx: int                   # index of '('
    close_idx: int                  # index of ')'
    args: tuple[tuple[int, int], ...]


def find_calls(text: str, masked: str, name: str, lo: int = 0, hi: int | None = None) -> list[Call]:
    """Every call of ``name`` in the range. The name may be ``a.b`` or ``obj:meth``."""
    hi = len(masked) if hi is None else hi
    pattern = re.compile(r"(?<![A-Za-z_0-9])" + re.escape(name) + r"\s*\(")
    calls: list[Call] = []
    for m in pattern.finditer(masked, lo, hi):
        open_idx = m.end() - 1
        args, close = call_args(text, masked, open_idx)
        if close < 0:
            continue
        calls.append(Call(name, m.start(), open_idx, close, tuple(args)))
    return calls


def statement_start(masked: str, idx: int) -> int:
    """Start of the statement (line) that ``idx`` sits in."""
    nl = masked.rfind("\n", 0, idx)
    return nl + 1


def line_of(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    return text[start:len(text) if end < 0 else end]
