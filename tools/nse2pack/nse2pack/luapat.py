"""Translation of Lua patterns into RE2 (Go syntax) regular expressions.

A Lua pattern is not a regular expression. The differences that stop you from
copying a pattern straight out of a script into an ``re`` field:

* classes are written with ``%``: ``%d``, ``%a``, ``%w``, ``%s``, ``%x``…;
* ``-`` after an atom is a lazy quantifier, not a literal and not a range;
* ``.`` matches a newline in Lua but not in RE2, which needs ``(?s)``;
* ``^`` and ``$`` are magic only at the very start and end of the pattern;
* ``{``, ``}``, ``|`` and ``\\`` are ordinary characters in Lua, metacharacters in RE2;
* ``%b``, ``%f`` and the position capture ``()`` have no RE2 equivalent at all.

Anything untranslatable raises :class:`Untranslatable`: the check must be
dropped with a clear reason rather than emitted as a pack that will not compile.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["Untranslatable", "Translated", "translate", "is_re2_safe"]


class Untranslatable(Exception):
    """The pattern has no RE2 equivalent."""


@dataclass(frozen=True)
class Translated:
    pattern: str   # the finished RE2 expression
    groups: int    # number of capturing groups
    dotall: bool   # the (?s) flag was needed


# Class contents, in a form that can be pasted inside [...].
_CLASS_IN = {
    "d": "0-9",
    "a": "A-Za-z",
    "w": "0-9A-Za-z",
    "s": r"\t\n\v\f\r ",
    "l": "a-z",
    "u": "A-Z",
    "x": "0-9A-Fa-f",
    "p": r"!-/:-@\[-`{-~",
    "c": r"\x00-\x1f\x7f",
    "g": "!-~",
}
_CLASS_OUT = {k: "[" + v + "]" for k, v in _CLASS_IN.items()}
_CLASS_OUT_NEG = {k.upper(): "[^" + v + "]" for k, v in _CLASS_IN.items()}

_RE2_MAGIC = set(r"\.+*?()|[]{}^$")
_RE2_MAGIC_IN_SET = set(r"\]^")


def _esc(ch: str) -> str:
    return "\\" + ch if ch in _RE2_MAGIC else ch


def _esc_in_set(ch: str) -> str:
    return "\\" + ch if ch in _RE2_MAGIC_IN_SET else ch


def translate(pat: str) -> Translated:
    """Translates a Lua pattern into an RE2 expression.

    :raises Untranslatable: when there is no equivalent.
    """
    if pat == "":
        raise Untranslatable("an empty pattern matches every reply")

    out: list[str] = []
    i, n = 0, len(pat)
    groups = 0
    depth = 0
    dotall = False
    in_set = False
    prev_atom = False  # was there an atom to the left — for '-' as a lazy quantifier

    while i < n:
        ch = pat[i]

        # --- inside a [set] -----------------------------------------------
        if in_set:
            if ch == "%":
                if i + 1 >= n:
                    raise Untranslatable("the pattern ends on a '%'")
                c = pat[i + 1]
                if c in _CLASS_IN:
                    out.append(_CLASS_IN[c])
                elif c.lower() in _CLASS_IN and c.isupper():
                    raise Untranslatable(
                        "the complement class %%%s cannot be expressed inside [...]" % c
                    )
                elif c in "bf":
                    raise Untranslatable("%%%s makes no sense inside [...]" % c)
                elif c.isdigit():
                    raise Untranslatable("back-reference %%%s is not supported by RE2" % c)
                elif c.isalpha():
                    raise Untranslatable("unknown class %%%s" % c)
                else:
                    out.append(_esc_in_set(c))
                i += 2
                continue
            if ch == "]":
                in_set = False
                out.append("]")
                prev_atom = True
                i += 1
                continue
            out.append(_esc_in_set(ch))
            i += 1
            continue

        # --- outside a set --------------------------------------------------
        if ch == "%":
            if i + 1 >= n:
                raise Untranslatable("the pattern ends on a '%'")
            c = pat[i + 1]
            if c in _CLASS_OUT:
                out.append(_CLASS_OUT[c])
            elif c in _CLASS_OUT_NEG:
                out.append(_CLASS_OUT_NEG[c])
            elif c == "b":
                raise Untranslatable("%b matches a balanced pair, which RE2 cannot express")
            elif c == "f":
                raise Untranslatable("%f is a frontier pattern, which RE2 cannot express")
            elif c.isdigit():
                raise Untranslatable("back-reference %%%s is not supported by RE2" % c)
            elif c.isalpha():
                raise Untranslatable("unknown class %%%s" % c)
            else:
                out.append(_esc(c))
            prev_atom = True
            i += 2
            continue

        if ch == "[":
            out.append("[")
            i += 1
            if i < n and pat[i] == "^":
                out.append("^")
                i += 1
            if i < n and pat[i] == "]":      # ']' as the first character is a literal
                out.append("\\]")
                i += 1
            in_set = True
            continue

        if ch == "(":
            if i + 1 < n and pat[i + 1] == ")":
                raise Untranslatable("a position capture '()' cannot be expressed in RE2")
            groups += 1
            depth += 1
            out.append("(")
            prev_atom = False
            i += 1
            continue

        if ch == ")":
            depth -= 1
            if depth < 0:
                raise Untranslatable("unmatched ')'")
            out.append(")")
            prev_atom = True
            i += 1
            continue

        if ch == ".":
            dotall = True            # in Lua '.' matches \n as well
            out.append(".")
            prev_atom = True
            i += 1
            continue

        if ch == "-":
            if prev_atom:
                out.append("*?")     # Lua's lazy quantifier
                prev_atom = False
            else:
                out.append("-")
                prev_atom = True
            i += 1
            continue

        if ch in "*+?":
            if not prev_atom:
                raise Untranslatable("quantifier %r has no atom to its left" % ch)
            out.append(ch)
            prev_atom = False
            i += 1
            continue

        if ch == "^":
            if i == 0:
                out.append("^")
                prev_atom = False
            else:
                out.append("\\^")
                prev_atom = True
            i += 1
            continue

        if ch == "$":
            if i == n - 1:
                out.append("$")
                prev_atom = False
            else:
                out.append("\\$")
                prev_atom = True
            i += 1
            continue

        out.append(_esc(ch))
        prev_atom = True
        i += 1

    if in_set:
        raise Untranslatable("unclosed set '['")
    if depth != 0:
        raise Untranslatable("unclosed group '('")

    pattern = "".join(out)
    if dotall:
        pattern = "(?s)" + pattern

    # The Python engine is not RE2, but it catches the same syntax errors.
    try:
        compiled = re.compile(pattern)
    except re.error as exc:                      # pragma: no cover - guard
        raise Untranslatable("the translation does not compile: %s" % exc) from exc
    if compiled.groups != groups:                # pragma: no cover - guard
        raise Untranslatable("the translation changed the number of capturing groups")

    return Translated(pattern=pattern, groups=groups, dotall=dotall)


_LOOKAROUND = re.compile(r"\(\?[=!<]")
_BACKREF = re.compile(r"\\[1-9]")


def is_re2_safe(pattern: str) -> bool:
    """Whether the finished expression stays within what RE2 supports."""
    return not (_LOOKAROUND.search(pattern) or _BACKREF.search(pattern))
