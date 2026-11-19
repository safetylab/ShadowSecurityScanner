"""Reading an NSE script: header fields, portrule and the body of action."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .lua import StringLiteral, block_end, mask

__all__ = ["NseScript", "parse", "parse_text"]

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CWE = re.compile(r"CWE-\d{1,4}", re.I)


@dataclass
class NseScript:
    path: Path
    name: str
    text: str
    masked: str
    strings: list[StringLiteral]
    description: str = ""
    categories: list[str] = field(default_factory=list)
    author: str = ""
    portrule: str = ""
    has_portrule: bool = False
    has_hostrule: bool = False
    action_lo: int = -1
    action_hi: int = -1

    # -- handy slices -----------------------------------------------------
    @property
    def action(self) -> str:
        return "" if self.action_lo < 0 else self.text[self.action_lo:self.action_hi]

    @property
    def action_masked(self) -> str:
        return "" if self.action_lo < 0 else self.masked[self.action_lo:self.action_hi]

    def literal_at(self, lo: int, hi: int) -> str | None:
        """The value of a string literal, when the slice is exactly one literal."""
        chunk = self.text[lo:hi].strip()
        if not chunk:
            return None
        for s in self.strings:
            if s.start >= lo and s.end <= hi and self.text[lo:s.start].strip() == "" \
                    and self.text[s.end:hi].strip() == "":
                return s.value
        return None

    def literals_in(self, lo: int, hi: int) -> list[str]:
        return [s.value for s in self.strings if s.start >= lo and s.end <= hi]

    @property
    def cves(self) -> list[str]:
        seen: dict[str, None] = {}
        for m in _CVE.finditer(self.text):
            seen.setdefault(m.group(0).upper(), None)
        return list(seen)

    @property
    def cwes(self) -> list[str]:
        seen: dict[str, None] = {}
        for m in _CWE.finditer(self.text):
            seen.setdefault(m.group(0).upper(), None)
        return list(seen)


def _assignment(masked: str, name: str) -> tuple[int, int] | None:
    """Boundaries of the value in a top-level ``name = …`` assignment."""
    pattern = re.compile(r"^[ \t]*" + re.escape(name) + r"[ \t]*=[ \t]*", re.M)
    m = pattern.search(masked)
    if not m:
        return None
    start = m.end()
    rest = masked[start:]
    head = rest.lstrip()
    offset = start + (len(rest) - len(head))
    if head.startswith("function"):
        return offset, block_end(masked, offset)
    if head.startswith("["):
        return offset, _long_string_end(masked, offset)
    if head.startswith("{"):
        depth = 0
        for i in range(offset, len(masked)):
            if masked[i] == "{":
                depth += 1
            elif masked[i] == "}":
                depth -= 1
                if depth == 0:
                    return offset, i + 1
        return offset, len(masked)
    end = masked.find("\n", offset)
    return offset, len(masked) if end < 0 else end


def _long_string_end(masked: str, offset: int) -> int:
    """End of a long ``[[…]]`` / ``[==[…]==]`` string — it does not end with the line."""
    m = re.match(r"\[(=*)\[", masked[offset:])
    if not m:
        end = masked.find("\n", offset)
        return len(masked) if end < 0 else end
    close = "]" + m.group(1) + "]"
    end = masked.find(close, offset + m.end())
    return len(masked) if end < 0 else end + len(close)


def parse_text(text: str, name: str, path: Path | None = None) -> NseScript:
    masked, strings = mask(text)
    s = NseScript(path=path or Path(name + ".nse"), name=name, text=text,
                  masked=masked, strings=strings)

    span = _assignment(masked, "description")
    if span:
        lit = s.literal_at(*span)
        s.description = " ".join((lit or "").split())

    span = _assignment(masked, "categories")
    if span:
        s.categories = [v.strip().lower() for v in s.literals_in(*span) if v.strip()]

    span = _assignment(masked, "author")
    if span:
        s.author = " ".join(s.literals_in(*span))

    span = _assignment(masked, "portrule")
    if span:
        s.has_portrule = True
        s.portrule = text[span[0]:span[1]].strip()

    s.has_hostrule = _assignment(masked, "hostrule") is not None

    span = _assignment(masked, "action")
    if span:
        s.action_lo, s.action_hi = span

    return s


def parse(path: Path) -> NseScript:
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_text(text, path.stem, path)
