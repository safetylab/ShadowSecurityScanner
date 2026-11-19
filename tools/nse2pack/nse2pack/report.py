"""The report of what the converter did not translate.

§11 of the specification: "a check lost in silence is worse than one that is
missing: the pack looks complete while coverage is quietly smaller". The report
is therefore as much a part of the output as the pack itself.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

__all__ = ["write_reports", "summary_lines"]


def _group(skips: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for skip in skips:
        out.setdefault(skip["kind"], []).append(skip)
    return out


def write_reports(out_dir: Path, data: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")

    lines: list[str] = []
    add = lines.append
    add("# NSE → check-pack conversion report")
    add("")
    add("Generated %s" % data["generated"])
    add("")
    add("| | |")
    add("|---|---|")
    add("| scripts read | %d |" % data["scripts_read"])
    add("| converted into checks | %d |" % len(data["converted"]))
    add("| not converted | %d |" % len(data["skipped"]))
    add("| packs written | %d |" % len(data["packs"]))
    add("")

    if data["packs"]:
        add("## Packs")
        add("")
        add("| file | catalogue row | checks | in the web sweep | own row |")
        add("|---|---|---|---|---|")
        for pack in data["packs"]:
            add("| `%s` | `%s` | %d | %d | %d |" % (pack["file"], pack["plugin_id"],
                                                    pack["checks"], pack["sweep"], pack["own"]))
        add("")

    skipped = data["skipped"]
    if skipped:
        add("## Not converted")
        add("")
        for kind, items in sorted(_group(skipped).items(), key=lambda kv: -len(kv[1])):
            add("### %s — %d" % (kind, len(items)))
            add("")
            for item in sorted(items, key=lambda s: s["script"]):
                mark = " *(candidate for a second-level script)*" if item["script_candidate"] else ""
                add("- `%s.nse` — %s%s" % (item["script"], item["reason"], mark))
            add("")

    if data["converted"]:
        add("## Converted")
        add("")
        add("| script | check id | pack | route |")
        add("|---|---|---|---|")
        for item in data["converted"]:
            add("| `%s.nse` | `%s` | `%s` | %s |" % (item["script"], item["check_id"],
                                                     item["pack"], item["route"]))
        add("")

    md_path = out_dir / "report.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summary_lines(data: dict) -> list[str]:
    """Terminal summary, in the same spirit as what packcheck prints."""
    lines = []
    for pack in data["packs"]:
        lines.append("  %-28s %s — %d check%s (sweep: %d, own row: %d)"
                     % (pack["file"], pack["plugin_id"], pack["checks"],
                        "" if pack["checks"] == 1 else "s",
                        pack["sweep"], pack["own"]))
    kinds: dict[str, int] = {}
    for skip in data["skipped"]:
        kinds[skip["kind"]] = kinds.get(skip["kind"], 0) + 1
    lines.append("")
    lines.append("  scripts read:   %d" % data["scripts_read"])
    lines.append("  converted:      %d" % len(data["converted"]))
    lines.append("  not converted:  %d%s" % (
        len(data["skipped"]),
        (" (" + ", ".join("%s: %d" % kv for kv in sorted(kinds.items())) + ")") if kinds else ""))
    return lines
