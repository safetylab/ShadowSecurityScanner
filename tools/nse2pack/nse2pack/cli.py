"""The converter's command line: a directory of NSE scripts → check-packs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import build, inspect as pack_inspect, parser as nse_parser, \
    report as report_mod, validate

# The order in which a script's main category is picked for splitting into packs:
# one pack is one catalogue row, which the operator switches on and off.
PRIMARY_ORDER = ["vuln", "version", "discovery", "safe", "auth", "default",
                 "intrusive", "external", "broadcast"]

HTTP_DEFAULT_PORTS = [80, 443]
MAX_DEFAULT_PORTS = 32


def primary_category(categories: list[str]) -> str:
    for candidate in PRIMARY_ORDER:
        if candidate in categories:
            return candidate
    return categories[0] if categories else "misc"


def _pack_skeleton(source: str, version: int, category: str) -> dict:
    return {
        "source": source,
        "version": version,
        "api": 1,
        "plugin": {
            "id": "pack-%s-%s" % (source, category),
            "name": "NSE %s checks (converted)" % category,
            "category": "web",
            "protocols": ["tcp"],
            "default_ports": [],
        },
        "checks": [],
    }


def _finish_plugin(pack: dict, transports: set[str]) -> None:
    checks = pack["checks"]
    http_only = all("http" in step for check in checks for step in check["steps"])
    pack["plugin"]["category"] = "web" if http_only else "network"
    protocols = sorted(transports) or ["tcp"]
    pack["plugin"]["protocols"] = protocols
    ports: set[int] = set()
    for check in checks:
        for port in check["match"].get("ports") or []:
            ports.add(port)
    if not ports and http_only:
        ports = set(HTTP_DEFAULT_PORTS)
    if ports:
        pack["plugin"]["default_ports"] = sorted(ports)[:MAX_DEFAULT_PORTS]
    else:
        del pack["plugin"]["default_ports"]


def collect_scripts(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(sorted(path.rglob("*.nse")))
        elif path.suffix == ".nse":
            found.append(path)
    seen: dict[Path, None] = {}
    for path in found:
        seen.setdefault(path.resolve(), None)
    return list(seen)


def check_only(args: argparse.Namespace) -> int:
    """--check: report what the scanner will do with packs that already exist."""
    paths = [Path(p) for p in args.scripts]
    missing = [p for p in paths if not p.is_file()]
    if missing:
        print("not a file: %s" % ", ".join(str(p) for p in missing), file=sys.stderr)
        return 2
    failed = False
    for path in paths:
        lines, bad = pack_inspect.check_pack(path, verbose=args.verbose, strict=args.strict)
        print("\n".join(lines))
        failed = failed or bad
    return 1 if failed else 0


def run(args: argparse.Namespace) -> int:
    scripts = collect_scripts([Path(p) for p in args.scripts])
    if not scripts:
        print("no *.nse file found", file=sys.stderr)
        return 2

    products: dict[str, str] = {}
    if args.products:
        products = {k.lower(): v for k, v in
                    json.loads(Path(args.products).read_text(encoding="utf-8")).items()}

    packs: dict[str, dict] = {}
    pack_transports: dict[str, set[str]] = {}
    converted: list[dict] = []
    skipped: list[dict] = []
    seen_ids: dict[str, str] = {}

    for path in scripts:
        try:
            script = nse_parser.parse(path)
        except OSError as exc:
            skipped.append(build.Skip(path.stem, "file could not be read: %s" % exc,
                                      build.KIND_BUG).as_dict())
            continue

        result = build.convert(script, products, args.min_marker)
        skipped.extend(skip.as_dict() for skip in result.skips)

        category = "all" if args.single else primary_category(script.categories)
        for check in result.checks:
            errors = validate.validate_check(check)
            if errors:
                skipped.append(build.Skip(
                    script.name,
                    "the generated check failed the compiler rules: " + errors[0],
                    build.KIND_BUG).as_dict())
                continue
            if check["id"] in seen_ids:
                skipped.append(build.Skip(
                    script.name, "id %s is already taken by script %s" % (check["id"],
                                                                  seen_ids[check["id"]]),
                    build.KIND_BUG).as_dict())
                continue
            seen_ids[check["id"]] = script.name

            pack = packs.setdefault(category, _pack_skeleton(args.source, args.pack_version,
                                                             category))
            pack["checks"].append(check)
            pack_transports.setdefault(category, set()).update(result.transports)
            route, _ = validate.route_of(check)
            converted.append({
                "script": script.name,
                "check_id": check["id"],
                "pack": "%s-%s.json" % (args.source, category),
                "route": "web sweep" if route == validate.ROUTE_SWEEP else "own row",
            })

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    pack_report: list[dict] = []
    for category, pack in sorted(packs.items()):
        _finish_plugin(pack, pack_transports.get(category, set()))
        errors = validate.validate_pack(pack)
        if errors:
            print("pack %s failed validation: %s" % (category, errors[0]), file=sys.stderr)
            return 1
        file_name = "%s-%s.json" % (args.source, category)
        (out_dir / file_name).write_text(
            json.dumps(pack, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        routes = [validate.route_of(check)[0] for check in pack["checks"]]
        pack_report.append({
            "file": file_name,
            "plugin_id": pack["plugin"]["id"],
            "checks": len(pack["checks"]),
            "sweep": routes.count(validate.ROUTE_SWEEP),
            "own": routes.count(validate.ROUTE_OWN),
        })

    data = {
        "generated": report_mod.now(),
        "source": args.source,
        "pack_version": args.pack_version,
        "scripts_read": len(scripts),
        "packs": pack_report,
        "converted": converted,
        "skipped": skipped,
    }
    json_path, md_path = report_mod.write_reports(out_dir, data)

    if not args.quiet:
        print("\n".join(report_mod.summary_lines(data)))
        print("  reports:        %s, %s" % (md_path, json_path))

    bugs = [s for s in skipped if s["kind"] == build.KIND_BUG]
    if bugs:
        print("", file=sys.stderr)
        print("generation errors (%d) — converter defects, not format boundaries:"
              % len(bugs), file=sys.stderr)
        for bug in bugs[:10]:
            print("  %s.nse: %s" % (bug["script"], bug["reason"]), file=sys.stderr)
        if args.strict:
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="nse2pack",
        description="Converts Nmap NSE scripts into check-packs for "
                    "ShadowSecurityScanner.")
    ap.add_argument("scripts", nargs="+",
                    help="a directory of .nse scripts (walked recursively) or single "
                         "files; with --check, the pack files to inspect instead")
    ap.add_argument("-o", "--out", default="out", help="where packs and reports are written")
    ap.add_argument("--source", default="nse",
                    help="the source field: the name users see and can switch off")
    ap.add_argument("--pack-version", type=int, default=1,
                    help="the pack version stamp; a higher number replaces a lower one")
    ap.add_argument("--single", action="store_true",
                    help="write one pack instead of splitting by NSE category")
    ap.add_argument("--products", metavar="FILE",
                    help="JSON map {\"name in NSE\": \"canonical name in the scanner db\"}")
    ap.add_argument("--min-marker", type=int, default=build.DEFAULT_MIN_MARKER,
                    metavar="N",
                    help="how long a lone piece of evidence must be; below this a check "
                         "is dropped unless a product anchor backs it (default %d)"
                         % build.DEFAULT_MIN_MARKER)
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if any check failed the compiler rules "
                         "(for CI)")
    ap.add_argument("--check", action="store_true",
                    help="do not convert: inspect packs that already exist and report "
                         "what the scanner will accept, drop and why")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="with --check, print the plan of each accepted check")
    ap.add_argument("--quiet", action="store_true", help="no terminal summary")
    args = ap.parse_args(argv)
    return check_only(args) if args.check else run(args)
