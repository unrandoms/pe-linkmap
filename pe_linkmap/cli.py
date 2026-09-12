"""Command line interface for PE inspection and release comparison."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import compare, inspect, load_snapshot


def markdown(report: dict) -> str:
    lines = ["# PE export comparison", "",
             f"Structural break detected: **{str(report['surface_breaking']).lower()}**", "",
             f"Machine type changed: **{str(report['machine_changed']).lower()}**", "",
             f"Before SHA-256: `{report['before_sha256']}`", "",
             f"After SHA-256: `{report['after_sha256']}`", ""]
    for key in ("removed_names", "added_names", "removed_ordinals", "moved_ordinals", "changed_forwarders"):
        lines += ["## " + key.replace("_", " ").capitalize(), ""]
        for item in report[key]:
            # Encode all controls and Markdown delimiters as HTML entities to keep untrusted names inert.
            text = json.dumps(item, ensure_ascii=True)
            safe = "".join(c if c.isalnum() or c in " .,:_-" else f"&#{ord(c)};" for c in text)
            lines.append("- " + safe)
        if not report[key]:
            lines.append("None.")
        lines.append("")
    lines.append(report["limits"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pe-linkmap", description="Inspect PE exports and compare DLL release surfaces without loading binaries.")
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("inspect", help="write a deterministic export snapshot")
    show.add_argument("file", type=Path)
    show.add_argument("-o", "--output", type=Path)
    diff = commands.add_parser("diff", help="compare two DLLs or exported JSON snapshots")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--snapshots", action="store_true", help="read pe-linkmap JSON snapshots instead of PE files")
    diff.add_argument("--format", choices=("json", "markdown"), default="json")
    diff.add_argument("--fail-on-breaking", action="store_true", help="exit 1 on a structural export break")
    diff.add_argument("-o", "--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect(args.file)
        else:
            read = load_snapshot if args.snapshots else inspect
            result = compare(read(args.before), read(args.after))
        output = markdown(result) if getattr(args, "format", "json") == "markdown" else json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return int(args.command == "diff" and args.fail_on_breaking and result["surface_breaking"])
    except (OSError, ValueError) as exc:
        print(f"pe-linkmap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
