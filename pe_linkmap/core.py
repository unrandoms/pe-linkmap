"""Deterministic PE export snapshots and structural compatibility checks."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from dll_proxy_gen.parser import parse_export_bytes

MAX_INPUT_BYTES = 64 * 1024 * 1024
MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}


def read_limited(path: Path) -> bytes:
    with path.open("rb") as source:
        data = source.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the 64 MiB inspection limit")
    return data


def inspect(path: Path) -> dict:
    data = read_limited(path)
    parsed = parse_export_bytes(data, path.name)
    result = {
        "schema_version": 1,
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "dll_name": parsed.dll_name,
        "machine": parsed.machine,
        "architecture": MACHINES.get(parsed.machine, f"unknown-0x{parsed.machine:04x}"),
        "exports": [
            {"name": e.name, "ordinal": e.ordinal, "rva": e.rva, "forwarder": e.forwarder}
            for e in sorted(parsed.exports, key=lambda e: (e.ordinal, e.name or ""))
        ],
    }
    validate(result)
    return result


def validate(value: object) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("expected a pe-linkmap schema_version 1 snapshot")
    if type(value.get("machine")) is not int or not 0 <= value["machine"] <= 65535:
        raise ValueError("snapshot machine must be a 16-bit integer")
    if not isinstance(value.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise ValueError("snapshot sha256 must contain 64 lowercase hexadecimal characters")
    exports = value.get("exports")
    if not isinstance(exports, list):
        raise ValueError("snapshot exports must be an array")
    names = set()
    ordinal_values = {}
    for item in exports:
        if not isinstance(item, dict):
            raise ValueError("each export must be an object")
        name, ordinal = item.get("name"), item.get("ordinal")
        if name is not None and (not isinstance(name, str) or not name):
            raise ValueError("export name must be nonempty text or null")
        if type(ordinal) is not int or not 0 <= ordinal <= 0xFFFFFFFF:
            raise ValueError("export ordinal must be an unsigned 32-bit integer")
        forwarder = item.get("forwarder")
        if forwarder is not None and (not isinstance(forwarder, str) or not forwarder):
            raise ValueError("forwarder must be nonempty text or null")
        rva = item.get("rva")
        if type(rva) is not int or not 0 < rva <= 0xFFFFFFFF:
            raise ValueError("export RVA must be a nonzero unsigned 32-bit integer")
        if name is not None:
            if name in names:
                raise ValueError(f"duplicate export name: {name}")
            names.add(name)
        binding = (rva, forwarder)
        if ordinal in ordinal_values and ordinal_values[ordinal] != binding:
            raise ValueError(f"conflicting exports for ordinal {ordinal}")
        ordinal_values[ordinal] = binding
    return value


def load_snapshot(path: Path) -> dict:
    try:
        return validate(json.loads(read_limited(path)))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON snapshot") from exc


def compare(before: dict, after: dict) -> dict:
    validate(before)
    validate(after)
    old = {e["name"]: e for e in before["exports"] if e["name"] is not None}
    new = {e["name"]: e for e in after["exports"] if e["name"] is not None}
    old_ord = {e["ordinal"]: e for e in before["exports"]}
    new_ord = {e["ordinal"]: e for e in after["exports"]}
    removed = sorted(old.keys() - new.keys())
    added = sorted(new.keys() - old.keys())
    moved = [{"name": name, "before": old[name]["ordinal"], "after": new[name]["ordinal"]}
             for name in sorted(old.keys() & new.keys()) if old[name]["ordinal"] != new[name]["ordinal"]]
    removed_ord = sorted(old_ord.keys() - new_ord.keys())
    forwarders = [{"ordinal": ordinal, "before": old_ord[ordinal].get("forwarder"),
                   "after": new_ord[ordinal].get("forwarder")}
                  for ordinal in sorted(old_ord.keys() & new_ord.keys())
                  if old_ord[ordinal].get("forwarder") != new_ord[ordinal].get("forwarder")]
    machine_changed = before["machine"] != after["machine"]
    breaking = bool(removed or removed_ord or moved or machine_changed)
    return {
        "schema_version": 1,
        "before_sha256": before.get("sha256"), "after_sha256": after.get("sha256"),
        "surface_breaking": breaking,
        "review_required": breaking or bool(forwarders),
        "machine_changed": machine_changed,
        "removed_names": removed, "added_names": added,
        "removed_ordinals": removed_ord, "moved_ordinals": moved,
        "changed_forwarders": forwarders,
        "limits": "Export surfaces do not establish calling conventions, signatures or behavioral ABI compatibility.",
    }
