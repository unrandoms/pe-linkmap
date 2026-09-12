import copy
import hashlib
import json
import struct

import pytest

from pe_linkmap.cli import main
from pe_linkmap.core import compare, inspect, load_snapshot
from dll_proxy_gen.parser import parse_export_bytes
from tests.test_parser import build_minimal_pe


def binary(tmp_path, name, exports):
    path = tmp_path / name
    path.write_bytes(build_minimal_pe(exports))
    return path


def export_offsets(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    rva, size = struct.unpack_from("<II", data, optional + 96)
    directory = 0x200 + rva - 0x1000
    functions = struct.unpack_from("<I", data, directory + 28)[0] - 0x1000 + 0x200
    return optional, rva, directory, functions


def test_snapshot_hashes_and_orders_actual_input_bytes(tmp_path):
    path = binary(tmp_path, "sample.dll", [(1, "Second"), (0, "First")])
    snapshot = inspect(path)
    assert snapshot["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert snapshot["architecture"] == "x86"
    assert [e["name"] for e in snapshot["exports"]] == ["First", "Second"]
    assert snapshot == inspect(path)


def test_aliases_are_not_lost(tmp_path):
    path = binary(tmp_path, "alias.dll", [(0, "One"), (0, "Alias")])
    exports = inspect(path)["exports"]
    assert {e["name"] for e in exports if e["ordinal"] == 1} == {"One", "Alias"}


def test_ordinal_only_table_accepts_zero_name_pointers():
    data = bytearray(build_minimal_pe([(0, None), (1, None)]))
    _, _, directory, _ = export_offsets(data)
    struct.pack_into("<II", data, directory + 32, 0, 0)
    assert [e.ordinal for e in parse_export_bytes(bytes(data)).exports] == [1, 2]


def test_forwarder_target_is_preserved(tmp_path):
    path = binary(tmp_path, "forward.dll", [(0, "Forwarded")])
    data = bytearray(path.read_bytes())
    optional, rva, directory, functions = export_offsets(data)
    target = b"KERNEL32.Sleep\x00"
    data[directory + 40:directory + 40 + len(target)] = target
    struct.pack_into("<I", data, optional + 100, 40 + len(target))
    struct.pack_into("<I", data, functions, rva + 40)
    section = optional + 224
    struct.pack_into("<I", data, section + 8, directory + 40 + len(target) - 0x200)
    path.write_bytes(data)
    parsed = parse_export_bytes(bytes(data))
    assert parsed.exports[0].forwarded
    assert inspect(path)["exports"][0]["forwarder"] == "KERNEL32.Sleep"


def test_added_export_is_not_a_structural_break(tmp_path):
    before = inspect(binary(tmp_path, "before.dll", [(0, "Keep")]))
    after = inspect(binary(tmp_path, "after.dll", [(0, "Keep"), (1, "Added")]))
    result = compare(before, after)
    assert result["added_names"] == ["Added"]
    assert not result["surface_breaking"]


def test_removed_export_and_moved_ordinal_are_reported(tmp_path):
    before = inspect(binary(tmp_path, "before.dll", [(0, "Removed"), (1, "Keep")]))
    after = inspect(binary(tmp_path, "after.dll", [(0, "Keep")]))
    result = compare(before, after)
    assert result["removed_names"] == ["Removed"]
    assert result["removed_ordinals"] == [2]
    assert result["moved_ordinals"] == [{"name": "Keep", "before": 2, "after": 1}]
    assert result["surface_breaking"]


def test_code_rva_changes_do_not_claim_abi_break(tmp_path):
    before = inspect(binary(tmp_path, "sample.dll", [(0, "Keep")]))
    after = copy.deepcopy(before)
    after["exports"][0]["rva"] += 0x1000
    assert not compare(before, after)["review_required"]


def test_forwarder_change_requires_review(tmp_path):
    before = inspect(binary(tmp_path, "sample.dll", [(0, "Keep")]))
    after = copy.deepcopy(before)
    after["exports"][0]["forwarder"] = "OTHER.Keep"
    result = compare(before, after)
    assert result["review_required"]
    assert not result["surface_breaking"]


def test_machine_change_is_structural_break(tmp_path):
    before = inspect(binary(tmp_path, "sample.dll", [(0, "Keep")]))
    after = copy.deepcopy(before)
    after["machine"] = 0x8664
    assert compare(before, after)["surface_breaking"]


def test_saved_snapshot_diff_and_ci_exit_code(tmp_path, capsys):
    before = binary(tmp_path, "before.dll", [(0, "Gone"), (1, "Stay")])
    after = binary(tmp_path, "after.dll", [(0, "Stay")])
    old_json, new_json = tmp_path / "before.json", tmp_path / "after.json"
    assert main(["inspect", str(before), "-o", str(old_json)]) == 0
    assert main(["inspect", str(after), "-o", str(new_json)]) == 0
    assert main(["diff", str(old_json), str(new_json), "--snapshots", "--fail-on-breaking"]) == 1
    assert json.loads(capsys.readouterr().out)["surface_breaking"]
    assert load_snapshot(old_json)["file"] == "before.dll"


def test_truncated_pe_reports_error_without_traceback(tmp_path, capsys):
    path = tmp_path / "truncated.dll"
    path.write_bytes(b"MZ")
    assert main(["inspect", str(path)]) == 2
    assert "truncated" in capsys.readouterr().err


def test_markdown_escapes_export_content(tmp_path, capsys):
    before = binary(tmp_path, "before.dll", [(0, "<img src=x>\n# heading")])
    after = binary(tmp_path, "after.dll", [(0, "Safe")])
    assert main(["diff", str(before), str(after), "--format", "markdown"]) == 0
    output = capsys.readouterr().out
    assert "<img" not in output
    assert "\n# heading" not in output


def test_conflicting_snapshot_is_rejected(tmp_path):
    snapshot = inspect(binary(tmp_path, "sample.dll", [(0, "Same")]))
    snapshot["exports"].append(snapshot["exports"][0].copy())
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(snapshot))
    with pytest.raises(ValueError, match="duplicate export"):
        load_snapshot(path)
