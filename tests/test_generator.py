"""
Tests for dll_proxy_gen.generator.

Verifies that the Jinja2 templates render correctly for different export
configurations and payload kinds.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from dll_proxy_gen.parser import Export, PEExports
from dll_proxy_gen.generator import generate, _orig_stem
from dll_proxy_gen.payload import PayloadKind


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def simple_exports() -> PEExports:
    return PEExports(
        dll_name="version.dll",
        base=1,
        exports=[
            Export(ordinal=1, name="GetFileVersionInfoA", rva=0x1000),
            Export(ordinal=2, name="GetFileVersionInfoW", rva=0x1010),
            Export(ordinal=3, name="VerQueryValueA",      rva=0x1020),
        ],
    )


@pytest.fixture()
def mixed_exports() -> PEExports:
    return PEExports(
        dll_name="winmm.dll",
        base=1,
        exports=[
            Export(ordinal=1, name="mciSendCommandA", rva=0x2000),
            Export(ordinal=2, name=None,              rva=0x2010),  # ordinal-only
        ],
    )


# ---------------------------------------------------------------------------
# _orig_stem helper
# ---------------------------------------------------------------------------

class TestOrigStem:
    def test_version_dll(self) -> None:
        assert _orig_stem("version.dll") == "_version_orig"

    def test_winmm_dll(self) -> None:
        assert _orig_stem("winmm.dll") == "_winmm_orig"

    def test_uppercase(self) -> None:
        assert _orig_stem("WINMM.DLL") == "_winmm_orig"

    def test_no_extension(self) -> None:
        assert _orig_stem("mylib") == "_mylib_orig"


# ---------------------------------------------------------------------------
# C source generation
# ---------------------------------------------------------------------------

class TestGenerateCSource:
    def test_contains_pragma_for_each_named_export(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        c = out.files["proxy.c"]
        assert "#pragma comment(linker," in c
        assert "GetFileVersionInfoA" in c
        assert "GetFileVersionInfoW" in c
        assert "VerQueryValueA" in c

    def test_forwarding_uses_orig_stem(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        c = out.files["proxy.c"]
        assert "_version_orig.GetFileVersionInfoA" in c

    def test_ordinal_annotation(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        c = out.files["proxy.c"]
        assert "@1" in c
        assert "@2" in c

    def test_dll_main_present(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        c = out.files["proxy.c"]
        assert "DllMain" in c
        assert "DLL_PROCESS_ATTACH" in c

    def test_no_payload_snippet(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports, payload_kind=PayloadKind.NONE)
        c = out.files["proxy.c"]
        assert "/* no payload */" in c

    def test_messagebox_payload(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports, payload_kind=PayloadKind.MESSAGEBOX)
        c = out.files["proxy.c"]
        assert "MessageBoxA" in c

    def test_ordinal_only_export_in_c(self, mixed_exports: PEExports) -> None:
        out = generate(mixed_exports)
        c = out.files["proxy.c"]
        # Ordinal-only exports should appear with NONAME
        assert "NONAME" in c

    def test_loadlib_payload(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports, payload_kind=PayloadKind.LOADLIB)
        c = out.files["proxy.c"]
        assert "LoadLibraryA" in c


# ---------------------------------------------------------------------------
# .def file generation
# ---------------------------------------------------------------------------

class TestGenerateDefFile:
    def test_library_directive(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        deffile = out.files["proxy.def"]
        assert "LIBRARY version.dll" in deffile

    def test_exports_section_header(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        deffile = out.files["proxy.def"]
        assert "EXPORTS" in deffile

    def test_forwarding_in_def(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        deffile = out.files["proxy.def"]
        assert "_version_orig.GetFileVersionInfoA" in deffile

    def test_ordinal_column(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        deffile = out.files["proxy.def"]
        assert "@1" in deffile

    def test_noname_ordinal_in_def(self, mixed_exports: PEExports) -> None:
        out = generate(mixed_exports)
        deffile = out.files["proxy.def"]
        assert "NONAME" in deffile


# ---------------------------------------------------------------------------
# CMakeLists.txt generation
# ---------------------------------------------------------------------------

class TestGenerateCMake:
    def test_cmake_present_by_default(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        assert "CMakeLists.txt" in out.files

    def test_cmake_omitted_when_flag_set(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports, emit_cmake=False)
        assert "CMakeLists.txt" not in out.files

    def test_cmake_output_name(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        cmake = out.files["CMakeLists.txt"]
        assert '"version"' in cmake  # OUTPUT_NAME

    def test_cmake_orig_stem_in_message(self, simple_exports: PEExports) -> None:
        out = generate(simple_exports)
        cmake = out.files["CMakeLists.txt"]
        assert "_version_orig" in cmake


# ---------------------------------------------------------------------------
# Shellcode header
# ---------------------------------------------------------------------------

class TestShellcodeHeader:
    def test_shellcode_header_generated(self, simple_exports: PEExports, tmp_path: Path) -> None:
        sc = tmp_path / "calc.bin"
        sc.write_bytes(b"\xcc\x90\x90")
        out = generate(simple_exports, payload_kind=PayloadKind.SHELLCODE,
                       shellcode_path=str(sc))
        assert "shellcode.h" in out.files
        h = out.files["shellcode.h"]
        assert "0xcc" in h
        assert "0x90" in h

    def test_shellcode_pragma_not_present_without_file(self, simple_exports: PEExports) -> None:
        # Shellcode payload without file — no shellcode.h generated
        out = generate(simple_exports, payload_kind=PayloadKind.SHELLCODE,
                       shellcode_path=None)
        assert "shellcode.h" not in out.files


# ---------------------------------------------------------------------------
# write() helper
# ---------------------------------------------------------------------------

class TestWrite:
    def test_writes_files_to_disk(self, simple_exports: PEExports, tmp_path: Path) -> None:
        out = generate(simple_exports)
        out.write(tmp_path)
        assert (tmp_path / "proxy.c").exists()
        assert (tmp_path / "proxy.def").exists()
        assert (tmp_path / "CMakeLists.txt").exists()

    def test_creates_output_dir(self, simple_exports: PEExports, tmp_path: Path) -> None:
        dest = tmp_path / "new_dir" / "output"
        out = generate(simple_exports)
        out.write(dest)
        assert dest.is_dir()
