"""
Tests for dll_proxy_gen.parser.

The pure-Python PE parser is exercised against a minimal hand-crafted PE
binary that is constructed in-memory by the helpers below.  This avoids any
dependency on a real Windows DLL being present in the CI environment.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest

from dll_proxy_gen.parser import (
    Export,
    PEExports,
    _parse_pure_python,
)

# We test the public surface: parse_exports dispatches to the pure-Python
# fallback when pefile is not available; we call _parse_pure_python directly
# so tests are deterministic regardless of whether pefile is installed.


# ---------------------------------------------------------------------------
# Minimal PE builder
# ---------------------------------------------------------------------------

def _pack_dword(v: int) -> bytes:
    return struct.pack("<I", v)


def _pack_word(v: int) -> bytes:
    return struct.pack("<H", v)


def _align(size: int, align: int) -> int:
    return (size + align - 1) & ~(align - 1)


def build_minimal_pe(exports: list[tuple[int, str | None]]) -> bytes:
    """
    Build a minimal 32-bit PE (PE32) binary with the given exports.

    *exports* is a list of (ordinal_hint_index, name_or_None) tuples where the
    ordinal hint index is 0-based (ordinal = base + index, base = 1).

    The resulting bytes are a valid PE that _parse_pure_python can parse.
    """
    # We lay out the entire image in memory.  Because the file is not loaded
    # by Windows, file offsets == RVAs (we use section VA == section raw off).

    FILE_ALIGN  = 0x200
    SECT_ALIGN  = 0x1000
    IMAGE_BASE  = 0x10000000
    BASE        = 1  # ordinal base

    # ---------- Strings section ----------
    # We will place: DLL name, function names, then the tables.

    dll_name_bytes = b"test.dll\x00"

    named = [(i, n) for i, n in exports if n is not None]
    ordinal_only = [(i, n) for i, n in exports if n is None]

    # Build name strings
    name_blobs: list[bytes] = []
    for _, name in named:
        name_blobs.append(name.encode("ascii") + b"\x00")

    # ---- Compute section layout ----
    # We'll put everything in one section starting at RVA 0x1000.
    SECT_RVA = 0x1000
    SECT_RAW = FILE_ALIGN  # section starts at file offset 0x200

    offset = 0
    dll_name_off = offset
    offset += len(dll_name_bytes)

    func_name_offs: list[int] = []
    for blob in name_blobs:
        func_name_offs.append(offset)
        offset += len(blob)

    # Align tables to 4 bytes
    offset = _align(offset, 4)

    # AddressOfFunctions (DWORD array, one per ordinal slot)
    num_functions = len(exports)
    addr_funcs_off = offset
    offset += 4 * num_functions

    # AddressOfNames (DWORD array, one per named export)
    addr_names_off = offset
    offset += 4 * len(named)

    # AddressOfNameOrdinals (WORD array, one per named export, 0-based index)
    addr_ordinals_off = offset
    offset += 2 * len(named)
    offset = _align(offset, 4)

    # IMAGE_EXPORT_DIRECTORY (40 bytes)
    export_dir_off = offset
    offset += 40

    sect_data_size = offset

    # ---- Now fill the bytes ----
    sect_data = bytearray(sect_data_size)

    # DLL name
    sect_data[dll_name_off:dll_name_off + len(dll_name_bytes)] = dll_name_bytes

    # Function names
    for idx, (_, name) in enumerate(named):
        blob = name.encode("ascii") + b"\x00"
        fo = func_name_offs[idx]
        sect_data[fo:fo + len(blob)] = blob

    # AddressOfFunctions: each function gets a fake RVA = SECT_RVA + 0x500 + i
    for i in range(num_functions):
        rva = SECT_RVA + 0x500 + i
        struct.pack_into("<I", sect_data, addr_funcs_off + i * 4, rva)

    # AddressOfNames and AddressOfNameOrdinals
    for seq, (export_idx, name) in enumerate(named):
        name_rva = SECT_RVA + func_name_offs[seq]
        struct.pack_into("<I", sect_data, addr_names_off + seq * 4, name_rva)
        struct.pack_into("<H", sect_data, addr_ordinals_off + seq * 2, export_idx)

    # IMAGE_EXPORT_DIRECTORY
    ed_off = export_dir_off
    struct.pack_into("<I", sect_data, ed_off + 0,  0)                      # Characteristics
    struct.pack_into("<I", sect_data, ed_off + 4,  0)                      # TimeDateStamp
    struct.pack_into("<H", sect_data, ed_off + 8,  0)                      # MajorVersion
    struct.pack_into("<H", sect_data, ed_off + 10, 0)                      # MinorVersion
    struct.pack_into("<I", sect_data, ed_off + 12, SECT_RVA + dll_name_off) # Name RVA
    struct.pack_into("<I", sect_data, ed_off + 16, BASE)                   # Base
    struct.pack_into("<I", sect_data, ed_off + 20, num_functions)           # NumberOfFunctions
    struct.pack_into("<I", sect_data, ed_off + 24, len(named))              # NumberOfNames
    struct.pack_into("<I", sect_data, ed_off + 28, SECT_RVA + addr_funcs_off)  # AddressOfFunctions
    struct.pack_into("<I", sect_data, ed_off + 32, SECT_RVA + addr_names_off)  # AddressOfNames
    struct.pack_into("<I", sect_data, ed_off + 36, SECT_RVA + addr_ordinals_off) # AddressOfNameOrdinals

    EXPORT_DIR_RVA  = SECT_RVA + export_dir_off
    EXPORT_DIR_SIZE = 40

    # ---- PE headers ----
    # DOS header (64 bytes) + DOS stub (0) → e_lfanew = 64
    E_LFANEW = 64

    dos_header = bytearray(64)
    dos_header[0:2]  = b"MZ"
    struct.pack_into("<H", dos_header, 2, 0x90)   # e_cblp
    struct.pack_into("<I", dos_header, 0x3C, E_LFANEW)

    # IMAGE_FILE_HEADER
    num_sections = 1
    opt_hdr_size = 224  # PE32 optional header size (standard)

    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,          # Machine: IMAGE_FILE_MACHINE_I386
        num_sections,    # NumberOfSections
        0,               # TimeDateStamp
        0,               # PointerToSymbolTable
        0,               # NumberOfSymbols
        opt_hdr_size,    # SizeOfOptionalHeader
        0x2102,          # Characteristics: DLL | 32-bit
    )

    # IMAGE_OPTIONAL_HEADER32
    data_dirs = bytearray(128)  # 16 × 8 bytes
    struct.pack_into("<I", data_dirs, 0,  EXPORT_DIR_RVA)   # Export VA
    struct.pack_into("<I", data_dirs, 4,  EXPORT_DIR_SIZE)  # Export size

    opt_header = struct.pack("<H", 0x010B)  # Magic: PE32
    opt_header += struct.pack("<BB", 14, 0)  # MajorLinkerVersion, Minor
    opt_header += struct.pack("<I",  _align(sect_data_size, FILE_ALIGN))  # SizeOfCode
    opt_header += struct.pack("<I",  0)  # SizeOfInitializedData
    opt_header += struct.pack("<I",  0)  # SizeOfUninitializedData
    opt_header += struct.pack("<I",  0)  # AddressOfEntryPoint
    opt_header += struct.pack("<I",  0)  # BaseOfCode
    opt_header += struct.pack("<I",  0)  # BaseOfData
    opt_header += struct.pack("<I",  IMAGE_BASE)  # ImageBase
    opt_header += struct.pack("<I",  SECT_ALIGN)  # SectionAlignment
    opt_header += struct.pack("<I",  FILE_ALIGN)  # FileAlignment
    opt_header += struct.pack("<HH", 6, 0)  # MajorOS, MinorOS
    opt_header += struct.pack("<HH", 0, 0)  # MajorImage, MinorImage
    opt_header += struct.pack("<HH", 4, 0)  # MajorSubsystem, MinorSubsystem
    opt_header += struct.pack("<I",  0)  # Win32VersionValue
    opt_header += struct.pack("<I",  SECT_ALIGN * 2)  # SizeOfImage
    opt_header += struct.pack("<I",  _align(E_LFANEW + 4 + 20 + opt_hdr_size + 40, FILE_ALIGN))  # SizeOfHeaders
    opt_header += struct.pack("<I",  0)  # CheckSum
    opt_header += struct.pack("<HH", 2, 0)  # Subsystem (GUI), DllCharacteristics
    opt_header += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap
    opt_header += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    opt_header += bytes(data_dirs)  # data directories

    assert len(opt_header) == opt_hdr_size, f"opt_header size mismatch: {len(opt_header)}"

    # IMAGE_SECTION_HEADER (40 bytes)
    sect_virt_size = sect_data_size
    sect_header = bytearray(40)
    sect_header[0:8] = b".export\x00"
    struct.pack_into("<I", sect_header, 8,  sect_virt_size)
    struct.pack_into("<I", sect_header, 12, SECT_RVA)
    struct.pack_into("<I", sect_header, 16, _align(sect_data_size, FILE_ALIGN))
    struct.pack_into("<I", sect_header, 20, SECT_RAW)
    struct.pack_into("<I", sect_header, 36, 0x40000040)  # characteristics

    # Assemble the file
    pe_sig = b"PE\x00\x00"
    headers = (bytes(dos_header) + pe_sig + file_header +
               opt_header + bytes(sect_header))
    headers_padded = headers + b"\x00" * (_align(len(headers), FILE_ALIGN) - len(headers))

    sect_padded = bytes(sect_data) + b"\x00" * (_align(sect_data_size, FILE_ALIGN) - sect_data_size)
    return headers_padded + sect_padded


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def simple_pe(tmp_path: Path) -> Path:
    """A PE with two named exports at ordinals 1 and 2."""
    pe_bytes = build_minimal_pe([(0, "FuncA"), (1, "FuncB")])
    p = tmp_path / "simple.dll"
    p.write_bytes(pe_bytes)
    return p


@pytest.fixture()
def mixed_pe(tmp_path: Path) -> Path:
    """A PE with one named export (index 0) and one ordinal-only export (index 1)."""
    pe_bytes = build_minimal_pe([(0, "FuncNamed"), (1, None)])
    p = tmp_path / "mixed.dll"
    p.write_bytes(pe_bytes)
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParsePurePython:
    def test_dll_name(self, simple_pe: Path) -> None:
        result = _parse_pure_python(simple_pe)
        assert result.dll_name == "test.dll"

    def test_ordinal_base(self, simple_pe: Path) -> None:
        result = _parse_pure_python(simple_pe)
        assert result.base == 1

    def test_named_exports_count(self, simple_pe: Path) -> None:
        result = _parse_pure_python(simple_pe)
        assert len(result.named) == 2

    def test_named_export_names(self, simple_pe: Path) -> None:
        result = _parse_pure_python(simple_pe)
        names = {e.name for e in result.named}
        assert names == {"FuncA", "FuncB"}

    def test_named_export_ordinals(self, simple_pe: Path) -> None:
        result = _parse_pure_python(simple_pe)
        ordinals = {e.ordinal for e in result.named}
        assert ordinals == {1, 2}

    def test_mixed_named_and_ordinal(self, mixed_pe: Path) -> None:
        result = _parse_pure_python(mixed_pe)
        assert len(result.named) == 1
        assert result.named[0].name == "FuncNamed"
        assert len(result.ordinal_only) == 1
        assert result.ordinal_only[0].name is None

    def test_file_not_found(self, tmp_path: Path) -> None:
        from dll_proxy_gen.parser import parse_exports
        with pytest.raises(FileNotFoundError):
            parse_exports(tmp_path / "nonexistent.dll")

    def test_invalid_magic(self, tmp_path: Path) -> None:
        p = tmp_path / "fake.dll"
        p.write_bytes(b"\x00" * 64)
        with pytest.raises(ValueError, match="MZ magic"):
            _parse_pure_python(p)

    def test_rva_in_export(self, simple_pe: Path) -> None:
        result = _parse_pure_python(simple_pe)
        for exp in result.exports:
            assert exp.rva > 0


class TestPEExportsModel:
    def test_named_property(self) -> None:
        exports = [Export(1, "A", 0x100), Export(2, None, 0x200)]
        pe = PEExports(dll_name="x.dll", base=1, exports=exports)
        assert len(pe.named) == 1
        assert pe.named[0].name == "A"

    def test_ordinal_only_property(self) -> None:
        exports = [Export(1, "A", 0x100), Export(2, None, 0x200)]
        pe = PEExports(dll_name="x.dll", base=1, exports=exports)
        assert len(pe.ordinal_only) == 1
        assert pe.ordinal_only[0].ordinal == 2
