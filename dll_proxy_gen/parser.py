"""
PE export table parser.

Attempts to use the ``pefile`` library when it is installed; falls back to a
pure-Python struct-based implementation that reads the PE/COFF headers directly
so the tool works on any platform without native dependencies.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------

@dataclass
class Export:
    """A single exported symbol from a DLL."""

    ordinal: int
    name: Optional[str]   # None for ordinal-only exports
    rva: int              # Relative Virtual Address of the function
    forwarder: Optional[str] = None

    @property
    def forwarded(self) -> bool:
        """True when the export is a forwarder (RVA inside the export section)."""
        return self.forwarder is not None

    def __repr__(self) -> str:
        label = self.name or f"@{self.ordinal}"
        return f"<Export ordinal={self.ordinal} name={label!r} rva=0x{self.rva:08x}>"


@dataclass
class PEExports:
    """Container for all exports parsed from a DLL."""

    dll_name: str                  # internal name from the export directory
    base: int                      # ordinal base
    exports: List[Export] = field(default_factory=list)
    machine: int = 0

    @property
    def named(self) -> List[Export]:
        return [e for e in self.exports if e.name is not None]

    @property
    def ordinal_only(self) -> List[Export]:
        return [e for e in self.exports if e.name is None]


# ---------------------------------------------------------------------------
# pefile-backed fast path
# ---------------------------------------------------------------------------

def _parse_with_pefile(path: Path) -> PEExports:
    import pefile  # type: ignore
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        raise ValueError(f"{path.name!r} has no export table")

    exp_dir = pe.DIRECTORY_ENTRY_EXPORT
    dll_name: str = exp_dir.name.decode("ascii", errors="replace")
    base: int = exp_dir.struct.Base

    exports: List[Export] = []
    for sym in exp_dir.symbols:
        name: Optional[str] = sym.name.decode("ascii", errors="replace") if sym.name else None
        exports.append(Export(ordinal=sym.ordinal, name=name, rva=sym.address or 0,
                              forwarder=sym.forwarder.decode("ascii", errors="replace") if sym.forwarder else None))

    machine = pe.FILE_HEADER.Machine
    pe.close()
    return PEExports(dll_name=dll_name, base=base, exports=exports, machine=machine)


# ---------------------------------------------------------------------------
# Pure-Python struct-based fallback
# ---------------------------------------------------------------------------

# PE constants
_MZ = b"MZ"
_PE_SIG = b"PE\x00\x00"
_MACHINE_AMD64 = 0x8664
_MACHINE_I386  = 0x014C
_MACHINE_ARM64 = 0xAA64

# IMAGE_DATA_DIRECTORY index for exports
_DIR_EXPORT = 0

# Struct formats (little-endian)
_FMT_DOS_HEADER = "<2sH"          # e_magic, ... (we only need e_lfanew)
_DOS_E_LFANEW_OFFSET = 0x3C      # offset of e_lfanew in the DOS header

_FMT_IMAGE_FILE_HEADER = "<HHIIIHH"  # Machine, NumberOfSections, TimeDateStamp,
                                      # PointerToSymbolTable, NumberOfSymbols,
                                      # SizeOfOptionalHeader, Characteristics
_FMT_IMAGE_OPTIONAL_MAGIC = "<H"

_FMT_DATA_DIRECTORY = "<II"  # VirtualAddress, Size

_FMT_EXPORT_DIRECTORY = "<IIHHIIIIII"
# Characteristics (I), TimeDateStamp (I), MajorVersion (H), MinorVersion (H),
# Name (I, RVA), Base (I), NumberOfFunctions (I), NumberOfNames (I),
# AddressOfFunctions (I, RVA), AddressOfNames (I, RVA)
# NOTE: AddressOfNameOrdinals is the 11th field (I) parsed separately below


def _rva_to_offset(rva: int, sections: list) -> int:
    """Convert a Relative Virtual Address to a file offset using the section table."""
    for va, raw_off, raw_size, virt_size in sections:
        size = min(virt_size, raw_size) if virt_size else raw_size
        if va <= rva < va + size:
            return raw_off + (rva - va)
    raise ValueError(f"RVA 0x{rva:08x} not mapped by any section")


def _read_sz(data: bytes, offset: int) -> str:
    """Read a null-terminated ASCII string from *data* at *offset*."""
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("ascii", errors="replace")


def _parse_pure_python(path: Path) -> PEExports:
    return parse_export_bytes(path.read_bytes(), path.name)


def parse_export_bytes(data: bytes, filename: str = "input") -> PEExports:
    """Parse a byte snapshot so a report hashes exactly the bytes it inspected."""
    try:
        return _parse_data(data, Path(filename))
    except (struct.error, IndexError) as exc:
        raise ValueError(f"{filename!r}: truncated PE structure") from exc


def _parse_data(data: bytes, path: Path) -> PEExports:

    # 1. DOS header
    if data[:2] != _MZ:
        raise ValueError(f"{path.name!r} is not a valid PE file (bad MZ magic)")
    e_lfanew = struct.unpack_from("<I", data, _DOS_E_LFANEW_OFFSET)[0]

    # 2. PE signature
    if data[e_lfanew:e_lfanew + 4] != _PE_SIG:
        raise ValueError(f"{path.name!r}: bad PE signature at offset 0x{e_lfanew:x}")

    fh_offset = e_lfanew + 4
    (machine, num_sections, _, _, _, opt_hdr_size, _) = struct.unpack_from(
        _FMT_IMAGE_FILE_HEADER, data, fh_offset
    )

    opt_offset = fh_offset + struct.calcsize(_FMT_IMAGE_FILE_HEADER)
    (opt_magic,) = struct.unpack_from(_FMT_IMAGE_OPTIONAL_MAGIC, data, opt_offset)

    # 3. Optional header: find data directory
    if opt_magic == 0x010B:   # PE32
        data_dir_base = opt_offset + 96
    elif opt_magic == 0x020B:  # PE32+ (64-bit)
        data_dir_base = opt_offset + 112
    else:
        raise ValueError(f"{path.name!r}: unknown optional header magic 0x{opt_magic:04x}")

    exp_rva, exp_size = struct.unpack_from(_FMT_DATA_DIRECTORY, data, data_dir_base + _DIR_EXPORT * 8)
    if exp_rva == 0:
        raise ValueError(f"{path.name!r} has no export table")

    # 4. Section table
    section_table_offset = opt_offset + opt_hdr_size
    sections = []
    for i in range(num_sections):
        sec_off = section_table_offset + i * 40
        virt_size  = struct.unpack_from("<I", data, sec_off + 8)[0]
        virt_addr  = struct.unpack_from("<I", data, sec_off + 12)[0]
        raw_size   = struct.unpack_from("<I", data, sec_off + 16)[0]
        raw_off    = struct.unpack_from("<I", data, sec_off + 20)[0]
        sections.append((virt_addr, raw_off, raw_size, virt_size))

    # 5. Export directory
    exp_off = _rva_to_offset(exp_rva, sections)

    (
        characteristics, timestamp, major_ver, minor_ver,
        name_rva, base, num_functions, num_names,
        addr_of_functions_rva, addr_of_names_rva,
    ) = struct.unpack_from(_FMT_EXPORT_DIRECTORY, data, exp_off)

    # AddressOfNameOrdinals is the 11th DWORD in the export directory.
    # struct "<IIHHIIIIII" is 36 bytes (the first 10 fields), so field 11 starts at 36.
    addr_of_name_ordinals_rva = struct.unpack_from("<I", data, exp_off + 36)[0]

    dll_name = _read_sz(data, _rva_to_offset(name_rva, sections))

    # 6. Walk tables
    fn_table_off    = _rva_to_offset(addr_of_functions_rva, sections)
    name_table_off = _rva_to_offset(addr_of_names_rva, sections) if num_names else 0
    ord_table_off = _rva_to_offset(addr_of_name_ordinals_rva, sections) if num_names else 0

    # Build ordinal -> name map from the name/ordinal parallel arrays
    ordinal_to_names: dict[int, list[str]] = {}
    for i in range(num_names):
        name_rva_i  = struct.unpack_from("<I", data, name_table_off + i * 4)[0]
        hint_ord    = struct.unpack_from("<H", data, ord_table_off + i * 2)[0]
        symbol_name = _read_sz(data, _rva_to_offset(name_rva_i, sections))
        if hint_ord >= num_functions:
            raise ValueError("Export name ordinal exceeds the address table")
        ordinal_to_names.setdefault(hint_ord, []).append(symbol_name)

    # Export address table: index 0 → ordinal base, index i → ordinal (base + i)
    exports: List[Export] = []
    for i in range(num_functions):
        fn_rva = struct.unpack_from("<I", data, fn_table_off + i * 4)[0]
        if fn_rva == 0:
            continue  # gap in the export table
        ordinal = base + i
        forwarder = None
        if exp_rva <= fn_rva < exp_rva + exp_size:
            forwarder = _read_sz(data, _rva_to_offset(fn_rva, sections))
        for name in ordinal_to_names.get(i, [None]):
            exports.append(Export(ordinal=ordinal, name=name, rva=fn_rva, forwarder=forwarder))

    return PEExports(dll_name=dll_name, base=base, exports=exports, machine=machine)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_exports(path: str | os.PathLike) -> PEExports:
    """
    Parse the export table of a PE/DLL file and return a :class:`PEExports` object.

    Uses ``pefile`` if available, otherwise falls back to the pure-Python parser.

    Parameters
    ----------
    path:
        Path to the DLL / PE file to analyse.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If the file is not a valid PE or has no export table.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    try:
        return _parse_with_pefile(p)
    except ImportError:
        return _parse_pure_python(p)
