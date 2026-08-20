"""
Code generator for DLL proxy stubs.

Renders Jinja2 templates to produce:
  - proxy.c         — C source with DllMain and #pragma comment forwarding stubs
  - proxy.def       — Module-definition file for explicit linker export control
  - CMakeLists.txt  — CMake build script targeting MSVC or MinGW
  - shellcode.h     — (optional) embedded shellcode byte array
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .parser import PEExports, Export
from .payload import PayloadKind, get_snippet, generate_shellcode_header


# Template directory relative to this file
_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def _make_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def _orig_stem(dll_name: str) -> str:
    """
    Derive the forwarding prefix from the internal DLL name.

    ``version.dll`` → ``_version_orig``
    ``winmm.dll``   → ``_winmm_orig``
    """
    stem = Path(dll_name).stem.lower()
    return f"_{stem}_orig"


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(
    exports: PEExports,
    payload_kind: PayloadKind,
    shellcode_path: Optional[str],
) -> dict:
    orig = _orig_stem(exports.dll_name)
    payload_snippet = get_snippet(payload_kind, shellcode_path)

    return {
        "dll_name":       exports.dll_name,
        "orig_stem":      orig,
        "base":           exports.base,
        "exports":        exports.exports,
        "named_exports":  exports.named,
        "ordinal_exports": exports.ordinal_only,
        "payload_snippet": payload_snippet,
        "payload_kind":   payload_kind.value,
        "has_shellcode":  payload_kind == PayloadKind.SHELLCODE,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class GeneratedOutput:
    """Holds all generated file contents keyed by filename."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}

    def write(self, output_dir: str | os.PathLike) -> None:
        """Write all generated files to *output_dir*, creating it if needed."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for name, content in self.files.items():
            (out / name).write_text(content, encoding="utf-8")

    def __repr__(self) -> str:
        return f"<GeneratedOutput files={list(self.files)}>"


def generate(
    exports: PEExports,
    *,
    payload_kind: PayloadKind = PayloadKind.NONE,
    shellcode_path: Optional[str] = None,
    emit_cmake: bool = True,
) -> GeneratedOutput:
    """
    Generate proxy DLL source files from a parsed export table.

    Parameters
    ----------
    exports:
        Result of :func:`dll_proxy_gen.parser.parse_exports`.
    payload_kind:
        Payload to inject in DllMain on DLL_PROCESS_ATTACH.
    shellcode_path:
        Path to a raw binary shellcode file; only used when
        *payload_kind* is :attr:`PayloadKind.SHELLCODE`.
    emit_cmake:
        When *True* (default), also render a ``CMakeLists.txt``.

    Returns
    -------
    GeneratedOutput
        Container whose :meth:`~GeneratedOutput.write` method persists the
        files to disk.
    """
    env = _make_env()
    ctx = _build_context(exports, payload_kind, shellcode_path)
    result = GeneratedOutput()

    # proxy.c
    tmpl_c = env.get_template("proxy.c.j2")
    result.files["proxy.c"] = tmpl_c.render(**ctx)

    # proxy.def
    tmpl_def = env.get_template("proxy.def.j2")
    result.files["proxy.def"] = tmpl_def.render(**ctx)

    # CMakeLists.txt
    if emit_cmake:
        tmpl_cmake = env.get_template("CMakeLists.txt.j2")
        result.files["CMakeLists.txt"] = tmpl_cmake.render(**ctx)

    # shellcode.h — embed the raw binary as a C byte array
    if payload_kind == PayloadKind.SHELLCODE and shellcode_path:
        sc_bytes = Path(shellcode_path).read_bytes()
        result.files["shellcode.h"] = generate_shellcode_header(sc_bytes)

    return result
