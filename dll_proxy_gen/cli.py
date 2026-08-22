"""
Command-line entry point for dll-proxy-gen.

Usage examples
--------------
List all exports without generating output::

    dll-proxy-gen --list-exports version.dll

Generate proxy with no payload::

    dll-proxy-gen --target version.dll --output ./proxy/

Generate proxy that pops a MessageBox::

    dll-proxy-gen --target winmm.dll --output ./winmm_proxy/ --payload messagebox

Generate proxy that runs shellcode from a binary file::

    dll-proxy-gen --target dwmapi.dll --output ./dwmapi_proxy/ \\
                  --payload shellcode --shellcode-file calc.bin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .parser import parse_exports, PEExports
from .generator import generate
from .payload import PayloadKind, list_payloads


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_exports(pe: PEExports, verbose: bool = False) -> None:
    print(f"DLL name  : {pe.dll_name}")
    print(f"Ordinal base: {pe.base}")
    print(f"Total exports: {len(pe.exports)}")
    print(f"  Named       : {len(pe.named)}")
    print(f"  Ordinal-only: {len(pe.ordinal_only)}")
    if verbose:
        print()
        header = f"{'Ordinal':>8}  {'RVA':>10}  Name"
        print(header)
        print("-" * len(header))
        for exp in sorted(pe.exports, key=lambda e: e.ordinal):
            name = exp.name or "<no name>"
            print(f"{exp.ordinal:>8}  0x{exp.rva:08x}  {name}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dll-proxy-gen",
        description=(
            "Generate DLL proxy forwarding stubs from an existing Windows DLL.\n"
            "The output .c / .def / CMakeLists.txt files can be compiled into a\n"
            "proxy DLL that forwards all calls to the original DLL and optionally\n"
            "runs a payload on load."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Main mode (mutually exclusive)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--target", "-t",
        metavar="DLL",
        help="Path to the target DLL to proxy.",
    )
    mode.add_argument(
        "--list-exports", "-l",
        metavar="DLL",
        dest="list_exports",
        help="Print all exports from the DLL and exit (no files generated).",
    )

    # Output
    p.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="./proxy_output",
        help="Directory to write generated files into (default: %(default)s).",
    )

    # Payload
    valid_payloads = list_payloads()
    p.add_argument(
        "--payload",
        choices=valid_payloads,
        default=PayloadKind.NONE.value,
        help=(
            f"Payload to inject on DLL_PROCESS_ATTACH "
            f"(choices: {', '.join(valid_payloads)}; default: %(default)s)."
        ),
    )
    p.add_argument(
        "--shellcode-file",
        metavar="BIN",
        help="Raw binary shellcode file; required when --payload shellcode is used.",
    )

    # Misc
    p.add_argument(
        "--no-cmake",
        action="store_true",
        help="Do not generate a CMakeLists.txt file.",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print all parsed exports before generating.",
    )

    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --list-exports mode
    if args.list_exports:
        try:
            pe = parse_exports(args.list_exports)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        _print_exports(pe, verbose=True)
        return 0

    # --target mode
    payload_kind = PayloadKind(args.payload)

    # Validate shellcode argument
    if payload_kind == PayloadKind.SHELLCODE and not args.shellcode_file:
        parser.error("--shellcode-file is required when --payload shellcode is used")
    if args.shellcode_file and not Path(args.shellcode_file).exists():
        print(f"error: shellcode file not found: {args.shellcode_file}", file=sys.stderr)
        return 1

    # Parse exports
    try:
        pe = parse_exports(args.target)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        _print_exports(pe, verbose=True)
        print()

    if not pe.exports:
        print(f"warning: {args.target!r} has no exports; generated files will be empty stubs.",
              file=sys.stderr)

    # Generate
    output = generate(
        pe,
        payload_kind=payload_kind,
        shellcode_path=args.shellcode_file,
        emit_cmake=not args.no_cmake,
    )

    output.write(args.output)

    out_path = Path(args.output).resolve()
    print(f"Generated {len(output.files)} file(s) in {out_path}:")
    for name in sorted(output.files):
        print(f"  {name}")

    orig_stem = f"_{Path(pe.dll_name).stem.lower()}_orig"
    dll_stem  = Path(pe.dll_name).stem.lower()
    print()
    print("Next steps:")
    print(f"  1. Rename the original {pe.dll_name} to {orig_stem}.dll")
    print(f"  2. Compile proxy.c into {dll_stem}.dll (see CMakeLists.txt or compile manually).")
    print(f"  3. Place {dll_stem}.dll alongside the target application.")
    print()
    print("MSVC (x64):  cl /LD /Fe:{dll_stem}.dll proxy.c /DEF:proxy.def")
    print(f"MinGW (x64): gcc -shared -o {dll_stem}.dll proxy.c -Wl,--kill-at")
    return 0


if __name__ == "__main__":
    sys.exit(main())
