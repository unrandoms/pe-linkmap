# pe-linkmap

![pe-linkmap: inspect and compare DLL exports](assets/project-mark.svg)

Compare the exported interface of two Windows DLL releases without loading or executing either binary. Use the JSON report in CI, or attach the Markdown report to a release review.

## Install from this checkout

Requires Python 3.10 or newer. No published package is required.

```sh
python -m pip install .
pe-linkmap --help
```

If upgrading an environment with the old distribution installed, run `python -m pip uninstall dll-proxy-gen` first to avoid overlapping package files.

## Capture and compare

```sh
pe-linkmap inspect before.dll -o before.json
pe-linkmap inspect after.dll -o after.json
pe-linkmap diff before.json after.json --snapshots --format markdown -o changes.md
pe-linkmap diff before.dll after.dll --fail-on-breaking
```

Snapshots contain the SHA-256 of the exact bytes inspected, machine type, export names, ordinals, RVAs and forwarding targets. Names sharing an ordinal and ordinal-only exports are preserved. JSON output has stable key and export ordering.

| Change | Result |
| --- | --- |
| Removed name or ordinal | Structural break |
| Existing name moved to another ordinal | Structural break |
| Machine type changed | Structural break |
| Forwarding target changed | Review required |
| Added export | Reported, no structural break |
| RVA changed | Not treated as an interface break |

Exit codes: `0` for a successful report; `1` for a structural break when `--fail-on-breaking` is set; `2` for invalid input or an I/O error. A report is still written before exit code `1`.

## Scope and limits

This is an export-surface check, not a complete ABI compatibility verdict. It cannot establish parameter types, calling conventions, behavior, or whether an export is code or data. An unchanged export list does not prove compatibility. Forwarding changes require human review even when CI exits successfully.

The static parser supports PE32 and PE32+ files with an export directory. Inputs are limited to 64 MiB; malformed, unsupported or exportless files are rejected. Snapshots use schema version 1 and are validated before comparison. No network service or Windows installation is required.

## Development

```sh
python -m pip install '.[dev]'
python -m pytest -q
```

Tests cover aliases, ordinal-only exports, forwarded exports, malformed input, snapshot validation, comparison behavior and CLI exit codes. Fixtures are generated as bytes; tests do not execute DLLs.

## History and credits

Maintained by [unrandoms](https://github.com/unrandoms), under the [MIT License](LICENSE).

This project evolved from this repository's `dll-proxy-gen` implementation. Its parser and existing history remain; the new `pe_linkmap` package adds release inspection, snapshots and comparison. The legacy `dll-proxy-gen` command remains for compatibility and is not the interface described above. Renaming the project does not change authorship of existing commits or third-party components.
