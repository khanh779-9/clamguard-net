#!/usr/bin/env python3
"""Compare ClamAV bytecode API names with ClamGuard's managed dispatcher.

Usage:
  python tools/check_clambc_api.py /path/to/clamav-1.5.4/libclamav/bytecode_api_decl.c
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print(__doc__.strip())
    raise SystemExit(2)

native = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
managed = Path(__file__).resolve().parents[1] / "src/ClamGuard.Bytecode/ClamBcEngine.cs"
source = managed.read_text(encoding="utf-8")

native_api = sorted(set(re.findall(r"cli_bcapi_([A-Za-z0-9_]+)\s*\(", native)))
try:
    dispatcher = source.split("return name switch", 1)[1].split("_ => throw", 1)[0]
except IndexError:
    print("ERROR: managed API dispatcher not found", file=sys.stderr)
    raise SystemExit(1)
managed_api = sorted(set(re.findall(r'"([a-z0-9_]+)"', dispatcher)))

missing = [x for x in native_api if x not in managed_api]
extra = [x for x in managed_api if x not in native_api]
print(f"ClamAV API names : {len(native_api)}")
print(f"Managed API names: {len(managed_api)}")
print(f"Missing          : {len(missing)}")
if missing:
    for name in missing:
        print(f"  - {name}")
print(f"Extra            : {len(extra)}")
if extra:
    for name in extra:
        print(f"  + {name}")
if missing or extra:
    raise SystemExit(1)
print("PASS: ClamGuard dispatcher covers every ClamAV 1.5.4 bytecode API name.")
