#!/usr/bin/env python3
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

"""
Read FULL_U, FULL_C, FULL_VS, FULL_QS from stdin and compute SHAKE-256 hashes.
Usage: ./diag_convert | python3 compute_hashes.py
"""
import sys
from hashlib import shake_256

KEYS = ("FULL_U", "FULL_C", "FULL_VS", "FULL_QS")

def to_c_array(data, name):
    cols = 8
    lines = [f"    static const uint8_t {name}[64] = {{"]
    for i in range(0, 64, cols):
        chunk = data[i:i+cols]
        row = ", ".join(f"0x{b:02x}" for b in chunk)
        comma = "," if i + cols < 64 else ""
        lines.append(f"        {row},{comma}")
    lines.append("    };")
    return "\n".join(lines)

vals = {}
for line in sys.stdin:
    line = line.strip()
    matched = False
    for key in KEYS:
        if line.startswith(key + "="):
            vals[key] = bytes.fromhex(line[len(key)+1:])
            matched = True
    if not matched:
        print(line)

mapping = [
    ("FULL_U",  "expected_hashed_u"),
    ("FULL_C",  "expected_hashed_c"),
    ("FULL_VS", "expected_hashed_v"),
    ("FULL_QS", "expected_hashed_q"),
]
for key, name in mapping:
    if key in vals:
        h = shake_256(vals[key]).digest(64)
        print(f"\n/* {key} -> {name} */")
        print(to_c_array(h, name))
        print(f"    /* first 8 bytes: {h[:8].hex()} */")
