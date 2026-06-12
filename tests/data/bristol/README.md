# Bristol Fashion test circuits

The circuit files in this directory are vendored from Nigel Smart's
"Bristol Fashion" MPC circuit corpus:

  https://nigelsmart.github.io/MPC-Circuits/

They are used by `tests/test_bristol_parser.c` and
`examples/example_bristol_aes128.c` to validate `parsers/bristol.c`
against real-world circuits from the standard MPC/ZK comparison
baseline.

## Files

| File             | Purpose                                              |
|------------------|------------------------------------------------------|
| `aes_128.txt`    | AES-128 (Boyar-Peralta S-box, 6400 AND gates)        |
| `aes_256.txt`    | AES-256 (Boyar-Peralta S-box, 8832 AND gates)        |
| `neg64.txt`      | 64-bit two's-complement negation                     |
| `mult2_64.txt`   | 64x64 -> 128-bit unsigned multiply (hi || lo halves) |

Only a subset is currently exercised by tests; the rest are kept on
hand for future cross-validation or benchmarking work.

## Format

All files use the Bristol Fashion format (three header lines, a blank
line, then one gate per line). Numbers within multi-bit input/output
values are little-endian: wire 0 of each value carries the LSB. (The
AES files in this corpus are an exception: they encode 128-bit blocks
with reversed byte order; see the test code for details.)

## License

The original corpus is published by Nigel Smart for use by the
MPC/ZK research community. The files are redistributed here under
that permissive intent, with attribution. Please consult the upstream
site for the current canonical versions and any usage notes.
