# CXX-NETPBM-08 — spctoppm global out-of-bounds write driven by the decoded-character counter
bound; the counter is controlled by the file's `bitmap_length` field.

**Project / component**: netpbm — `spctoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-787 global-buffer-overflow write — Medium (SIGBUS without instrumentation)
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
The decoded-character counter drives an index into a fixed 32000-byte static array with no upper
bound; the counter is controlled by the file's `bitmap_length` field.

## Root cause
```c
static char screen[ROWS*COLS/2];              /* spctoppm.c:23 — 32000 bytes */
...
static void DoChar(const int n, const char c) {
    i = 160 + 2 * (n / 7960) + 8 * ((n % 7960) / 2) + (n & 1);
    screen[i] = c;                             /* spctoppm.c:172 */
}
```

`DoBitmap()` decodes as many runs as the file's 32-bit `bitmap_length` demands; each run advances the
counter by up to 130.

## Proof of concept
`poc/poc.spc` — 2.0 MB, produced by `gen_poc.py`: a well-formed Spectrum `.spc` header with the bitmap
length raised so that the counter passes the end of `screen`.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-08-spctoppm-dochar-global-oob-write
ASAN_OPTIONS=detect_leaks=0 spctoppm poc/poc.spc > /dev/null
```
Expected: `global-buffer-overflow` write report; **a plain `-O2` build crashes with SIGBUS (rc=138)**, i.e.
the write leaves the data segment mapping.
```

## Impact and threat model
Consumers of untrusted ZX Spectrum `.spc` screen files.

## Suggested fix
Bound the character counter before computing the index in `DoChar()`, and reject `bitmap_length`
values larger than the format allows.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) `-O2` build: **real crash**, SIGBUS rc=138.

