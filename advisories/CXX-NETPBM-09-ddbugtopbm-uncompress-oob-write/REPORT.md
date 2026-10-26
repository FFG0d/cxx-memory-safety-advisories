# CXX-NETPBM-09 — ddbugtopbm global out-of-bounds write driven by the sketch length field
a fixed 64 KiB static buffer; the RLE decoder never validates the output index.

**Project / component**: netpbm — `ddbugtopbm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-787 global-buffer-overflow write — Medium (SIGBUS without instrumentation)
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
The decompressed length of every sketch record is taken from the record itself and used to write into
a fixed 64 KiB static buffer; the RLE decoder never validates the output index.

## Root cause
```c
static unsigned char obuf[64*1024];                       /* ddbugtopbm.c:127 */
int const sketchlen = buf[8]*256+buf[9];                  /* 16-bit length from the file */
uncompress_sketch(buf+26+80+1, obuf, sketchlen-80-1);      /* ddbugtopbm.c:143 */
...
static void
uncompress_sketch(unsigned char * const cPtr, unsigned char * const uPtr, int const size) {
    ...
    for (i=0; i<size; ++i) { ... }     /* no bound on the output index */
```

## Proof of concept
`poc/poc.ddb` — 2134 bytes, produced by `gen_poc.py`. Note: `ddbugtopbm` reads only from standard input.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-09-ddbugtopbm-uncompress-oob-write
ASAN_OPTIONS=detect_leaks=0 ddbugtopbm < poc/poc.ddb > /dev/null
```
Expected: `global-buffer-overflow` write report (`uncompress_sketch ddbugtopbm.c:58`); **a plain build
crashes with SIGBUS (rc=138)**.
```

## Impact and threat model
Consumers of untrusted DiddleBug sketch files.

## Suggested fix
Validate `sketchlen` against the record length and against `sizeof(obuf)` before decompressing.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: **real crash**, SIGBUS rc=138.

