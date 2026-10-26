# CXX-NETPBM-04 — pjtoppm heap out-of-bounds read for a plane with an odd declared length
a plane with an odd declared length the last iteration reads `[col+1]` past the plane buffer.

**Project / component**: netpbm — `pjtoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-125 heap-buffer-overflow read — Low
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
In HP-PCL transfer mode 1, the decode loop assumes each RLE command consumes a byte pair, so for
a plane with an odd declared length the last iteration reads `[col+1]` past the plane buffer.

## Root cause
```c
for (i = 0, col = 0; col < imlen[row * planes + plane]; col += 2) {
    int cmd, val;
    for (cmd = image[row * planes + plane][col],
             val = image[plane + row * planes][col+1];   /* pjtoppm.c:76-77 */
         cmd >= 0 && i < newcols; --cmd, ++i)
        buf[i] = val;
}
```

When `imlen[...]` is odd, the last `col` equals `imlen-1` and `[col+1]` reads one byte past the end
of that plane.

## Proof of concept
`poc/poc.pj` — 39 bytes, produced by `gen_poc.py`: a PCL stream in mode 1 whose middle plane declares
an odd length.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-04-pjtoppm-odd-plane-oob-read
ASAN_OPTIONS=detect_leaks=0 pjtoppm poc/poc.pj > /dev/null
```
Expected: `heap-buffer-overflow` read report; a plain build silently over-reads one byte and keeps
producing output.
```

## Impact and threat model
Consumers of untrusted HP-PCL or HPGL/2 files (print pipelines, converters, document scanners).

## Suggested fix
Bound `col+1` by `imlen[...]`, or require an even plane length (and reject odd ones) while parsing
the plane table.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: no crash; one byte is silently over-read and the conversion continues.

