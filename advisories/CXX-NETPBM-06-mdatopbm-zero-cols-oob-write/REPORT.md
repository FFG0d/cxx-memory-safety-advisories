# CXX-NETPBM-06 — mdatopbm heap out-of-bounds write when the header declares zero columns
pixel bytes per input byte before resetting the column pointer.

**Project / component**: netpbm — `mdatopbm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-787 heap-buffer-overflow write — Low
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
A header declaring zero columns yields a zero-length output row, but the renderer still writes 8
pixel bytes per input byte before resetting the column pointer.

## Root cause
```c
short yy;
pm_readlittleshort(ifP, &yy); nInRows = yy;
pm_readlittleshort(ifP, &yy); nInCols = yy;     /* mdatopbm.c:282-283 */
nOutCols = 8 * nInCols;                          /* mdatopbm.c:286 — 0 when nInCols == 0 */
...
data = pbm_allocarray(nOutCols, nOutRows);       /* mdatopbm.c:291 — 0 bytes per row */
```

`overflow2(nInCols, 8)` added in current upstream does not fire for `nInCols == 0`.

## Proof of concept
`poc/poc.mda` — 148 bytes, produced by `gen_poc.py`: a well-formed MDA image with the column field set
to zero.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-06-mdatopbm-zero-cols-oob-write
ASAN_OPTIONS=detect_leaks=0 mdatopbm poc/poc.mda > /dev/null
```
Expected: `heap-buffer-overflow` write report; a plain build silently corrupts the heap and emits a
7-byte PBM.
```

## Impact and threat model
Consumers of untrusted MDA/Hercules image files (retro-computing tooling, format converters).

## Suggested fix
Reject `nInCols == 0` (and negative values) before allocating the output array.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: no crash; the heap is silently corrupted and a malformed PBM is produced.

