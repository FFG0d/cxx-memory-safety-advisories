# CXX-NETPBM-02 — xwdtopnm heap out-of-bounds read when a DirectColor XWD declares ncolors = 0

**Project / component**: netpbm — `xwdtopnm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-125 heap-buffer-overflow read — Low (information disclosure, possible crash)
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
An XWD file whose header declares the DirectColor visual class with `ncolors = 0` makes `xwdtopnm` allocate a zero-entry colour table and then index it with pixel-derived indices.

## Root cause
The colour table is allocated with the file-supplied `ncolors` and there is no lower-bound check:

```c
*colorsP = pnm_allocrow(h11FixedP->ncolors);   /* xwdtopnm.c:603, ncolors may be 0 */
for (i = 0; i < h11FixedP->ncolors; ++i)       /* zero iterations */
    PPM_ASSIGN((*colorsP)[i], ...);
```

Pixel decoding later turns mask bits into an index and reads the table:

```c
redIndex = (pixel & compMask.red) >> zeroBits(compMask.red);   /* xwdtopnm.c:1251 area */
PPM_ASSIGN(xelrow[col], colorsP[redIndex].r, colorsP[greenIndex].g, colorsP[blueIndex].b);
```

With `ncolors = 0` the table has zero entries, so every pixel indexes out of bounds.

## Proof of concept
`poc/poc.xwd` — 135 bytes, produced by `gen_poc.py`. It is a well-formed 1x1 XWD stream whose
header differs in the `ncolors` field (set to 0) and in the visual class (DirectColor).
Any XWD written by the project's own `pnmtoxwd` on a DirectColor visual reproduces the shape.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-02-xwdtopnm-directcolor-ncolors0-oob-read
ASAN_OPTIONS=detect_leaks=0 xwdtopnm poc/poc.xwd > /dev/null
```
Expected: `heap-buffer-overflow` read report in `xwdtopnm`, or (without instrumentation) a silently
produced PPM that contains bytes read past the colour-table allocation.
```

## Impact and threat model
Tools that convert untrusted X11 screen dumps (`.xwd`) — screenshot pipelines, image converters,
forensic tooling. The read address is attacker-influenced through the pixel data, so the practical
impact is information disclosure into the output image.

## Suggested fix
Reject `ncolors == 0` (and, more generally, clamp pixel indices to the allocated table size) when the
header declares DirectColor.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: does not crash; it silently emits a PPM (the over-read is not observable without instrumentation).

