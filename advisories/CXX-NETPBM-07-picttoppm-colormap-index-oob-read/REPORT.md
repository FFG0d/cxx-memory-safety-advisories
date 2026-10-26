# CXX-NETPBM-07 — picttoppm heap out-of-bounds read when a raster index exceeds the colour table
with the file-declared `ctSize`; no upper bound is enforced.

**Project / component**: netpbm — `picttoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-125 heap-buffer-overflow read — Low
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
An 8-bpp PICT bitmap uses raster bytes directly as colour-table indices while the table is allocated
with the file-declared `ctSize`; no upper bound is enforced.

## Root cause
```c
MALLOCARRAY(colorTable, ctSize + 1);          /* picttoppm.c:2246 — ctSize from the file */
...
for (colNumber = 0; colNumber < xsize; ++colNumber) {
    unsigned int const colorIndex = srcrow[colNumber];   /* 0..255, unchecked */
    ...
    putRgb(colorMap[colorIndex], dstCursor, dst);        /* picttoppm.c:1609 */
}
```

`readColorTable()` only validates indices *inside* the table entries, not the raster indices.

## Proof of concept
`poc/poc.pict` — 3036 bytes: a well-formed PICT produced by the project's own `ppmtopict`, with exactly
one byte changed (the colour-table size field) so that raster indices exceed the table.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-07-picttoppm-colormap-index-oob-read
ASAN_OPTIONS=detect_leaks=0 picttoppm poc/poc.pict > /dev/null
```
Expected: `heap-buffer-overflow` read report; a plain build silently emits a PPM built from
out-of-bounds table entries.
```

## Impact and threat model
Consumers of untrusted QuickTime/PICT images.

## Suggested fix
Clamp `colorIndex` against the allocated table size (or reject bitmaps whose pixel values exceed
`ctSize`).

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Note: Debian's `10_netpbm-security-code.patch` adds `#error "Unfixable. Don't ship me"` at the top of
  `converter/ppm/picttoppm.c`, so Debian/Ubuntu do not build this program; the defect still exists in
  the upstream tarball.
- Plain (non-instrumented) build: no crash; an out-of-bounds PPM is silently produced.

