# CXX-NETPBM-11 — ximtoppm stack out-of-bounds access when num_colors exceeds 256

**Project / component**: netpbm — `ximtoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-125 stack-buffer-overflow read (and one CWE-787 write site) — Low
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
`num_colors` is an ASCII field parsed with `atoi()` and used to walk a fixed 256-entry colour table.

## Root cause
```c
typedef struct ImageHeader {
    ...
    unsigned char c_map[256][3];      /* xim.h:39 — fixed 256 entries */
} ImageHeader;
...
headerP->ncolors = atoi(aHead.num_colors);          /* ximtoppm.c:123 — arbitrary 8-char decimal */
MALLOCARRAY_NOFAIL(headerP->colors, headerP->ncolors);
for (i = 0; i < headerP->ncolors; ++i) {
    headerP->colors[i].red = aHead.c_map[i][0];     /* ximtoppm.c:159 — stack over-read */
    ...
}
```

## Proof of concept
`poc/poc.xim` — 2048 bytes, produced by `gen_poc.py`: `num_colors` set to a value above 256.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-11-ximtoppm-ncolors-stack-overflow
ASAN_OPTIONS=detect_leaks=0 ximtoppm poc/poc.xim > /dev/null
```
Expected: UBSan `index 256 out of bounds for type 'unsigned char[256][3]'` at `ximtoppm.c:159`;
a plain build silently reads adjacent stack memory and writes it into the output image.
```

## Impact and threat model
Consumers of untrusted Xim images.

## Suggested fix
Reject `num_colors > 256` while parsing the header.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: no crash; adjacent stack bytes are copied into the output.

