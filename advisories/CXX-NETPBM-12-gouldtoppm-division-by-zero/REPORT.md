# CXX-NETPBM-12 — gouldtoppm division by zero when the header declares zero bits per pixel

**Project / component**: netpbm — `gouldtoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-369 division by zero (SIGFPE) — Low (DoS)
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
The header's `bitsperpixel` field is used as a divisor without a non-zero check.

## Root cause
```c
*bytesperline = (headerblk[5]<<8) | headerblk[4];
*bitsperpixel = (headerblk[7]<<8) | headerblk[6];      /* gouldtoppm.c:127 — never checked */
...
*cols = (*bytesperline)*8 / (*bitsperpixel);           /* gouldtoppm.c:134 — divide by zero */
```

## Proof of concept
`poc/poc.gould` — 896 bytes, produced by `gen_poc.py`: bytes 6..7 of the 512-byte header set to 0
while `bytesperline` is non-zero.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-12-gouldtoppm-division-by-zero
ASAN_OPTIONS=detect_leaks=0 gouldtoppm poc/poc.gould > /dev/null
```
Expected: **SIGFPE, rc=136** in both instrumented and plain builds.

## Impact and threat model
Consumers of untrusted Gould scanner images.

## Suggested fix
Reject `bitsperpixel == 0` (and values that do not divide evenly) while parsing the header.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) `-O2` build: **real crash**, SIGFPE rc=136, twice.

