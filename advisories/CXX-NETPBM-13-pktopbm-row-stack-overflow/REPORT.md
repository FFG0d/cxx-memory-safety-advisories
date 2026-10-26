# CXX-NETPBM-13 — pktopbm stack out-of-bounds write for a character wider than the row buffer
so a wide character writes past `row`.

**Project / component**: netpbm — `pktopbm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-121 stack-buffer-overflow write; without instrumentation it manifests as an infinite loop (DoS) — Medium
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
The row buffer holds 3201 entries but the character header's `cwidth` is only rejected above 65535,
so a wide character writes past `row`.

## Root cause
```c
#define MAXROWWIDTH 3200
...
bit row[MAXROWWIDTH+1];                     /* pktopbm.c:485 — 3201 entries */
...
if (cwidth < 0 || cheight < 0 ||
    cwidth > 65535 || cheight > 65535)      /* pktopbm.c:393-394 — far too permissive */
    *mustIgnoreP = true;
...
while (hbit--)                              /* hbit starts at cwidth */
    row[rp++] = turnon ? PBM_BLACK : PBM_WHITE;   /* pktopbm.c:544 */
```

## Proof of concept
`poc/poc.pk` — 76 bytes, produced by `gen_poc.py`: a PK font whose character 0 declares `cwidth` far
above `MAXROWWIDTH`.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-13-pktopbm-row-stack-overflow
ASAN_OPTIONS=detect_leaks=0 pktopbm -character 0 poc/poc.pk out.pbm
```
Expected: `stack-buffer-overflow` write report (`readOneCharacter pktopbm.c:544`); a plain build enters
an **infinite loop** (observed consuming CPU for minutes).
```

## Impact and threat model
Consumers of untrusted PK/GF bitmap fonts (TeX toolchains, font converters).

## Suggested fix
Reject `cwidth > MAXROWWIDTH` (and `cheight` beyond the format limit) before decoding a character.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) `-O2` build: the process spins in an infinite loop (DoS), it does not terminate.

