# CXX-NETPBM-03 — ilbmtoppm out-of-bounds read when formatting a non-terminated 4-byte chunk ID
`%s`, so `pm_message()` reads past the end of that global array.

**Project / component**: netpbm — `ilbmtoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-125 global-buffer-overflow read — Low (information disclosure in a message)
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
`ID2string()` returns a 4-byte static buffer that is not NUL-terminated; it is then passed to
`%s`, so `pm_message()` reads past the end of that global array.

## Root cause
```c
static char *
ID2string(IFF_ID const id) {
    static char str[4];          /* ilbmtoppm.c:104 — exactly 4 bytes, never NUL-terminated */
    str[0] = ...; str[1] = ...; str[2] = ...; str[3] = ...;
    return str;
}
...
default:
    pm_message("unknown chunk type %s - skipping", ID2string(iffid));   /* ilbmtoppm.c:2363-2364 */
```

## Proof of concept
`poc/poc.iff` — 20 bytes, produced by `gen_poc.py`: a minimal IFF/ILBM stream whose chunk ID is not one
of the recognised four-character codes, which drives execution into the `default:` branch above.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-03-ilbmtoppm-id2string-nonul-oob-read
ASAN_OPTIONS=detect_leaks=0 ilbmtoppm poc/poc.iff > /dev/null
```
Expected: `global-buffer-overflow` read report in `ID2string`/`pm_message`; a plain build prints
out-of-bounds bytes after the chunk ID.
```

## Impact and threat model
Any consumer of untrusted IFF/ILBM images. The over-read bytes are printed through a diagnostic
message, so the leak surface is the message stream (stderr / log files).

## Suggested fix
Terminate the buffer with `\0` on the fifth byte (`static char str[5]`), or format the ID with a
bounded `%.4s`.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: no crash; the tool prints the over-read bytes after the chunk ID and exits rc=1.

