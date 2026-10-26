# CXX-GROFF-01 — NULL pointer dereference in the file-iterator path (strdup result used before the NULL check)

**Project / component**: groff
**Affected version**: groff 1.24.2
**Type / severity**: CWE-476 — Low (DoS)
**Discovery method**: manual source audit followed by structure-aware mutation of well-formed samples

## Summary
troff builds a file_iterator whose name can be NULL; strdup(fn) is used before the NULL check on the following line, so a crafted document dereferences address 0.

## Root cause
`src/roff/troff/input.cpp:446`

```c
  char *s = strdup (fn);        /* line 446 */
  if (fn == 0)                  /* line 447: too late */
```

The NULL check happens after the value is already used.

## Proof of concept
poc/poc.roff (5 bytes changed relative to a bundled sample document) and poc/orig.roff.

Derivation from a well-formed sample: 5 single-byte changes; see finding notes.

## Reproduction
```bash
cd groff/CXX-GROFF-01-fiterator-strdup-null
troff -F<font dir> -M<tmac dir> -Tps poc/poc.roff
```

Expected: SIGSEGV at address 0; exit code 139 in a plain build (134 under instrumentation). Plain build crashes: no memory detection tool required.

## Impact and threat model
Any pipeline that formats untrusted roff/man input (documentation build systems, man-page viewers).

## Suggested fix
Move the NULL check before the first use.

## Disclosure status
- Verified against groff 1.24.2; still reproducible at that revision.
- Not present in the CVE database (checked for the affected function/line).
- 
