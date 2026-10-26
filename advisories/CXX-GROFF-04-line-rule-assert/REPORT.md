# CXX-GROFF-04 — Assertion failure (abort) while parsing line-drawing escapes

**Project / component**: groff
**Affected version**: groff 1.24.2
**Type / severity**: CWE-617 — Low (DoS)
**Discovery method**: manual source audit followed by structure-aware mutation of well-formed samples

## Summary
read_line_rule_expression() assumes the token produced by a line-drawing escape carries charinfo; a crafted sequence violates it and aborts.

## Root cause
`src/roff/troff/input.cpp:6131-6132 (read_line_rule_expression)`

```c
  assert (0 == "attempted to use token without charinfo in line-drawing escape sequence");
```

Missing-charinfo case handled by an assertion.

## Proof of concept
poc/poc.roff and poc/orig.roff.

Derivation from a well-formed sample: crafted line-drawing escape sequence.

## Reproduction
```bash
cd groff/CXX-GROFF-04-line-rule-assert
troff -F<font dir> -M<tmac dir> -Tps poc/poc.roff
```

Expected: Assertion failure at input.cpp:6132; exit code 134, also in a plain build.

## Impact and threat model
Formatting untrusted roff aborts the process.

## Suggested fix
Emit a diagnostic instead of asserting.

## Disclosure status
- Verified against groff 1.24.2; still reproducible at that revision.
- Not present in the CVE database (checked for the affected function/line).
- 
