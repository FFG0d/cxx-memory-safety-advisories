# CXX-NETPBM-05 — pjtoppm NULL pointer dereference for a zero-length plane
the writer then dereferences every plane unconditionally, and only plane 0 is checked.

**Project / component**: netpbm — `pjtoppm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-476 NULL pointer dereference (DoS) with CWE-125 over-read — Low
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
A plane whose declared length is zero makes `realloc(buf, 0)` free the buffer and return NULL;
the writer then dereferences every plane unconditionally, and only plane 0 is checked.

## Root cause
```c
MALLOCARRAY(buf, newcols);
for (i = 0, col = 0; col < imlen[row * planes + plane]; col += 2) { ... }
cols = MAX(cols, i);
free(image[row * planes + plane]);
image[row * planes + plane] = realloc(buf, i);      /* pjtoppm.c:89 — i may be 0 */
```

```c
/* writePpm(): only plane 0 is checked for NULL, then all planes are dereferenced */
```

With a zero-length plane `i == 0`, so the plane pointer becomes NULL (or allocator-defined) and the
subsequent loop dereferences it.

## Proof of concept
`poc/poc.pj` — 38 bytes, produced by `gen_poc.py`: mode-1 PCL stream with one zero-length plane.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-05-pjtoppm-zero-plane-null-deref
ASAN_OPTIONS=detect_leaks=0 pjtoppm poc/poc.pj > /dev/null
```
Expected: UBSan reports `applying zero offset to null pointer` at `pjtoppm.c:133`, followed by a SEGV
under ASan; on allocators where `realloc(p,0)` returns a valid pointer the code reads out of bounds.
```

## Impact and threat model
Consumers of untrusted HP-PCL files.

## Suggested fix
Treat `realloc(..., 0)` as a failure (or allocate one element), and NULL-check every plane before use.

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`) with a
  clang `-O1 -g -fsanitize=address,undefined` build, two independent runs, identical stacks.
- The 11.15.04 tree was built from `netpbm-free_11.15.04+ds.orig.tar.xz`; configure then serial `make`
  (parallel make races on the shared `importinc/` symlinks).
- Also reproducible on 11.10.02.
- Not present in the CVE database (checked for the tool name and the affected function).
- Plain (non-instrumented) build: no crash on macOS/glibc allocations — the failure is allocator-dependent.

