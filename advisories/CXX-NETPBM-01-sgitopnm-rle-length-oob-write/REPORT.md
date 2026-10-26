# CXX-NETPBM-01 — sgitopnm RLE scanline length is not validated against the decode buffer (heap overflow write)

**Project / component**: netpbm — `sgitopnm`
**Affected version**: netpbm 11.15.04 (current upstream; also verified on 11.10.02)
**Type / severity**: CWE-787 heap-buffer-overflow write (can escalate to CWE-122) — Medium
**Discovery method**: manual source audit, then structure-aware mutation of a well-formed sample

## Summary
An SGI image using RLE storage declares per-scanline compressed lengths in its offset table. `sgitopnm` reads each scanline into a buffer sized `WORSTCOMPR(xsize) == 2*xsize + 2` elements, but uses the file-supplied 32-bit `length` as the loop bound, so the read loop overwrites heap memory past that buffer.

## Root cause
`converter/other/sgitopnm.c`

```c
#define WORSTCOMPR(x)   (2*(x) + 2)
...
MALLOCARRAY_NOFAIL(temp, WORSTCOMPR(head->xsize));   /* sgitopnm.c:381 */
...
long const length = table[sgiIndex].length;          /* sgitopnm.c:398-400, straight from the file */
for (i = 0; i < length; ++i)
    temp[i] = getByteAsShort(ifP);                   /* sgitopnm.c:408-412 */
rleDecompress(temp, length, image[iindex], head->xsize);
```

With `xsize = 8` the buffer holds 18 `ScanElem` (36 bytes) while `length` can be any 32-bit value.

## Proof of concept
`poc/poc.sgi` — 1024 KiB, produced by `gen_poc.py`.
Header: magic 0x01DA, storage=1 (RLE), bpc=1, dimension=3, xsize=8, ysize=1, zsize=1, pixmax=255, ncolors=0; the offset table declares start=520 and length=0x100000, followed by 1 MiB of data so the copy loop can keep reading after it has left the buffer.

## Reproduction
```bash
cd netpbm/CXX-NETPBM-01-sgitopnm-rle-length-oob-write
ASAN_OPTIONS=detect_leaks=0 sgitopnm poc/poc.sgi > /dev/null
```
Expected:
WRITE of size 2 at ... thread T0
    #0 readChannels sgitopnm.c:410
    #1 main sgitopnm.c:512
0x... is located 0 bytes to the right of 36-byte region
SUMMARY: AddressSanitizer: heap-buffer-overflow sgitopnm.c:410 in readChannels
```

## Impact and threat model
Any consumer of untrusted SGI images (conversion pipelines, thumbnailing, forensic tooling). The overflow size is derived from the file, so it is a textbook heap corruption primitive.

## Suggested fix
Reject `length > WORSTCOMPR(head->xsize)` while reading the offset table (or decode using the actual number of bytes read).

## Disclosure status
- Verified on netpbm 11.15.04 (current upstream; Debian sid ships `2:11.15.04+ds-1`), clang `-O1 -g -fsanitize=address,undefined`, two independent runs, identical stacks.
- Also reproducible on 11.10.02 (ASan) and, without instrumentation: on 11.10.02 with `-O2` the same PoC gave 4 SIGSEGV out of 20 runs, and on netpbm 10.0 with `-O2` 10 SIGSEGV out of 10 runs — an intermittent but real crash whose hit rate depends on heap layout.
- Not present in the CVE database (checked for `sgitopnm` and for the RLE decode path).
