# Memory-safety advisories (C/C++ image and document parsers)

Reports, minimal proof-of-concept inputs and proposed patches for memory-safety
defects found in widely deployed C/C++ parsers: **netpbm** (image format
converters) and **GNU groff** (the `troff`/`man` typesetting toolchain).

Every advisory directory contains:

- `REPORT.md` - the technical report: affected code, root cause, impact, reproduction command
- `poc/` - the minimal input that triggers the defect, and any harness source
- `patch/` - the patch proposed in the original report
- `upstream.md` - how and when the report reached upstream, and what upstream did

All items were reported to the upstream maintainers before any CVE request.
Where upstream fixed a defect, the fix commit is linked; where upstream did not
confirm an item, that is stated explicitly rather than implied.

## Index

| Advisory | Project | Defect | Upstream | CVE request |
| --- | --- | --- | --- | --- |

| [`CXX-NETPBM-01-sgitopnm-rle-length-oob-write`](advisories/CXX-NETPBM-01-sgitopnm-rle-length-oob-write/REPORT.md) | netpbm | 01 sgitopnm rle length oob write | fixed | - |
| [`CXX-NETPBM-02-xwdtopnm-directcolor-ncolors0-oob-read`](advisories/CXX-NETPBM-02-xwdtopnm-directcolor-ncolors0-oob-read/REPORT.md) | netpbm | 02 xwdtopnm directcolor ncolors0 oob read | fixed | CAN-2026-2040234 |
| [`CXX-NETPBM-03-ilbmtoppm-id2string-nonul-oob-read`](advisories/CXX-NETPBM-03-ilbmtoppm-id2string-nonul-oob-read/REPORT.md) | netpbm | 03 ilbmtoppm id2string nonul oob read | fixed | CAN-2026-2040235 |
| [`CXX-NETPBM-04-pjtoppm-odd-plane-oob-read`](advisories/CXX-NETPBM-04-pjtoppm-odd-plane-oob-read/REPORT.md) | netpbm | 04 pjtoppm odd plane oob read | fixed | CAN-2026-2040231 |
| [`CXX-NETPBM-05-pjtoppm-zero-plane-null-deref`](advisories/CXX-NETPBM-05-pjtoppm-zero-plane-null-deref/REPORT.md) | netpbm | 05 pjtoppm zero plane null deref | fixed | CAN-2026-2040232 |
| [`CXX-NETPBM-06-mdatopbm-zero-cols-oob-write`](advisories/CXX-NETPBM-06-mdatopbm-zero-cols-oob-write/REPORT.md) | netpbm | 06 mdatopbm zero cols oob write | fixed | - |
| [`CXX-NETPBM-07-picttoppm-colormap-index-oob-read`](advisories/CXX-NETPBM-07-picttoppm-colormap-index-oob-read/REPORT.md) | netpbm | 07 picttoppm colormap index oob read | fixed | CAN-2026-2040233 |
| [`CXX-NETPBM-08-spctoppm-dochar-global-oob-write`](advisories/CXX-NETPBM-08-spctoppm-dochar-global-oob-write/REPORT.md) | netpbm | 08 spctoppm dochar global oob write | fixed | - |
| [`CXX-NETPBM-09-ddbugtopbm-uncompress-oob-write`](advisories/CXX-NETPBM-09-ddbugtopbm-uncompress-oob-write/REPORT.md) | netpbm | 09 ddbugtopbm uncompress oob write | fixed | - |
| [`CXX-NETPBM-11-ximtoppm-ncolors-stack-overflow`](advisories/CXX-NETPBM-11-ximtoppm-ncolors-stack-overflow/REPORT.md) | netpbm | 11 ximtoppm ncolors stack overflow | fixed | - |
| [`CXX-NETPBM-12-gouldtoppm-division-by-zero`](advisories/CXX-NETPBM-12-gouldtoppm-division-by-zero/REPORT.md) | netpbm | 12 gouldtoppm division by zero | fixed | - |
| [`CXX-NETPBM-13-pktopbm-row-stack-overflow`](advisories/CXX-NETPBM-13-pktopbm-row-stack-overflow/REPORT.md) | netpbm | 13 pktopbm row stack overflow | fixed | CAN-2026-2040683 |
| [`CXX-GROFF-01-fiterator-strdup-null`](advisories/CXX-GROFF-01-fiterator-strdup-null/REPORT.md) | groff | 01 fiterator strdup null | fixed | CAN-2026-2040158 |
| [`CXX-GROFF-04-line-rule-assert`](advisories/CXX-GROFF-04-line-rule-assert/REPORT.md) | groff | 04 line rule assert | fixed | CAN-2026-2040230 |

## Notes on provenance

- netpbm: all twelve items were reported to the netpbm maintainer on 2026-10-13.
  On 2026-10-26 he confirmed that he had verified each one and that the fixes are
  in release 11.16.02 (Advanced) and 11.02.31 (Stable); 10.86.52 (Super Stable)
  follows at the end of December 2026.
- groff: the five items were reported to `bug-groff@gnu.org` on 2026-10-16. Two
  became Savannah tickets (#68783, #68788) and are fixed upstream, and are
  published here. The remaining three were never turned into upstream tickets and
  are not published in this repository until upstream addresses them.

## Contact

hjh_nju - jinghaohu33@163.com

