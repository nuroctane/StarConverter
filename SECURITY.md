# Security policy

StarConverter will eventually handle raw block devices. A defect can cause permanent data loss even
when it is not a conventional security vulnerability.

Do not test unpublished write paths on a device containing valuable data. Use disposable image files
until the physical-device gate in `docs/SAFETY.md` has been explicitly satisfied.

Report vulnerabilities and data-integrity defects privately to `nuroctane@gmail.com`. Include the
StarConverter commit, operating system, source and target filesystem geometry, an anonymized planner
report, and the smallest reproducible image when possible. Do not attach personal disk images.
