# StarConverter UI craft brief

## 1. Product and audience

StarConverter is a cross-platform desktop utility for planning and eventually executing recoverable
exFAT <-> NTFS conversions. Its primary audience is a technically aware person who understands
volumes, filesystems, verification, and recovery but should not need to reason about allocator or
journal internals for every decision. The application must also expose exact technical evidence for
operators and auditors.

## 2. Primary job and workflow

The core workflow is `SOURCE -> ANALYZE -> PLAN -> REVIEW -> EXPORT/CONVERT -> VERIFY`, with rollback
and recovery evidence visible wherever it exists. Selecting or editing any source, direction, or
guarantee input immediately invalidates all downstream evidence. A plan or export is actionable only
when its identity and digest remain bound to the current inputs and the user has explicitly reviewed
the exact preview.

## 3. Visual and interaction intent

The interface is a precise dark-black instrument panel, not a terminal costume. Use the canonical
ASCII wordmark `[ STAR :: CONVERTER ]`, compact rectangular surfaces, monospace typography, explicit
state tokens, and restrained status colors. The experience should feel portable and approachable in
the manner of HandBrake or 7-Converter: one obvious source, one obvious direction, a legible preflight
report, and advanced evidence available without dominating the main task.

## 4. Safety and accessibility requirements

Correctness is more important than speed or visual drama. Never select a physical device by default,
never imply a conversion is safe from stale evidence, and never hide rollback or recovery state.
Disabled actions need a visible textual reason in addition to hover help. Status cannot be conveyed
by color alone. Keyboard focus, screen-reader labels, copyable exact identifiers, escaped untrusted
paths, and stable layout during analysis are required. Until physical-device qualification is
complete, the UI must remain explicit that only regular image files are supported.

## 5. Learned constraints

- 2026-08-26: The product identity is text-only ASCII. Do not create or ship a pictogram, image logo,
  SVG logo, custom icon, Unicode star, or ornamental non-ASCII mark.
- 2026-08-27: Native visuals have not yet been captured in an automated rendering harness. Code-only
  review must be labeled as such until a reproducible egui snapshot or capture path exists.
- Evidence derived from a source path, direction, guarantee mode, or analyzed identity is invalid the
  instant any of those inputs changes.
