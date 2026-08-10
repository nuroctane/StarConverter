# StarConverter design system

## Context and goals

Design intent: a high-contrast native utility that feels like a precise black instrument panel whose
ASCII grammar makes filesystem state easier to scan, not like a terminal costume placed over a
generic application.

The interface must remain approachable to someone who understands “source,” “NTFS,” and “verify”
without requiring them to understand clusters or transaction journals. Technical details stay one
level below the primary workflow and remain available for audit.

## Design tokens and foundations

### Color

| Token | Value | Use |
| --- | --- | --- |
| `void` | `#050506` | Application canvas |
| `surface` | `#0A0B0C` | Primary panels |
| `surface-raised` | `#111315` | Controls and selected rows |
| `line` | `#292D32` | One-pixel frames and dividers |
| `line-strong` | `#59616B` | Focus and active boundaries |
| `ink` | `#F2F4F5` | Primary text |
| `ink-muted` | `#9AA1AA` | Secondary labels |
| `ink-faint` | `#626971` | Disabled and tertiary text |
| `ready` | `#7BFFB2` | Verified success only |
| `warning` | `#FFC857` | Needs attention; reversible |
| `danger` | `#FF6077` | Blocker, destructive, or failed |
| `working` | `#A8D8FF` | Active analysis/progress |

Pure white is reserved for high-priority text and the star mark. Status color must never be the only
signal: pair it with `[READY]`, `[WARN]`, `[BLOCKED]`, or `[ACTIVE]`.

### Typography

- Primary UI: `JetBrains Mono`, 14 px, fallback to the platform monospace font.
- Dense metadata: 12 px with at least 18 px line height.
- Section label: 12 px uppercase, letter spacing equivalent to 0.08 em.
- Page title: 24 px medium; do not exceed 30 px in the desktop utility.
- Numeric capacity values use tabular figures and right alignment.
- Avoid a decorative display face inside controls. The ASCII mark supplies identity.

### Spacing and shape

- Spacing scale: 4, 8, 12, 16, 24, 32 px.
- Touch/click targets must be at least 44 x 44 px even when the visual control is smaller.
- Panel radius: 2 px. Button radius: 2 px. Do not introduce pills except compact status capsules.
- Borders are one physical pixel where rendering permits; selected/focused elements use two pixels.
- No shadows, glass blur, gradients, fake scanlines, bloom, or ornamental CRT distortion.

### ASCII grammar

- Product mark: `[ STAR :: CONVERTER ]`.
- State: `[READY]`, `[ANALYZING]`, `[BLOCKED]`, `[ROLLBACK AVAILABLE]`.
- Process: `SOURCE -> PLAN -> TARGET`.
- Namespace or detail separator: `::`.
- Destructive actions use a leading `!` in technical/audit views, not in friendly button labels.
- ASCII frames may structure empty states and log output. They must not be individually announced by
  screen readers; accessible labels describe the contained state.

## Component-level rules

### Source picker

Anatomy: source icon, friendly volume name, device/image path, filesystem badge, capacity, and
health state. Default and hover use `surface`/`surface-raised`; focus-visible uses `line-strong` plus a
2 px inner outline; loading shows `[SCANNING]`; error preserves the selected path and explains why it
cannot proceed. Long paths middle-ellipsize visually but remain available through copy and tooltip.

Keyboard: Enter opens the picker, arrows move through detected sources, and Ctrl/Cmd+C copies the
stable identifier when the row is focused. Never auto-select the first physical device.

### Filesystem direction control

Anatomy: source filesystem, `->`, target filesystem, and a swap button. Only exFAT/NTFS directions
are enabled. Same-filesystem selection is disabled with the message “Source already uses NTFS” (or
exFAT), rather than silently swapping.

The swap control must never change the selected physical source; it only changes a synthetic/demo
direction or begins a new source selection.

### Guarantee-mode selector

Three equal-width choices: Strict, Escrow, Content only. Each choice includes one sentence describing
what is refused or preserved. Default is Strict. Selected state uses `surface-raised`, `ink`, and a
two-pixel boundary. Hover alone must not resemble selection. Disabled and error states explain which
detected feature caused the restriction.

### Preflight report

Rows are grouped into Identity, Geometry, Health, Semantics, Space, and Recovery. Each row contains a
plain label, exact value, status token, and optional disclosure. Blockers sort first within their
group. Empty state reads “Select an image or volume to begin analysis.” Loading rows reserve their
final height to avoid layout movement.

### Primary action bar

The bar always exposes Analyze, Save plan, and—only after the physical-device safety gate—Convert.
Convert must remain disabled until every blocker is cleared and the user has reviewed the plan.
Rollback appears beside Verify whenever recovery material exists; it is never hidden in an overflow
menu.

Default uses `ink` on `surface-raised`; hover strengthens the border; active shifts down by one pixel;
focus-visible draws a two-pixel `working` outline; disabled uses `ink-faint`; loading retains the
button label and adds `[WORKING]`; destructive confirmation uses `danger` but never flashes.

### Queue and activity log

Jobs display source, direction, phase, progress, and recovery status. The log is append-only in the
UI, selectable, copyable, and exportable as UTF-8 text/JSON. It follows the same ASCII grammar as the
CLI. Horizontal overflow is scrollable; technical tokens are never wrapped mid-value.

### Responsive behavior

- At 1100 px and wider: source rail, primary workbench, and activity rail.
- From 720–1099 px: activity moves below the workbench.
- Below 720 px: one column, persistent bottom action bar, 44 px targets, no side-by-side mode cards.
- Long localized labels may wrap to two lines without reducing target height or hiding the status.

## Accessibility requirements and testable acceptance criteria

- All normal text must meet WCAG 2.2 AA contrast; critical status text must meet 7:1 where practical.
- Every pointer action must be reachable by keyboard with a visible focus indicator at least 2 px
  thick and 3:1 against adjacent colors.
- Controls must expose accessible names, roles, values, disabled reasons, and progress state.
- Status must combine text/symbol and color; grayscale screenshots must remain understandable.
- Minimum interactive target is 44 x 44 px.
- Reduced-motion mode removes animated progress interpolation; numeric and textual progress remains.
- Screen-reader order must follow Source, Direction, Guarantee, Preflight, Action, Activity.
- ASCII art must be hidden from accessibility APIs and replaced by “StarConverter.”
- A 200% text-size test must not clip the selected source, blockers, or primary actions.

## Content and tone standards with examples

Use concise, literal, action-oriented language. State what StarConverter observed, why it matters,
and the safe next action.

- Good: `[BLOCKED] Volume is dirty. Repair it with the operating-system filesystem checker, then
  analyze again.`
- Bad: `Oops! Something went wrong with your disk.`
- Good: `Needs 12.4 GiB temporary space; 18.1 GiB is available.`
- Bad: `You should probably have enough room.`
- Good button: `Analyze source`.
- Bad button: `Let's go!`.

Never describe a downgrade as lossless. Use “content-only” when metadata cannot round-trip, and list
the exact affected feature count.

## Anti-patterns and prohibited implementations

- Do not auto-select, auto-format, or auto-finalize a physical device.
- Do not use a generic modal reading only “Are you sure?”; show device identity and consequence.
- Do not hide blockers behind an expert toggle.
- Do not use green for an operation that has merely started.
- Do not use fake terminal animation, matrix rain, scanline overlays, or low-contrast gray-on-black.
- Do not mix rounded consumer cards, glass panels, and ASCII frames.
- Do not communicate byte quantities using ambiguous decimal/binary units.
- Do not truncate stable device identifiers without a copy affordance.
- Do not disable a control without exposing the reason.

## QA checklist

- [ ] Canvas, surfaces, text, and all statuses use semantic tokens.
- [ ] Default, hover, focus-visible, active, disabled, loading, and error states are implemented.
- [ ] Keyboard-only flow can select an image, choose a mode, analyze, save a plan, and inspect logs.
- [ ] Focus is always visible and follows the documented order.
- [ ] Status remains understandable without color.
- [ ] All hit targets are at least 44 x 44 px.
- [ ] Empty, loading, blocker, insufficient-space, and recovery-available states are tested.
- [ ] Long paths, translated labels, narrow width, and 200% text do not hide critical controls.
- [ ] Reduced-motion mode does not remove progress information.
- [ ] ASCII decoration is excluded from accessible names.
- [ ] Convert is absent or disabled until the safety gate and preflight contract are satisfied.
