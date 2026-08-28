# StarConverter native UI tokens

These tokens mirror the native `egui` implementation and `docs/DESIGN_SYSTEM.md`. Changes should be
made in all three places together.

## Color

| Token | RGB | Hex | Role |
| --- | --- | --- | --- |
| `void` | `5, 5, 6` | `#050506` | Application canvas |
| `surface` | `10, 11, 12` | `#0A0B0C` | Primary panels |
| `raised` | `17, 19, 21` | `#111315` | Controls and selected rows |
| `line` | `41, 45, 50` | `#292D32` | Frames and dividers |
| `line_strong` | `89, 97, 107` | `#59616B` | Focus and active boundaries |
| `ink` | `242, 244, 245` | `#F2F4F5` | Primary text and wordmark |
| `muted` | `154, 161, 170` | `#9AA1AA` | Secondary labels |
| `faint` | `132, 140, 150` | `#848C96` | Disabled and tertiary text |
| `ready` | `123, 255, 178` | `#7BFFB2` | Verified success only |
| `warning` | `255, 200, 87` | `#FFC857` | Reversible attention state |
| `danger` | `255, 96, 119` | `#FF6077` | Blocker, destructive, or failed |
| `working` | `168, 216, 255` | `#A8D8FF` | Active analysis and progress |

## Type and spacing

- Primary family: JetBrains Mono with platform monospace fallback.
- Primary UI size: 14 px; dense metadata: 12 px with at least 18 px line height.
- Spacing scale: 4, 8, 12, 16, 24, 32 px.
- Minimum interaction target: 44 x 44 px.
- Panel and button radius: 2 px. Borders: one physical pixel, two when focused or selected.

## Grammar and motion

- Wordmark: `[ STAR :: CONVERTER ]`.
- Flow: `SOURCE -> PLAN -> TARGET`.
- States: `[READY]`, `[ANALYZING]`, `[BLOCKED]`, `[ROLLBACK AVAILABLE]`.
- Details use `::`; no Unicode substitutes or decorative symbols.
- Motion communicates state only, respects reduced-motion settings, and never flashes destructive
  actions. No shadows, gradients, glass, bloom, fake scanlines, or CRT distortion.
