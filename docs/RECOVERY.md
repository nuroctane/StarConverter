# Copy-export verification and recovery

StarConverter's current production surface creates a new regular image. It does not modify the
source, overwrite an existing path, or access a physical device. In-place rollback/finalize remains
disabled until the serializer and operating-system qualification gates are complete.

## Keep these files together

An escrow-mode export produces:

- the new target image;
- `<target>.starconverter-escrow`; and
- console or saved-plan evidence containing the source, candidate, and logical-manifest SHA-256
  values.

The sidecar wraps the schema-v4 preservation payload in a checksummed envelope bound to the exact
source hash, candidate hash, manifest hash, and filesystem direction. Copying or renaming the image
and its sidecar together is safe; substituting another same-direction sidecar fails verification.
Back up both files before relying on the candidate.

## Verify a completed export

The read-only verifier validates the integrity and binding of the sidecar, re-hashes and reinspects the candidate, rebuilds
its logical manifest, and checks the embedded preservation payload. Supplying the original source
also proves that its bytes and filesystem match the export identity:

```powershell
starconverter verify-export "C:\images\target.img" `
  "C:\images\target.img.starconverter-escrow" `
  --source "C:\images\source.img"
```

Verification accepts regular files only and never opens any input for write. Do not treat an
unverified sidecar as recovery evidence.

Current publication uses hard links to obtain atomic create-new/no-clobber behavior. Both output
directories must therefore support hard links. In particular, requesting a final image or escrow
path directly on exFAT/FAT, or on another filesystem that does not implement hard links, fails
closed before exposing a completed name. Export to a supported local filesystem, verify and back
up the pair, and copy it to removable media separately if needed. Directory-entry persistence is
not yet forced with a platform-specific parent-directory barrier, so an operating-system or power
failure can still leave a partial or a lone sidecar even after file contents were flushed.

## If export was interrupted

The requested final candidate name is published only after the partial candidate and escrow have
been flushed, reinspected, hashed, and cross-checked. An interruption before publication can leave
a file whose name contains `.starconverter-partial-<process>-<sequence>`; it is not a completed
candidate and must never be renamed into place.

Safe response:

1. Confirm the original source still exists and remains unchanged.
2. Leave any partial artifact untouched while diagnosing the interruption.
3. If neither final path exists, retry the export; if a lone sidecar exists, choose another new
   candidate/sidecar pair so no existing path is overwritten.
4. Run `verify-export` on the completed image and sidecar, including `--source` when available.
5. Only after successful verification and a separate backup should an abandoned partial artifact
   be removed manually.

StarConverter deliberately does not auto-delete partial files discovered from earlier processes:
the application cannot prove ownership of an arbitrary pre-existing path after a crash.

## Existing final name or lone sidecar

The exporter never overwrites. If the requested image already exists, verify it rather than retrying
over it. If a bound sidecar exists but the requested final image does not, the process may have been
interrupted between sidecar and candidate publication. Preserve it for diagnosis, choose a new
sidecar/final pair for the retry, and do not infer that an image conversion completed.

## What escrow cannot do yet

The sidecar is integrity-checked, candidate-bound preservation evidence, but the current pre-alpha does not yet expose a
command that reapplies NTFS-only semantics after a later reverse conversion. It is not a substitute
for a source backup. Restoration, in-place rollback/finalize, physical-device recovery, and repair
operations remain explicit roadmap gates.

The Windows VHD qualification script is also validation-only: it attaches two repository fixtures
read-only with no drive letter and invokes CHKDSK without repair flags. It is not a recovery or
formatting command.
