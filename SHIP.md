# Shipping StarConverter

The canonical shipping policy is `C:\Users\david\.agents\SHIP.md`.

For this repository the required sequence is:

1. Run format, lint, and tests.
2. Commit the relevant work on `main`.
3. Push `origin main`.
4. Create a dated 7z archive under `D:\BACKUP\CODE Backups\StarConverter\`, excluding
   `.git`, `target`, `dist`, and generated disk images.
5. Report the commit hash and subject, `origin/main`, and the full archive path.

Preferred command:

```powershell
powershell -File $env:USERPROFILE\.agents\ship.ps1 -Repo StarConverter -Message "<subject>"
```
