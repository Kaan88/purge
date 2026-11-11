# install (placeholder)

`install.ps1`, the v1 deploy script, lands in **M2** (ENGINE_PLAN.md §3.2, §11.1). It will:
- copy the engine (and, from M3, the UI) to `%ProgramFiles%\Purge`;
- create `C:\ProgramData\Purge` (sessions, quarantine, fingerprints, kb) with a protected DACL, so the
  broker never works in a directory a standard user could have pre-created or planted junctions in.

A real installer is an M7 item.
