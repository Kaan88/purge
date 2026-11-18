# Future ideas (not in any milestone yet)

Collected from discussions with the user. Each needs its own design and a Fable review before work starts.

## AI for residue (2026-11-17, 2026-11-18)

- AI works only on what the engine's scanners found. It adds no item to a plan, and it never marks an item Safe.
  Every item still goes through the guard, the deny lists, the bands and quarantine with undo.
- Uses: rank and explain unproven items (Likely, Weak); a plain-language line per item in the review; draft knowledge
  base entries (shared components, installer families, vendor folders) for a human to approve; recognise Windows
  background churn; answer "why was X kept?" from the scan's evidence.
- Later, "suggest where to look": AI proposes locations, the engine scans them with its own rules. Nothing AI-originated
  enters a plan directly.

## User override of the engine (2026-11-18)

- Unproven items (Likely, Weak) can already be ticked by the user.
- Soft blocks (owner unknown, too large, unrecognised data refers to it): overridable only by an explicit action that
  names the item and the reason it was held; always quarantine with undo, never a direct purge; logged.
- Hard blocks (deny list: Windows core, Windows-managed stores, items another installed app still uses): never
  overridable.
- AI agreement is not evidence and unlocks nothing by itself.

## Community knowledge base (2026-11-18)

- A public GitHub repository for the knowledge base (shared components, app leftovers, vendor folders, later the release
  baseline packs).
- Pull requests are scrutinised (user, 2026-11-18): reviewed by maintainers, rig-tested on the VMs where possible.
- Entries can only add places to look and evidence; they can never weaken the guard. The deny list still refuses a
  malicious entry that points at Windows.
- Releases are signed; the engine accepts only signed data.
- Contributions are opt-in, drafted from a user's scan and scrubbed of user names, SIDs and personal paths before
  anything leaves the PC.

## Other

- Footprint section: a WizTree-like disk map; per-app cache cleaning for installed apps (no generic cleaner).
