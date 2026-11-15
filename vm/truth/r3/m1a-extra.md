# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| r3-firefox | ok | 101 | 0 | 0 | Blocked | True | plan_hash | be6d71c50d49 / be6d71c50d49 |
| r3-firefox-tb | ok | 93 | 0 | 0 | Blocked | True | plan_hash | f3748233b0b6 / f3748233b0b6 |
| r3-ff-esr | ok | 88 | 0 | 0 | Blocked | True | plan_hash | 3fc3fb96ffec / 3fc3fb96ffec |
