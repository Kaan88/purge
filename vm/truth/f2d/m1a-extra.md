# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| f2d-firefox | ok | 92 | 0 | 0 | Blocked | True | plan_hash | 582743d0e10c / 582743d0e10c |
| f2d-vscode-user | ok | 596 | 0 | 0 | Blocked | True | plan_hash | f5e7812d83bf / f5e7812d83bf |
| f2d-git | ok | 46 | 0 | 0 | Blocked | True | plan_hash | 6df54fdbde85 / 6df54fdbde85 |
| f2d-npp | ok | 9 | 0 | 0 | absent | True | plan_hash | 3c2b1314a3da / 3c2b1314a3da |
| f2d-vlc | ok | 829 | 0 | 0 | Blocked | True | plan_hash | c9b31e6c3e7a / c9b31e6c3e7a |
