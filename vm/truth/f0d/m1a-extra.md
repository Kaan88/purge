# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| f0d-firefox | ok | 92 | 0 | 0 | Blocked | True | plan_hash | 56d0847d9a8f / 56d0847d9a8f |
| f0d-vscode-user | ok | 598 | 0 | 0 | Blocked | True | plan_hash | f9ef21a706ac / f9ef21a706ac |
| f0d-git | ok | 46 | 0 | 0 | Blocked | True | plan_hash | 37074e6e9c84 / 37074e6e9c84 |
| f0d-npp | ok | 9 | 0 | 0 | absent | True | plan_hash | e7448790eab5 / e7448790eab5 |
| f0d-vlc | ok | 829 | 0 | 0 | Blocked | True | plan_hash | 158b715d20af / 158b715d20af |
