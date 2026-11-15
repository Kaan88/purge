# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| x0-nb-firefox-tb | ok | 86 | 0 | 0 | Blocked | True | plan_hash | 22abe257ba52 / 22abe257ba52 |
| x0-nb-vscode | ok | 741 | 0 | 0 | Blocked | True | plan_hash | 0a96e5ddb302 / 0a96e5ddb302 |
| x0-nb-vscode-user | ok | 740 | 0 | 0 | Blocked | True | plan_hash | 572c90d3f65e / 572c90d3f65e |
| x0-nb-git | ok | 43 | 0 | 0 | Blocked | True | plan_hash | a5189cefc038 / a5189cefc038 |
| x0-nb-npp | ok | 9 | 0 | 0 | absent | True | plan_hash | 78847b02d116 / 78847b02d116 |
