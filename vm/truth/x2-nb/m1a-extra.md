# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| x2-nb-firefox-tb | ok | 86 | 0 | 0 | Blocked | True | plan_hash | 7319c8ff159d / 7319c8ff159d |
| x2-nb-vscode | ok | 739 | 0 | 0 | Blocked | True | plan_hash | 0a96e5ddb302 / 0a96e5ddb302 |
| x2-nb-vscode-user | ok | 738 | 0 | 0 | Blocked | True | plan_hash | 889b05bf2135 / 889b05bf2135 |
| x2-nb-git | ok | 44 | 0 | 0 | Blocked | True | plan_hash | b55b8846b3f3 / b55b8846b3f3 |
| x2-nb-npp | ok | 9 | 0 | 0 | absent | True | plan_hash | 78847b02d116 / 78847b02d116 |
