# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| x0-ff-esr | ok | 90 | 0 | 0 | Blocked | True | plan_hash | d9fa48c29c3f / d9fa48c29c3f |
| x0-vlc | ok | 828 | 0 | 0 | Blocked | True | plan_hash | 14173df1df56 / 14173df1df56 |
