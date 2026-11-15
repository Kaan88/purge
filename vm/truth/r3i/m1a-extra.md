# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| r3i-firefox | ok | 100 | 0 | 0 | Blocked | True | plan_hash | f203fea2840c / f203fea2840c |
| r3i-firefox-tb | ok | 93 | 0 | 0 | Blocked | True | plan_hash | 5d809dc6230f / 5d809dc6230f |
