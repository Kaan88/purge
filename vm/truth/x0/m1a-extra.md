# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| x0-npp-userfiles | ok | 11 | 0 | 0 | absent | True | plan_hash | 18ddd212234f / 18ddd212234f |
| x0-git-toolsdir | ok | 51 | 0 | 0 | Blocked | True | plan_hash | c53cea146939 / c53cea146939 |
| x0-ff-devedition | ok | 90 | 0 | 0 | Blocked | True | plan_hash | 2dd70d07ada9 / 2dd70d07ada9 |
| x0-vscode-with-user | ok | 600 | 0 | 0 | Blocked | True | plan_hash | 13977f3378e4 / 13977f3378e4 |
| x0-git-userstate | ok | 52 | 0 | 0 | Blocked | True | plan_hash | 7e3ac68f4156 / 7e3ac68f4156 |
| x0-thunderbird | ok | 169 | 0 | 0 | Blocked | True | plan_hash | f801421eccb7 / f801421eccb7 |
| x0-ff-tbafter | ok | 90 | 0 | 0 | Blocked | True | plan_hash | c911059608ed / c911059608ed |
| x0-vscode-userstate | ok | 744 | 0 | 0 | Blocked | True | plan_hash | 0ddb66efb932 / 0ddb66efb932 |
| x0-vscode-insiders-pair | ok | 742 | 0 | 0 | Blocked | True | plan_hash | 818c015dc447 / 818c015dc447 |
| x0-winmerge | ok | 39 | 0 | 0 | Blocked | True | plan_hash | 5305b397c98a / 5305b397c98a |
| x0-vscode-upgrade | ok | 742 | 0 | 0 | Blocked | True | plan_hash | 2b59aa26c6f0 / 2b59aa26c6f0 |
| x0-ff-esr | ok | 100 | 0 | 0 | Blocked | True | plan_hash | 0f1c201f7f24 / 0f1c201f7f24 |
| x0-vscode-zipcopy | ok | 744 | 0 | 0 | Blocked | True | plan_hash | b813025ebcda / b813025ebcda |
| x0-ff-reinstall | ok | 98 | 0 | 0 | Blocked | True | plan_hash | afc1e2d44c33 / afc1e2d44c33 |
| x0-git-upgrade | ok | 57 | 0 | 0 | Blocked | True | plan_hash | e849693a33be / e849693a33be |
