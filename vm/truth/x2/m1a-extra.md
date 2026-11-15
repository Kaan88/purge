# Extra checks (M-LIVE, M-DET)

Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; pass = `det_equal` (`plan_hash` of the two scans' `.scan.json` sidecars, or the file SHA-256).

| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |
|---|---|---:|---:|---:|---|---|---|---|
| x2-git-toolsdir | ok | 40 | 0 | 0 | absent | True | plan_hash | daccadc02918 / daccadc02918 |
| x2-git-userstate | ok | 52 | 0 | 0 | Blocked | True | plan_hash | 3d9f4318283a / 3d9f4318283a |
| x2-vscode-userstate | ok | 741 | 0 | 0 | Blocked | True | plan_hash | 5c865302cd98 / 5c865302cd98 |
| x2-vscode-zipcopy | ok | 734 | 0 | 0 | Blocked | True | plan_hash | 2a36ee5fa7fa / 2a36ee5fa7fa |
| x2-git-upgrade | ok | 52 | 0 | 0 | Blocked | True | plan_hash | 3ae1fde24194 / 3ae1fde24194 |
| x2-npp-userfiles | ok | 11 | 0 | 0 | absent | True | plan_hash | 1d039491eb33 / 1d039491eb33 |
| x2-ff-esr | ok | 90 | 0 | 0 | Blocked | True | plan_hash | c00d2e1ae9ce / c00d2e1ae9ce |
| x2-ff-devedition | ok | 91 | 0 | 0 | Blocked | True | plan_hash | 6c82ed204240 / 6c82ed204240 |
| x2-vscode-with-user | ok | 593 | 0 | 0 | Blocked | True | plan_hash | 3003e42e4831 / 3003e42e4831 |
| x2-thunderbird | ok | 169 | 0 | 0 | Blocked | True | plan_hash | 176282190531 / 176282190531 |
| x2-ff-tbafter | ok | 91 | 0 | 0 | Blocked | True | plan_hash | b3ca68df59e2 / b3ca68df59e2 |
| x2-vscode-insiders-pair | ok | 740 | 0 | 0 | Blocked | True | plan_hash | 36ef4acb7b49 / 36ef4acb7b49 |
| x2-vscode-upgrade | ok | 740 | 0 | 0 | Blocked | True | plan_hash | 0dc7a14a2b94 / 0dc7a14a2b94 |
| x2-ff-reinstall | ok | 98 | 0 | 0 | Blocked | True | plan_hash | f2dcd6d60b42 / f2dcd6d60b42 |
| x2-vlc | ok | 829 | 0 | 0 | Blocked | True | plan_hash | 426cc97eaa14 / 426cc97eaa14 |
| x2-winmerge | ok | 40 | 0 | 0 | Blocked | True | plan_hash | 5305b397c98a / 5305b397c98a |
