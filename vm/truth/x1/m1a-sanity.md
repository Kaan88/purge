# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/f0/ambient-f0.json`.

**Total residual: 0** over 0 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

