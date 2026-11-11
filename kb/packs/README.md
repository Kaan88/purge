# kb/packs

One JSON file per app family (ENGINE_PLAN.md §5.9): `match`, `vendor_aliases`, `leftovers`,
`parent_if_empty`, `protect`, `user_data`, `file_assoc`, `max_weight`. `purge-engine kb lint` rejects any
pack that resolves into a deny-list rule or a secrets store.

Empty until M4. First packs planned: Mozilla, VS Code, Git, Python, WinMerge, Notepad++, 7-Zip.
