# M3-RIG-UAC results (2026-11-21)

Package M3-RIG-UAC (docs/M3_DESIGN.json, wave 1). Run: `vm\rig-m3.ps1 -Mode all`, exit 0, 19:36-19:42 host time.
VM Inbound-Win11-Test, Windows 11 Enterprise LTSC evaluation 26100.1742, user `tester` (administrator), snapshot
`m3-uac-on` (ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1, EnableLUA=1; checked by `uac-check` after the
restore). Evidence: `E:\purge-build\gate-evidence\m3-rig-uac\` (host log, screenshots, `jobs\`, `guest\`,
`summary.json`). Method: vm/RIG.md section 13.

## Verdict

| Question | Answer |
|---|---|
| Does medium input reach a high dialog on this build? | **No.** 0 of 9 attempts across 4 methods reached the dialog (`guest\uipi.json` `medium_blocked_all=true`) |
| Does the control (high driver, same dialog) reach it? | **Yes.** 4 of 4 methods reached it (`control_reached=4/4`) |
| Can the secure desktop be answered from the host? | **Yes.** `keyboardputscancode` Alt+N gave error 1223; Alt+Y gave a high-integrity child. No fallback keys were needed |

So `m3-uac` can run unattended with host scancodes; the six-step manual checklist is not needed and no DECISIONS row
was written for it.

## UIPI probe, per attempt

Dialog: `m3probe dialog`, high integrity, foreground in all 8 cases (5 already in front, 3 after `AttachThreadInput`).
Drivers: medium = task at the limited run level, high = started by the elevated agent. Integrity levels are read
from each process's token and recorded in `drive.json`.

| Method | Attempt | Medium driver | High driver (control) |
|---|---|---|---|
| SendInput key | Alt+D (accelerator of "Delete") | inserted 4/4, **not reached** | reached |
| SendInput key | Enter (default button Cancel) | inserted 2/2, **not reached** | reached |
| SendInput mouse | click at the custom button's centre | inserted 3/3, **not reached** | reached |
| PostMessage | `TDM_CLICK_BUTTON` 1001 to the dialog | returned FALSE, error 5, **not reached** | reached |
| PostMessage | `WM_COMMAND` 1001 to the dialog | returned FALSE, error 5, not reached | not reached (TaskDialog ignores it; not a UIPI effect) |
| PostMessage | `BM_CLICK` to the child `Button` window | returned FALSE, error 5, **not reached** | reached |
| SendMessageTimeout | `TDM_CLICK_BUTTON` 1001 | returned 0, error 5, **not reached** | reached |
| UI Automation | list descendants | partial tree (6): three panes, the two button HWNDs, the title bar; no check box, no text | full tree (9 elements) |
| UI Automation | `InvokePattern.Invoke` on "Delete (probe)" | `InvalidOperationException`, **not reached** | reached |
| UI Automation | `TogglePattern.Toggle` on the check box | check box not visible to UIA, not reached | reached |

Notes:
- SendInput does not report the UIPI block (it says every event was inserted); only the dialog's own event log shows
  that nothing arrived. A broker test must judge by the journal or dialog state, never by the SendInput return value.
- PostMessage and SendMessage from medium fail with ERROR_ACCESS_DENIED (5), which matches the documented UIPI
  behaviour.
- The TaskDialog push buttons are real child `Button` windows (class `Button`, text "&Delete (probe)"), so
  `BM_CLICK` is a valid attack path for `m3-consent`, and UIPI blocks it.

## Secure desktop

| Answer | Prompt seen | Input desktop during the prompt | Keys | Outcome |
|---|---|---|---|---|
| No | `consent.exe` pid 3868, session 1; `uac-no-1-prompt.png` | `OpenInputDesktop` from high: error 5 (Winlogon desktop) | Alt+N `38 31 b1 b8` | `runas` failed with 1223 "The operation was canceled by the user"; `consent.exe` gone |
| Yes | `consent.exe` pid 3736, session 1; `uac-yes-1-prompt.png` | error 5 | Alt+Y `38 15 95 b8` | child pid 3248 at **high** integrity, user tester; `consent.exe` gone |

- The input desktop was `Default` before the prompts (`inputdesk-idle.json`) and again afterwards
  (`inputdesk-end.json`).
- `controlvm screenshotpng` captures the secure desktop: the screenshot shows the dimmed background with the UAC
  prompt ("Do you want to allow this app from an unknown publisher...", m3probe.exe, Yes / No).
- The prompt opens with **No** focused. A bare Enter from the host would decline, so `m3-uac` must send Alt+Y for Yes.

## Left manual

- Nothing for the scancode route.
- Still open by design: the `SendInput` check by hand on the VM with UAC on (M3_DESIGN.md 11.3), and the same matrix
  against the real broker dialog (`m3-consent`) once the broker exists.
