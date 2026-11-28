# M6: the assistant (AI advice on leftovers)

Plan of 2026-11-28, by the milestone designer (Fable). Branch `plan/m5-m6`. Nothing here is built yet.

The user's decision of 2026-11-28: v1.0 is M4 + M5 + M6 with their UI; evals and VM gates wait until after 1.0.
This replaces the DECISIONS row of 2026-11-22 that made M6 release 1.2.

Sources: ENGINE_PLAN D7, §3.3 (the agent row), §5.8.6, §5.9 (M6 lifecycle), §8, §9.4 (S5, S6), §11.1;
BASELINE_LOCAL_DESIGN §7 (residue and advice, already in `purge-model/src/residue.rs`); FUTURE_IDEAS ("AI for
residue", "User override", "Community knowledge base"); the code at `ui/rust` 348b861. Section 9 lists where this
plan departs from ENGINE_PLAN and why.

The rules this milestone is built around, in the user's words and the DECISIONS': AI suggests where to look; the
engine scans with its own rules; nothing that comes from AI enters a plan directly; AI agreeing is not evidence;
personal data never goes to an outside service without consent.

## 1. What it means for the user

An optional assistant on the Leftovers page. It reads a cleaned description of what the scan found and can do
four things, none of which removes anything or ticks anything:

| The assistant can | What happens in Purge |
|---|---|
| **Give an opinion on unproven items** ("this looks like part of Windows", "this looks like the app's") | A note on the item. "Looks like Windows" moves the item one band down. "Looks like the app's" changes nothing but the note |
| **Suggest places to look** ("check `%APPDATA%\Foo`") | The engine examines the place with its own rules. Either it finds its own evidence and lists the item, **unticked**, marked as suggested, or it refuses and says why ("still used by Thunderbird") |
| **Warn about a ticked item** ("this may be your data") | The item is unticked, with a "Tick again" button |
| **Answer a question** ("why was this kept?") | Text in the assistant's pane only, labelled as the assistant's words |

### 1.1 Modes and providers

Settings, card "Assistant". Off by default; while it is Off nothing of the assistant shows anywhere else.

| Mode | What it is | What the user gives | Leaves the PC? |
|---|---|---|---|
| **Off** (default) | — | — | No |
| **Local model** | A model server on this PC: Ollama, or any server that speaks the OpenAI chat API (LM Studio, llama.cpp, Foundry Local) | Address (default `http://127.0.0.1:11434`), model (picked from the server's list) | No. The address must be this PC (`127.0.0.1`, `::1`, `localhost`); anything else counts as an online service |
| **Online service** | Anthropic's API (Claude), or any online service that speaks the OpenAI chat API | The user's own API key, model (picked from the service's list; for Anthropic the default is `claude-opus-5-5`, and the list offers the cheaper ones) | Yes: the cleaned description (1.3), after consent |
| **Outside client** | An AI program the user already runs (Claude Desktop, Claude Code, another MCP client) talks to Purge through `purge-mcp.exe` | "Copy MCP config" into that client | Whatever that client does with it; Purge asks before it hands a scan over |

Purge ships no model and no key, and has no account of its own with any service.

### 1.2 Pages, panes, states, ids

**Settings, card "Assistant"** (`AssistCard`):

| Control | AutomationId |
|---|---|
| Mode: Off / Local model / Online service / Outside client | `AssistModeOff`, `AssistModeLocal`, `AssistModeOnline`, `AssistModeClient` |
| Service (Online): Anthropic / OpenAI-compatible | `AssistServiceBox` |
| Address | `AssistAddressField` (wired whole, `textfield::FieldInput`, AGENTS.md rule 2) |
| API key (shown as dots, never read back into the field) with "Save" and "Remove" | `AssistKeyField`, `AssistKeySave`, `AssistKeyRemove` |
| Model | `AssistModelBox` |
| "Test" and its result line ("Answered in 1.2 s" / "No answer from 127.0.0.1:11434" / "The key was refused") | `AssistTestButton`, `AssistTestText` |
| "Show me what will be sent, every time" (Online: on, and the user may turn it off; Local: off) | `AssistPreviewSwitch` |
| "See what was sent" (the outbox) | `OpenOutboxButton` |
| Outside client: "Copy MCP config", status line ("No client connected" / "A client is connected") | `CopyMcpConfigButton`, `McpStatusText` |

Choosing Online service or Outside client the first time opens the consent dialog (`ContentDialog`,
`DialogTitle` "Send leftover lists to <service>?", `DialogPrimaryButton` "Allow", `DialogCloseButton` "Not now"):
what is sent, what never is (1.3), and that the service's own terms decide what it keeps. Without "Allow" the mode
stays Off. The consent is per service address and is forgotten when the address changes.

**Leftovers page.**

- Header: the toggle "Assistant" (`AssistantToggle`), only when the mode is not Off and a scan is shown.
- Right pane, 380 px (`AssistantPane`), head "Assistant · suggestions only", the model's name and a chip
  "On this PC" / "Online" / "Outside client" (`AssistHeadText`, `AssistPrivacyChip`).
- Actions: "Review unproven items" (`AssistReviewButton`), "Suggest places to look" (`AssistLookButton`); in the
  details pane "Ask about this item" (`DAskButton`); at the foot a question field and "Ask" (`AssistPromptField`,
  `AssistSendButton`), and "See what was sent" (`AssistOutboxLink`). There is no button that removes or ticks.
- Cards (`AssistCard_n`, each one Text for the rig, plus its buttons):
  - Opinion: "3 items look like parts of Windows" with the items as links; "5 items look like the app's".
  - Suggestion: the place, then the engine's verdict: "Added, unticked: the engine found 2 references to
    <app>" / "Refused: still used by Mozilla Thunderbird" / "Refused: nothing ties this to <app>" / "Already
    listed".
  - Warning: "Unticked `%APPDATA%\Foo`: may hold your data" with "Tick again" (`AssistRetick_n`).
  - Answer: the text, under "The assistant's words. Purge has not checked them."
- States of the pane: `not_set_up` (link to Settings), `idle`, `preview` (below), `waiting` (with "Stop",
  `AssistStopButton`), `done`, `failed {reason}`: `offline` ("No answer from <address>. The rest of Purge works
  without it."), `key_refused`, `declined` (the service declined to answer), `bad_answer` (the answer did not fit
  the form and was dropped), `busy`, `too_large`.
- **Preview** (`ContentDialog`, `DialogTitle` "Send this to <service>?", the exact text of the request in a
  scrolling read-only box `AssistPreviewText`, its size, `DialogPrimaryButton` "Send", `DialogCloseButton`
  "Don't send"). Shown before every request when the switch is on.
- Rows: an "AI" mini-badge on items that carry a note or were suggested. Details pane: a line `DAssistNote`
  (1.4).

**The broker's consent dialog** lists every item the assistant suggested, one by one, marked "suggested by the
assistant" (ENGINE_PLAN §3.1 already asks for agent-origin items to be listed).

**Outbox** (`ContentDialog` with a list `OutboxList`: time, service, model, size; a row opens the exact request
text; `ClearOutboxButton`).

**Outside client.** When a client asks for a scan the first time, Purge asks (`ContentDialog`, `DialogTitle` "Let
the outside client read the leftover list of <app>?", "Allow" / "Not now"). Its notes, suggestions and warnings
arrive as the same cards.

Not in 1.0: the assistant in History, signature cards with "Approve" (section 6).

### 1.3 Privacy: what leaves the PC

One document only ever goes to a model: the **agent view** of one scan (`purge.agent-view/1`), plus the user's
own typed question if there is one.

| In the view | Never in the view |
|---|---|
| The program being removed: name, publisher, version, installer kind | The list of other installed programs |
| Per item (at most 400, unproven ones first): id, kind, cleaned location, band, category, size and age as coarse steps, the ids of its evidence and blockers, the shape numbers of the residue (counts, owner class) | File contents, registry value data |
| The name of another program where a blocker names it ("still used by Thunderbird") | The user's name, the computer's name, SIDs, e-mail addresses, the profile folder's name |
| | Full paths: every location is `%APPDATA%\…`-style, drive letters other than the system drive are `<DRIVE:n>` |

- The cleaning is done by one function, in the broker, which knows the user's folders and SID. Every string from
  the machine (a folder or key name) is cut to 260 characters and scrubbed: a segment that holds the user name,
  the profile folder name or the computer name becomes `<USER>` / `<HOST>`, a SID `<SID:n>`, an e-mail address
  `<EMAIL>`. The table that maps the placeholders back stays in the broker.
- **Program and folder names do leave the PC in the Online mode.** They say which software was installed. That is
  why Online needs the consent dialog, why the preview is on by default there, and why the outbox exists.
- **Outbox:** every request is written to `%LOCALAPPDATA%\Purge\assistant\outbox.jsonl` (time, service address,
  model, the exact body, no key) before it is sent; if it cannot be written, nothing is sent. 20 MB, oldest
  dropped.
- **The key** is kept in Windows Credential Manager (per user), never in the settings file, the outbox or a log.
- Requests happen only on the user's click. There is no background request, no telemetry, no update check here.
- What an online service keeps is that service's matter (for Anthropic's API: its retention terms); the consent
  dialog says so and promises nothing else.

### 1.4 What the user sees of a note

ENGINE_PLAN says explanations are fixed templates, never free text, and that AI notes never show on Likely or
UserData rows. Refined here, because the opinions are mostly about Likely items:

- In the item's details (`DAssistNote`) only a **fixed sentence** chosen by the opinion's verdict and reason code
  is shown ("The assistant thinks this is part of Windows: it sits among Windows' own keys"). Never the model's
  own words.
- On a **Likely or UserData** item only a note that argues for keeping is shown. "Looks like the app's" is not
  shown there: it would be an argument for ticking, from something that proves nothing.
- The model's own words (a note's text, an answer) appear only in the assistant's pane, as plain text with
  control and direction characters removed, under the label of 1.2.

### 1.5 Offline

Off and Local need no network. Online without a connection shows `offline` in the pane; every other part of Purge
is unaffected, and the scan, the bands and the plan never wait for the assistant.

## 2. Design

### 2.1 Who talks to whom

```
 model server / online service                         MCP client (Claude Desktop, …)
          ▲ HTTPS or loopback HTTP                               │ stdio (MCP)
          │                                                      ▼
 Purge.exe (medium)                                     purge-mcp.exe (medium; purge-model + purge-rpc only)
   purge-assist: provider, prompt, checks, outbox                │ pipe of the user's own (bridge.*)
   purge-ui-model/assist: the pane's state  ◄────────────────────┘
          │ broker pipe: agent.view (Read), agent.annotate, agent.probes_submit (Propose)
          ▼
 purge-broker (elevated): builds the agent view, binds advice (residue::bind/apply), runs suggestions through
                          purge-scan::probe, the guard and the policy. Never talks to a network.
```

- Scans exist only in the broker (`leftovers.scan` is a pipe method), and the broker serves one client, the UI it
  checked. So the UI is the hub: it asks the broker for the view, sends it to the model, and hands the model's
  answer back to the broker as typed, untrusted proposals.
- **The broker and the engine never open a socket**, and the code that does (`purge-assist`) is linked into
  `Purge.exe` only.
- `purge-mcp.exe` keeps its two allowed Purge crates. It cannot scan and cannot reach the broker; it reaches the
  running `Purge.exe` over a pipe and gets the same view the built-in assistant gets.

### 2.2 Types (`purge-model/src/agent.rs`; all `deny_unknown_fields`, all with length caps)

- `AgentView` (`purge.agent-view/1`): `scan_id`, `rev`, `app {name, publisher, version, installer}`, `items[]`
  (`id`, `item_fp`, `kind`, `place: RedactedPath`, `band`, `category`, `harm`, `size_step`, `age_step`,
  `evidence[]` and `blockers[]` as ids, `shape?`, `ticked_by_default`), `kept[]` (the protected ones, same form),
  `omitted`. Built by `agent::view(candidates, residue, &RedactEnv) -> (AgentView, RedactMap)`, a pure function.
- `RedactedPath { base: PlaceToken, rest: Vec<UntrustedString> }`, `UntrustedString { text, truncated }`.
  `PlaceToken` is a closed enum (`%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, `%PROGRAMFILES%`,
  `%PROGRAMFILES(X86)%`, `%COMMONPROGRAMFILES%`, `%USERPROFILE%`, `%TEMP%`, `%PUBLIC%`, `HKCU\Software`,
  `HKCU\Software\Classes`, `HKLM\SOFTWARE`, `HKLM\SOFTWARE\WOW6432Node`, `HKLM\SOFTWARE\Classes`, `<DRIVE:n>`,
  `<OTHER>`). M4's knowledge packs need the same "whitelisted location tokens" (ENGINE_PLAN §5.9): one table, in
  `purge-model`, whichever milestone lands first.
- `AdviceDoc` (`purge.advice/1`): exists (`residue.rs`), used as is. Its `bind` and `apply` already guarantee that
  advice only appends an `Ai` note to an existing candidate.
- `ProbeDoc` (`purge.probes/1`): `scan_id`, `model`, `probes[≤16] { id, kind: dir|key, base: PlaceToken (not
  `<OTHER>`, not `<DRIVE:n>`), rest: 1..=6 segments (each ≤128 characters; no wildcard, `..`, `:`, trailing dot
  or space, control character), reason: <enum> }`.
- `ProbeVerdict`: `candidate {id}` | `duplicate {id}` | `rejected {rule_id}`; `rule_id` is a guard or blocker id,
  or `PROBE-MISSING`, `PROBE-NO-EVIDENCE`, `PROBE-FORM`.
- The assistant's answer to one request (`purge.assist-out/1`, checked in `purge-assist`): `advice?: AdviceDoc`,
  `probes?: ProbeDoc`, `flags[] {id, reason: <enum>}`, `answer?: text ≤ 2,000 characters`.

### 2.3 RPC on the broker pipe (`purge-rpc`)

| Method | Set | In → out |
|---|---|---|
| `agent.view {scan_id}` | Read | → `AgentView` |
| `agent.annotate {scan_id, rev, advice}` | Propose | → `{rev, applied[], dropped[{id, why}], changed[]}` |
| `agent.probes_submit {scan_id, rev, probes}` ⇢ `scan.progress` | Propose, cancellable | → `{rev, verdicts[{probe_id, verdict}]}` |

- A scan gets a revision number; a call with a stale `rev`, or for a scan that has a plan in progress, is refused.
  After a change the UI reloads the candidates it shows.
- Limits per scan: 4 `annotate` calls, 4 `probes_submit` calls, 16 probes each. The elevated broker does bounded
  work for a medium caller.
- **No `plan.flag`, no `signature.propose`, no `propose_selection`.** What is ticked is the UI's state until
  `plan.create`, so a warning that unticks needs no broker call. Signatures are deferred (section 6). A selection
  proposed by an agent would be preselection under another name.

### 2.4 A suggestion's way through the engine (`purge-scan/src/probe.rs`)

`probe::evaluate(ctx, app, &Probe) -> ProbeVerdict or Candidate`:

1. The form is checked again, the place token is expanded with the **scan user's** folders (the broker's own
   values, never a path from the caller), and the result is canonicalised by `purge-guard`.
2. It must exist (`PROBE-MISSING`), must not be a target the scan already lists (`duplicate`).
3. `framework::evaluate_location` tries the ordinary evidence constructors on exactly that target: name tokens,
   harvested token, vendor subfolder, app-named key with a reference into a root, references in the snapshot, the
   time window, content mentioning the app's path. **Being suggested is not evidence**: nothing is added for it.
   No constructor holds: `PROBE-NO-EVIDENCE`.
4. The candidate gets `Origin::ProbeAgent` and goes through the same guard, blockers and policy as every other
   one. A hard block shows as `rejected {rule_id}`. `band.rs` already never preselects a `ProbeAgent` candidate
   and adds the note "Proposed by an assistant, so it starts unticked".

### 2.5 `purge-assist` (new workspace crate, linked by `purge-ui` only)

- `Assistant::run(task: Review | Look | Explain {id} | Ask {question}, view: &AgentView, cfg) -> Outcome`. The
  crate's public API takes an `AgentView` and nothing else from the machine; its sources never name `Candidate`,
  `Fingerprint` or `Target` (a check-deps identifier rule, like rule 5).
- One fixed, versioned instruction text per task, the view as one JSON block marked as data, the answer asked for
  as JSON by the service's schema feature.
- Three adapters behind one trait:

  | Adapter | Request | Answer form |
  |---|---|---|
  | Ollama | `POST /api/chat`, `stream: false`; models from `GET /api/tags` | `format` = the JSON schema |
  | OpenAI-compatible | `POST /v1/chat/completions`; models from `GET /v1/models`; `Authorization: Bearer` when a key is set | `response_format` = `json_schema` |
  | Anthropic | `POST https://api.anthropic.com/v1/messages`, headers `x-api-key`, `anthropic-version: 2026-10-21`; models from `GET /v1/models` | Structured outputs (`output_config.format`). No forced `tool_choice` and no sampling parameters: current models refuse both. `output_config.effort` set explicitly. `stop_reason` is checked before the content is read (`refusal` → `declined`, `max_tokens` → `bad_answer`). Not streamed, `max_tokens` 16,000 |

  There is no official Rust SDK, so these are plain HTTP requests. The implementer loads the `claude-api` skill
  and takes the exact request shapes from its `curl/examples.md` and `shared/tool-use-concepts.md`, including its
  advice on refusal fallbacks, not from memory. Model ids are never fixed in code except the one default.
- The answer is parsed strictly: unknown field, over-long text, an id that is not in the view, more than the caps
  → that part is dropped and counted; nothing parseable → `bad_answer`.
- **HTTP** through WinHTTP (`http.rs`, the crate's only `unsafe` module): the system's TLS, certificate store and
  proxy; certificate checks never relaxed; redirects off (a key must not follow a redirect to another host);
  `https` required unless the host is this PC; answer capped at 4 MB; 5-minute limit; "Stop" cancels.
- **Key** through Credential Manager (`cred.rs`: `CredWriteW`, `CredReadW`, `CredDeleteW`).
- **Outbox** (`outbox.rs`), written before sending.
- A `FakeProvider` (scripted answers, including hostile ones) for the tests and for `Purge.exe --sample`.

### 2.6 The pane's state (`purge-ui-model/src/assist/`)

A plain state machine like the other models: events in (button, `AgentView` arrived, outcome arrived, broker
result arrived), requests out (`GetView`, `Send`, `Annotate`, `SubmitProbes`, `Untick {id}`, `ShowPreview`).
It has **no request that ticks an item**, and it emits `Send` only from the state that holds the consent for this
service address and, where the preview is on, the user's "Send" for exactly this request text.

### 2.7 Outside client: `purge-mcp.exe` and the bridge

- `Purge.exe`, while the mode is Outside client, serves a pipe `\\.\pipe\purge-assist-<32 hex>` (the user's SID
  only, medium label, local clients only; `purge_win::pipe`, already in the `read` feature) and writes its name to
  `%LOCALAPPDATA%\Purge\assistant\bridge.json`. `purge-mcp.exe` reads that file and opens the pipe with `std`.
- Bridge methods (`purge-rpc`, NDJSON like the rest): `bridge.hello`, `bridge.scans`, `bridge.view {scan_id}`,
  `bridge.annotate`, `bridge.probes_submit`, `bridge.flag`. The UI asks the user before the first `bridge.view` of
  a scan, writes what it serves to the outbox, and passes proposals to the broker through the same three calls
  and the same model as the built-in assistant.
- MCP tools, the whole list: `list_scans`, `get_leftovers` (the view), `annotate_items`, `suggest_places`,
  `flag_items`. Every `inputSchema` has `additionalProperties: false` and length limits. No resources, prompts,
  sampling or elicitation. With Purge closed or the mode elsewhere, each tool answers "Open Purge and choose
  Settings → Assistant → Outside client".
- The MCP side is written by hand over `serde_json`: stdio, `initialize`, `notifications/initialized`, `ping`,
  `tools/list`, `tools/call`. The protocol revision is pinned to the newest stable one when the package starts
  (the implementer reads the specification and records the choice); an older client version is answered by the
  specification's negotiation rule.
- "Copy MCP config" puts `{"mcpServers": {"purge": {"command": "<install dir>\\purge-mcp.exe"}}}` on the
  clipboard.

## 3. Safety invariants

| # | Invariant | Enforced in | Tests |
|---|---|---|---|
| A1 | Nothing the assistant sends raises a band, ticks an item, removes a blocker or makes an item Safe | `residue::apply` (appends an `Ai` note only), `purge-policy` (`Tier::Ai` never scored; negative note → one band down), `band.rs` (`ProbeAgent` never preselected) | Existing policy and residue tests, plus one in the broker over generated `AdviceDoc`s and `ProbeDoc`s: for every candidate present before, band after ≤ band before, `preselected` after implies before, blockers after ⊇ before; no new candidate is preselected |
| A2 | A suggestion becomes a candidate only on the engine's own evidence; the hard blocks hold | `purge-scan::probe`, `purge-plan::decide`, `purge-guard` | Suggestions at `%WINDIR%`, `C:\Program Files` itself, another installed app's root, a baseline key, a structural container, a path with `..` or a wildcard: each `rejected` with its rule id, no candidate. A suggestion at an unrelated existing folder: `PROBE-NO-EVIDENCE` |
| A3 | The UI never ticks on the assistant's word | `purge-ui-model/assist` has no tick request | For generated outcomes fed to the model, the selected set never grows; "Tick again" only restores what the same warning unticked |
| A4 | The broker's consent dialog names every assistant-suggested item | `bins/purge-broker/src/consent/view.rs`, `text.rs`, both renderers | Consent tests with `ProbeAgent` items: each listed with the mark; the verification checkbox is required |
| A5 | `purge-mcp` never links the executor | `xtask check-deps` rules 1 to 3, `ALLOWED` unchanged (`purge-model`, `purge-rpc`) | The existing check-deps tests; `cargo clippy -p purge-mcp` alone in `xtask ci` |
| A6 | The elevated side has no network code: `purge-assist` is in the tree of `purge-ui` only; the broker's and the engine's own trees have no `windows-sys` networking or credentials feature; `BROKER_OUTSIDE` unchanged | `xtask check-deps`, new rule 7 | check-deps unit tests with manifests that break each |
| A7 | Nothing personal is in the view | `purge-model::agent::view` | Canary test: a scan whose every string carries the user name, profile folder name, computer name, a SID and an e-mail address, in several spellings: the serialised view holds none of them. The view type has no field for data or content |
| A8 | Nothing is sent without consent, and what is sent is what was shown and logged | `purge-ui-model/assist` (`Send` only with consent, and with the preview's "Send" for the same text), `purge-assist` (outbox first; one public entry) | Model tests for every path to `Send`; `purge-assist` against a loopback test server: the body received equals the outbox entry byte for byte; outbox not writable → no connection is made |
| A9 | The key stays in Credential Manager and goes only to the chosen host | `purge-assist::cred`, `http.rs` (redirects off, `https` unless local) | Test server that redirects: no second request; the key appears in no outbox entry, no error text, no `Debug` output |
| A10 | The model's answer is untrusted: strict parsing, caps, ids bound to the view; its own words are shown only in the pane, as plain text | `purge-assist::check`, `residue::bind`, `purge-ui` | Hostile answers from the `FakeProvider`: unknown fields, 10 MB, ids of other scans, direction-override characters, text that imitates Purge's own lines. Nothing applied beyond the rules; the details pane shows fixed sentences only |
| A11 | No tool or method executes, deletes, restores, activates or selects | The bridge and MCP tool lists; no `purge://` handler | A test that the MCP `tools/list` is exactly the five names; the rpc table test that every `agent.*` and `bridge.*` method is Read or Propose |
| A12 | The broker does bounded work for assistant calls | `bins/purge-broker/src/agent.rs` | The fifth `annotate`, the seventeenth probe, a stale `rev`, a scan with a plan: refused |

The honest limit stays as ENGINE_PLAN §3.1 states it: a program running as the user, with a shell, is the user.
These rules keep the assistant from being a way to delete; the broker's own dialog remains the gate.

## 4. Packages

Each is one agent session, in its own worktree `E:\purge-ui-wt\<name>` on a branch from `ui/rust`. Fable reviews
M6-CONTRACT (the cleaning), M6-PROBE, M6-BROKER, M6-ASSIST and M6-MCP before merge.

| Order | Package | Crates and files | Depends on |
|---|---|---|---|
| 1 | **M6-CONTRACT** | `purge-model` (`agent.rs`, `lib.rs`), `purge-rpc` (`methods.rs`, `table.rs`, `sets.rs` tests: `agent.*`, `bridge.*`), `tools/xtask` (`check_deps.rs`: rule 7 and the identifier rule; `gen_dto`), `Cargo.toml` (member `crates/purge-assist`, empty) | — |
| 2 | **M6-PROBE** | `crates/purge-scan` (`probe.rs`, `framework` helper `evaluate_location`) | 1 |
| 2 | **M6-ASSIST** | `crates/purge-assist` (`lib.rs`, `task.rs`, `prompt.rs`, `check.rs`, `provider/{mod,ollama,openai,anthropic,fake}.rs`, `http.rs`, `cred.rs`, `outbox.rs`) | 1 |
| 2 | **M6-UI-MODEL** | `crates/purge-ui-model` (`assist/{mod,cards,text,settings,tests}.rs`; `leftovers/` for notes, badges and the untick) | 1 |
| 3 | **M6-BROKER** | `bins/purge-broker` (`agent.rs`, `scan.rs` revision, `serve.rs`, `consent/view.rs`, `consent/text.rs`, tests) | 1, M6-PROBE |
| 3 | **M6-UI** | `bins/purge-ui` (`screens/assist.rs`, `leftovers.rs`, `settings.rs`, `prefs.rs`, `link/`, `sample_broker.rs`, `script_steps.rs`), `crates/purge-client` (the three calls, sample data) | M6-UI-MODEL, M6-ASSIST; runs beside M6-BROKER on the sample broker |
| 4 | **M6-MCP** | `bins/purge-mcp` (`main.rs`, `mcp.rs`, `bridge.rs`), `bins/purge-ui` (`mcp_bridge.rs`, the Outside client part of Settings), the installer's file list | M6-BROKER, M6-UI |

**M6-CONTRACT.** The types of 2.2 and the methods of 2.3 and 2.7 with serde and schema tests (round trips, unknown
fields refused, every cap). `agent::view` with the canary test (A7) and golden views of two fixture scans. The
`PlaceToken` table with expansion against a `RedactEnv`. check-deps rule 7 (A6) and the identifier rule for
`purge-assist`, with their unit tests. No behaviour in the broker or the UI.

**M6-PROBE.** 2.4. Tests over `purge-source` fixtures: A2's cases; a suggestion the engine can tie to the app
becomes a `ProbeAgent` candidate that is Likely at most by the proposal alone and Safe only with engine Tier A,
and unticked either way; a duplicate; user data stays user data.

**M6-ASSIST.** 2.5. Tests: each adapter against a test server on `127.0.0.1` (plain `std::net::TcpListener` in
the test, canned answers including errors, a redirect, a slow answer, a refusal); `check.rs` on hostile answers
(A10); the outbox (A8); the key never in output (A9). `cred.rs` is tested against the real Credential Manager
with a test-only target name that the test removes (per-user, no elevation). No test contacts an outside host,
and no outside model is used while building.

**M6-UI-MODEL.** 2.6, with the settings model (modes, consent per address, the preview switch), the cards and all
wording (`xtask ui-strings`). Tests: A3, A8's model half, every state of 1.2, the note rules of 1.4.

**M6-BROKER.** The three handlers, the revision and the limits (A12), the consent lines (A4), the property test
of A1 over the flow-test fixtures. The view is built with the scan user's `RedactEnv` (the impersonated token's
folders, as the scans use).

**M6-UI.** Section 1.2 on the toolkit: read the toolkit's `docs/CATALOGUE.md` first and wire the two text fields
whole (AGENTS.md rules 1 to 4). `Purge.exe --sample` uses the `FakeProvider` and a sample broker that answers the
three calls, so the scripted walk covers: enabling Local, the consent dialog for Online, a review, a suggestion
accepted and one refused, a warning and "Tick again", the preview's "Don't send", the `offline` state, the
outbox. The live HTTP path is in the build but not in the walk.

**M6-MCP.** 2.7. Tests: the MCP exchange over in-memory pipes (handshake, the exact tool list, schema refusals,
oversized input), the bridge against a fake UI end, the "Purge is closed" answers, the model's handling of a
client's proposals (the same paths as the built-in assistant). If time runs out, this package alone moves to
1.1 and the mode is not shown.

## 5. New crates

**None from outside.** One new workspace crate, `purge-assist`, and features of a crate already linked:

| What | Licence | Why |
|---|---|---|
| `windows-sys` features `Win32_Networking_WinHttp`, `Win32_Security_Credentials` (in `purge-assist` only) | MIT OR Apache-2.0 (already in the tree, 0.61) | HTTPS with the system's TLS, proxy and certificates; the key in Credential Manager |

Considered and not recommended (each would need the user's OK):

| Crate | Licence | Why not |
|---|---|---|
| `rmcp` 3.12.0, the official Rust MCP SDK that ENGINE_PLAN names | Apache-2.0 | Brings `tokio`, `futures`, `tokio-util`, `jiff`, `tracing`, `indexmap`, `sha2` 0.11 and more, and needs Rust 1.88 (the workspace says 1.85). Purge needs five tools over stdio, and `purge-rpc` already frames newline-delimited JSON-RPC |
| `ureq` or `reqwest` with `rustls` | MIT OR Apache-2.0 | A second TLS stack and its certificate handling in the tree; WinHTTP is already on every PC |
| `keyring` | MIT OR Apache-2.0 | Three Win32 calls |

## 6. Deferred until after 1.0

- Every eval of ENGINE_PLAN §8.6: R1 (engine plus assistant per model), R2 (a scripted hostile agent against the
  real pipeline in the rig), R3 (injection canary apps), the `agent_uplift` number. Until R1 exists nobody knows
  how good any model's advice is; the product's claim in 1.0 is only that the advice cannot do harm.
- A comparison or recommendation of models, and any tuning of the instruction texts against real answers.
- **Signatures and the knowledge-base lifecycle** (`signature.propose`, `proposed → … → vm_validated → approved →
  active`, the S6 "Approve" stepper, restore as negative feedback). It needs M4's `purge-kb` (an empty crate
  today), one of its states is a VM validation no user's PC can do, and it is the one place where AI output would
  persist and raise evidence in later scans. FUTURE_IDEAS already puts drafted knowledge-base entries and the
  community repository later.
- The assistant in History; streaming answers; a model shipped with Purge.
- VM runs. The one VM run of the UI after everything is implemented should include the assistant in Local mode
  with no model server running (the `offline` state), and, if a local server is at hand in the VM, one suggested
  item going through the broker's real consent dialog.

## 7. Conventions for the agents

- Rust builds and tests run on the laptop: `tools/laptop/lt.sh <worktree> <cargo args>` (read the script's head).
  For example `tools/laptop/lt.sh E:/purge-ui-wt/m6-assist test --release -p purge-assist`. `cargo fmt` may run
  locally.
- The app runs on the PC: `tools/laptop/lt.sh <worktree> --fetch Purge.exe purge-engine.exe purge-broker.exe
  purge-mcp.exe`, then `powershell -NoProfile -File tools\desk\run-hidden.ps1 -Exe
  E:\purge-target\lt\<name>\Purge.exe -Args '--sample --script'`. UI tests only ever on the hidden desktop.
- Worktrees in `E:\purge-ui-wt\<name>`, one branch each from `ui/rust`. Never push, never touch `main`, `baseline`
  or the main checkout; the coordinator merges.
- No VM, no VBoxManage, **no outside models**: no test and no agent calls a real model or an outside host; the
  adapters are tested against a server the test itself starts on `127.0.0.1`. Nothing elevated and nothing
  destructive on the dev PC.
- Gates before handing back: `cargo fmt --all -- --check`, `cargo clippy -p <your crates> --all-targets -- -D
  warnings`, `cargo test -p <your crates>`, `cargo xtask check-deps`, and for UI packages the hidden-desktop
  scripted walk.
- No new third-party crate without the user's OK (this plan needs none). The repo's conventions: doc comments
  that say why, no `unwrap` outside tests, errors as `thiserror` types. Read `AGENTS.md` before any UI work.
- Small commits with clear messages, ending with the attribution lines given.
- At most three agents run at once, over M4, M5 and M6 together.

### Shared files (with M4 and M5)

`purge-rpc` (`methods.rs`, `table.rs`), `purge-model/src/lib.rs`, `purge-scan/src/framework.rs`
(`evaluate_location`, shared with M5-SCAN), `bins/purge-broker/src/serve.rs` and `scan.rs`,
`tools/xtask/src/check_deps.rs`, and in the UI `screens/leftovers.rs`, `screens/settings.rs`, `prefs.rs`,
`script_steps.rs`. Therefore: M5-CONTRACT and M6-CONTRACT are merged one after the other before either milestone
fans out; M5-UI and M6-UI do not run at the same time; whoever merges second rebases. With M4: the place-token
table (2.2) and anything M4 gives `purge-kb`; `docs/M4_PLAN.md` (branch `plan/m4`) did not exist when this was
written, so the coordinator checks its package list against the list above. M6 leaves `purge-kb` alone.

Suggested order over both milestones, three agents: M5-CONTRACT → M6-CONTRACT → {M5-ETW, M5-PARSE, M5-SCAN} →
{M5-BROKER, M5-UI, M6-PROBE} → {M6-ASSIST, M6-UI-MODEL, M6-BROKER} → M6-UI → M6-MCP, with M4's packages taking
free places.

## 8. Decisions this plan makes for the coordinator to record (DECISIONS rows)

- The UI is the hub; the broker serves the view and takes three typed calls; no agent directory on disk.
- Advice texts are never shown as explanation; fixed sentences only (1.4).
- `plan.flag`, `signature.propose` and `propose_selection` are not built in 1.0.
- MCP by hand, WinHTTP by hand, no new outside crate.

## 9. Where this plan departs from ENGINE_PLAN

| ENGINE_PLAN | This plan | Why |
|---|---|---|
| §3.3: stdio has Read and Propose; the MCP server has Read and Propose on its own | In the code stdio has Read and UserRun, and scans exist only on the broker's pipe. `purge-mcp` reaches the running UI | A medium process cannot scan; the broker serves only the UI it checked |
| §8.1 (2): `purge-mcp` writes proposals to `%LOCALAPPDATA%\Purge\agent\`, read by the broker | No such directory. Proposals reach the broker as typed calls from the UI | The elevated broker reading user-writable files is the pattern the store work removed (planted links, DECISIONS 2026-11-22) |
| §8.2: thirteen read tools (`list_programs`, `inspect_location`, `find_references`, …) and five propose tools | Five tools | The read tools have no method behind them (`location.inspect`, `references.find`, `guard.explain`, `plan.validate`, `kb.*` of §3.3 were never built), and the list of installed programs is more than an assistant needs |
| §8.2: `rmcp`, "the stateless revision 2026-07-28" | By hand; the revision is pinned when M6-MCP starts | Section 5 |
| §8.4: modes "local model, external MCP client, or a later built-in cloud assistant" | Online service with the user's own key is in 1.0 (open question 1) | The user asked for the provider choice now |
| §8.4: redacted path-like values may be served | No value data at all | The stricter rule is simpler to prove |
| §5.8.6, §8.5: AI notes never on Likely or UserData rows | Keeping-side notes are shown there, as fixed sentences | The opinions are mostly about Likely items; a "keep" note cannot talk anyone into deleting |
| §5.9, §9.4 S6, §11.1: signatures, lifecycle, approvals, the assistant in S4 | Deferred | Section 6 |
| §11.1: exit = R2 and R3 gates at 0, `agent_uplift` reported | Unit and property tests of section 3 in 1.0; the evals after it | The user's decision of 2026-11-28 |
| §3.1, §3.2, §9: the UI is C# WinUI with DTOs by NJsonSchema; the broker is `purge-engine --broker` | The UI is Rust on the toolkit; the broker is `purge-broker` | Already true in the code; ENGINE_PLAN was not updated |

## 10. Open questions for the user

1. **Which providers ship in 1.0?** Recommendation: Local model (Ollama and OpenAI-compatible servers) and
   Anthropic's API with your own key, plus the generic OpenAI-compatible online address since it costs nothing
   extra; Outside client (MCP) as the last package, moved to 1.1 if time runs out. The smaller choice is Local
   only: nothing ever leaves the PC, but small local models are likely to give poor advice.
2. **Is it acceptable that program and folder names go to an online service** after the consent dialog, with the
   preview before every request on by default? Recommendation: yes, with exactly those two guards and the outbox.
   Your user name, computer name, SIDs, file contents and registry data never go.
3. **Signatures and knowledge-base approvals after 1.0?** Recommendation: yes, defer (section 6). In 1.0 nothing
   the assistant says outlives the scan it was said about.
4. **No new outside crates** (MCP and HTTPS written against what Windows and the repo already have).
   Recommendation: yes. The other choice is `rmcp` and an HTTP crate, about twenty more crates in `Purge.exe` and
   `purge-mcp.exe` (none in the broker either way).
