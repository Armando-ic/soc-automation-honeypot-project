# Tier-1 concealment — plan, evidence, and execution tracker

**What this is:** the active honeypot experiment. Hide the instrumentation, change nothing else, and see
whether the next operator stays longer. Split out of the master checklist so the experiment reads as one
self-contained artifact.

- Live situational snapshot: [`CURRENT-STATE.md`](CURRENT-STATE.md)
- Phase index: [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)
- **Copy-paste procedure:** [`honeypot-opening-runbook.md`](../honeypot-opening-runbook.md) → **B8 → "NEXT: Tier-1 concealment"**
- The incident that motivated it: [`INC-2026-001`](../incidents/INC-2026-001-first-interactive-intrusion.md)

**Status:** approved 2026-08-08 · executed 2026-08-10 · **RESULT 2026-08-11: NULL — the next operator stayed
38.9s vs the 54.1s baseline. The hypothesis is not supported.** Concealment stays in place; see "The result".
**Last updated:** 2026-08-11

---

## The hypothesis

INC-2026-001's operator opened **Task Manager twice** and left after 54 seconds. Task Manager's process
list shows **`Sysmon64.exe` and `splunkd.exe`**, and the host is literally named **`vm-honeypot-win`** —
visible in every process-owner string, in `This PC`, and in the RDP client title bar.

**"They left because the box was empty" and "they left because they saw the instrumentation" are different
explanations with different fixes**, and the second is at least as well supported by what they actually
did. Tier 1 tests the second.

**Success criterion:** the next operator stays **materially longer** with the box otherwise unchanged. That
is a publishable, properly-isolated finding.

## Scope — concealment ONLY

**Tier 2 (furnishing) is explicitly EXCLUDED**: no planted documents, no fake saved-RDP history, no
line-of-business software. Exactly one variable changes so the next result stays comparable with
INC-2026-001. Changing several at once tells you nothing about which mattered.

**Do not expand scope.**

## The plan, as refined 2026-08-10

This supersedes the original three-step summary.

| # | Change | Status |
|---|---|---|
| 1 | **Windows host → `<neutral-hostname>`** — value-neutral and production-shaped. The **Azure VM name stays `vm-honeypot-win`**; only the in-guest computer name changes | ✅ Done 2026-08-10 |
| 2 | **Sysmon service, driver and binary → neutral names** — removes the loudest tell in Task Manager, no telemetry fidelity lost | ✅ Done 2026-08-10 |
| 3 | ~~Rename the Splunk forwarder service display name~~ | **DROPPED** |

**Why value-neutral and not value-suggesting.** A value-suggesting name (e.g. an accounting file server) would confound
the experiment: if the next operator stays longer, you could not tell whether it was the hidden
instrumentation or the juicy name. A value-neutral name keeps exactly one variable moving.

**Why the Splunk rename was dropped.** A display-name rename does **not** hide `splunkd.exe` from Task
Manager — display name only changes the Services-tab Description; the Processes and Details tabs still show
the image name. Actually hiding it means renaming the binary, which breaks the UF's service path, recovery
and upgrades. And a Splunk Universal Forwarder is unremarkable on a real production Windows server, so it
arguably *supports* the cover story rather than blowing it. Dropping it narrows scope at no cost to the
hypothesis.

## Ripple check — verified firsthand 2026-08-10

The runbook says verify rather than assume. This was traced in the repo before any live change.
**Verdict: nothing in the live path filters on hostname.** Re-verify if the pipeline changes.

| Live-path consumer | Finding |
|---|---|
| [`app.py`](../../../grounding-service/grounding_service/app.py) `host_feed_spl` — the brake's feeder | Filters `index` + `sourcetype` + `EventCode=3` + ports. **No host filter.** Brake survives ✅ |
| Both saved searches ([`honeypot-brake-triggers.md`](../honeypot-brake-triggers.md) §3) | Filter on index / source / EventCode / **user**. Alarm survives ✅ |
| [B8 dashboard](../dashboards/honeypot-attacker-session-b8.xml) | `ComputerName` is a `\| table` **display column only**, never a filter ✅ |
| Phase B B1 / B2 / B3 | No host filter ✅ |
| [`build_honeypot_logon_alert_workflow.py`](../build_honeypot_logon_alert_workflow.py) | `result.ComputerName \|\| HOST` — a **fallback**. The embed simply shows the new name ✅ |
| [`build_honeypot_brake_workflow.py`](../build_honeypot_brake_workflow.py) | Falcon FQL `hostname:'vm-honeypot-win'` — **already dead** (Falcon retired, node non-halting). No new breakage |
| **The NSG deny rule** | References no hostname at all. The authoritative safety control is host-agnostic ✅ |

**Two consequences worth knowing:**

1. **The Splunk `host` field WILL change.** [`splunk-inputs.conf`](../splunk-inputs.conf) sets no `host =`
   stanza, so the UF uses the system hostname. After the rename `index=honeypot` holds two host values, and
   any query grouping by `host` across the boundary shows a split. **Nothing gates on it** — and the change
   is a useful forensic marker of exactly when the rename landed.
2. **The Sysmon event channel does NOT change.** It stays `Microsoft-Windows-Sysmon/Operational` regardless
   of the binary, service or driver name, so `splunk-inputs.conf` still binds and no forwarder change is
   needed. This was the one thing that could have silently killed the data plane. Source:
   [TrustedSec SysmonCommunityGuide](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/install_windows.md).
   **Still verified live after the reinstall rather than trusted on the doc.**

## ✅ Execution tracker

**One variable at a time, Phase B between each.** Detail and copy-paste commands live in the runbook; this
is the state tracker, not the procedure.

- ✅ **0. Phase B BASELINE (2026-08-10, before any change).** B1 **224** /15m · B2 **20,729** /24h · B3 **39**
  /15m (informational). Both gates green. **This is the control: B2 must stay non-zero after the Sysmon
  rename — a drop to 0 there is the signature of a broken reinstall.**
- ✅ **1. Sysmon renamed (2026-08-10).** Service + driver + binary all moved to neutral names (actual
  strings live in the dated session handoff + chat, deliberately kept out of this published file). Clean
  `-u force` / `-i -d`; ruleset proven **byte-identical** (the full before/after `-c` diff was exactly the
  3 self-referential header fields and zero rule lines). Orphaned original binary deleted; no Sysmon-named
  artifact left in SCM or on disk; new driver `.sys` in place. Service description could NOT be changed via
  SCM — **Sysmon's anti-tamper ACL denies even Administrators** — but WAS changed via the registry key.
  Residuals accepted: the signed PE `FileDescription` and driver altitude `385201`.
- ✅ **2. Phase B re-verified (2026-08-10) — and it caught a real break.** The rename dropped the Splunk
  UF's subscription to the Sysmon channel: B1 read **0** while Security (4625) kept flowing. Root cause: the
  `-u`/`-i` briefly unregistered the channel, so the UF lost its handle and **froze its bookmark at the
  rename moment**, even though Sysmon kept logging and the channel persisted (RecordCount stayed ~55k, not
  reset). **Fix: `Restart-Service SplunkForwarder`** — the bookmark was still valid, so the UF resumed and
  backfilled the ~24-min gap. B1 back to **222** (baseline 224). **Lesson: renaming a telemetry agent
  silently drops the forwarder's per-channel subscription — always restart the UF and re-run Phase B. This
  is exactly why Phase B gates between changes.**
- ✅ **3. Host renamed → `<neutral-hostname>` + rebooted (2026-08-10).** Rename took (hostname now `<neutral-hostname>`); both
  services auto-started; the resident disconnected intruder session was cleared by the reboot
  (`query session` shows only the operator) — **INC-2026-001 residual #1 CLOSED.** Standalone box
  (`PartOfDomain: False`), so no domain credential was needed.
- ✅ **4. Phase B re-verified post-reboot.** B1 **601** /15m (healthy post-boot burst). `stats count by host`
  shows the predicted split — **`<neutral-hostname>` 2194 / `vm-honeypot-win` 80** at the boundary — the `host` field
  flipped as expected, nothing gated on it, data path fully intact. B4 unaffected: the saved searches live
  on the untouched search head, and the alarm fired live at **15:28 today** on `216.225.207.214`.
- ✅ **5. Watch CLOSED 2026-08-11 — a landing arrived, and the experiment returned a null.** State at the
  moment of the landing: host `<neutral-hostname>`, Sysmon renamed, service description neutralized, no
  Sysmon-named artifacts, data plane green. The next operator dwelled **38.9s against the 54.1s baseline**.
  Full incident: [`INC-2026-002`](../incidents/INC-2026-002-credential-handoff-intrusion.md).

**Sysmon first, host+reboot last** on purpose: the reboot re-validates that the Sysmon reinstall survives a
boot, and a broken reinstall is caught at step 2 before anything else is disturbed.

## 📊 The result — NULL (2026-08-11)

**A landing arrived roughly 15 hours after the concealment went in. The operator stayed 38.9 seconds. The
baseline was 54.1. The hypothesis is not supported.**

Full incident write-up: [`INC-2026-002`](../incidents/INC-2026-002-credential-handoff-intrusion.md).

| Phase | INC-2026-001 (instrumentation visible) | INC-2026-002 (instrumentation disguised) |
|---|---|---|
| Logon → shell (`explorer.exe`) | 3.95s | 3.67s |
| Logon → first Task Manager | 15.07s | **24.27s** |
| **First Task Manager → disconnect** | **39.04s** | **14.61s** |
| **Total dwell** | **54.11s** | **38.88s** |

The sharpest measure is the third row, because it controls for shell-load time: **after opening Task Manager
on the disguised host, this operator left 2.7× faster than the one who saw `Sysmon64.exe` in plain sight.**

### What this does and does not license us to say

- ✅ **Defensible:** concealing the instrumentation produced **no lengthening of dwell time**. The
  pre-registered success criterion was not met.
- ❌ **Not defensible:** "concealment made it worse." This is **n=1 against n=1** — two different actors on
  different days. A 15-second difference sits well inside the variation you would expect between two people.
- ✅ **Defensible and more interesting than the original question:** the two sessions **replicated each
  other almost exactly** — two Type 3 validations seconds apart, then a Type 10, clipboard redirection on,
  shell in under four seconds, Task Manager twice via the shell, disconnect without logging off. Two
  independent actors three days apart running the same ~40-second routine indicates a **standardised
  access-triage procedure and probably shared tooling.**
- ✅ **Defensible:** the credential was **handed off, not re-cracked**. Neither interactive actor ever
  guessed a password on this host, and the original cracker re-validated the credential 3m34s before a
  different address used it.

### The better candidate for the real tell

**Server Manager auto-launches on this host and presents a server with no roles and nothing configured** — it
fired at +7.6s, before Task Manager was ever opened, and it explains why this operator took nine seconds
longer to reach Task Manager than the last one. An empty Server Manager states "this box is worthless" far
more loudly than a process list does.

That points at **Tier 2 (furnishing)** as the next lever, exactly as the pre-registered decision rule said a
null would. **Tier 2 remains out of scope until the USER explicitly chooses it.**

### What the experiment was still worth

The design held up even though the hypothesis did not. One variable moved, the control was measured first,
the data plane was gated between every change, and the result is interpretable precisely *because* nothing
else changed. A null from a clean experiment beats a positive from a muddy one — and the run produced two
findings (the replication and the handoff) that are stronger than the thing it set out to measure.

## Known costs and honest limits

- **There is a telemetry-blind window** during the Sysmon uninstall/reinstall, and a longer one across the
  reboot. The box is internet-exposed with a burned credential throughout, and the brake is blind for the
  duration (the feeder returns empty, which reads GREEN — see the `host_feed_spl` docstring). Inherent to
  Tier 1, bounded by keeping it attended and fast. **Do not try to mitigate with NSG changes** — that adds
  moving parts to the safety control itself.
- **Expect operator-generated noise.** Every interactive logon emits **14 × 4697** and fires the ⚠️ amber
  backstop. Your own maintenance logons will look like activity; the discriminator is "was I logged in",
  not the source address (your home IP is a routable public IPv4, so the link-local test does not help here).
- **Renaming Sysmon defeats a 54-second Task Manager glance** — exactly the behaviour INC-2026-001
  observed. It does **not** defeat `services.msc`, `fltmc` (the driver's altitude **385201** is fixed and
  still visible — confirmed live 2026-08-10), or Event Viewer. **Do not let the finding get overstated.**
- **The binary's `FileDescription` = "System activity monitor" PERSISTS** in Task Manager's Description
  column (Details tab) and in the Processes-tab friendly name, because it lives in the signed PE metadata,
  not the filename. **Deliberately NOT edited:** changing it means modifying a Microsoft-signed binary,
  which breaks its Authenticode signature — a *worse* tell than a generic description. A valid
  Microsoft-signed `<neutral-service>.exe` reads as a legit MS component; a tampered one reads as "someone
  modified this." The valid signature is the better camouflage. We rename the file/service/driver and clear
  the *service* Description (ours to change), and accept the PE `FileDescription` as a secondary residual —
  same class as keeping `splunkd.exe` visible.
- **Rename mechanics (confirmed live 2026-08-10):** the service name equals the executable's base name, so
  renaming `Sysmon64.exe` → `<neutral-service>.exe` renames the service to `<neutral-service>`. The driver is renamed
  separately with `-i -d <name>` (8-char max) → `<neutral-driver>`. There is no in-place rename: it is uninstall
  (`-u force`) then reinstall. The event channel stays `Microsoft-Windows-Sysmon/Operational` throughout.
- **A null result is still a result** — and that is what came back. See "The result" above.
- **🔒 THE RENAME CREATED A NEW LEAK SURFACE INSIDE THE TELEMETRY. This one was not anticipated.** The
  concealment identity is not merely a set of strings to keep out of prose — **it is now written into
  `index=honeypot` itself**, from **2026-08-10 ~17:58 UTC** onward:
  - **`4697` × 2 at 17:58:42** — the Sysmon reinstall, carrying the new service and driver names together
    with their full binary paths in `Service_Name` / `Service_File_Name`.
  - **`4698` at 18:39:59** — a Windows Defender scheduled-scan task whose Subject `Account Name` is the
    **renamed machine account**, with the new hostname repeated inside the embedded task XML.
  - **The Splunk `host` field** on every event after the reboot, plus the `User` field on every Sysmon
    `EventCode=1` (`<neutral-hostname>\Administrator`).

  **Consequence: any screenshot, dashboard export, Phase-5 fixture or red-team corpus sample drawn from
  `index=honeypot` covering that window will leak the concealment identity.** A landed operator who found
  the public repo could use it to confirm the host is the honeypot — which is precisely the risk the
  placeholders exist to prevent. **Redact before publishing anything sourced from this index after
  2026-08-10 17:58.** Treat the index window as part of the sensitive list, not just the strings.
