# Tier-1 concealment — plan, evidence, and execution tracker

**What this is:** the active honeypot experiment. Hide the instrumentation, change nothing else, and see
whether the next operator stays longer. Split out of the master checklist so the experiment reads as one
self-contained artifact.

- Live situational snapshot: [`CURRENT-STATE.md`](CURRENT-STATE.md)
- Phase index: [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)
- **Copy-paste procedure:** [`honeypot-opening-runbook.md`](../honeypot-opening-runbook.md) → **B8 → "NEXT: Tier-1 concealment"**
- The incident that motivated it: [`INC-2026-001`](../incidents/INC-2026-001-first-interactive-intrusion.md)

**Status:** approved 2026-08-08 · executed 2026-08-10 · **concealment IN PLACE — now watching for the next landing**
**Last updated:** 2026-08-10

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
| 1 | **Windows host → `<neutral-hostname>`** — value-neutral and production-shaped. The **Azure VM name stays `vm-honeypot-win`**; only the in-guest computer name changes | In plan |
| 2 | **Sysmon service, driver and binary → neutral names** — removes the loudest tell in Task Manager, no telemetry fidelity lost | In plan |
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

## ⬜ Execution tracker

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
- 🟢 **5. Baselines recorded; dwell-time watch is now PASSIVE.** New state: host `<neutral-hostname>`, Sysmon renamed,
  service description neutralized, no Sysmon-named artifacts. **Success criterion = the next operator dwells
  materially longer than 54s with the box otherwise unchanged.** Nothing to execute — just watch. A null
  result (another sub-minute visit) is itself evidence for "the box was empty" and points at Tier 2.

**Sysmon first, host+reboot last** on purpose: the reboot re-validates that the Sysmon reinstall survives a
boot, and a broken reinstall is caught at step 2 before anything else is disturbed.

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
- **A null result is still a result.** If the next operator also leaves fast, that is evidence for "the box
  was empty" and points at Tier 2 as the next lever — which remains out of scope until deliberately chosen.
