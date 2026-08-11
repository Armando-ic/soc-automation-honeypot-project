# Honeypot — Where we are right now

**What this is:** the live situational snapshot for the honeypot operation, split out of the master
checklist so that the "read this first" page can change every session without churning the phase index.

- Phase-by-phase deliverable index: [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)
- Active Tier-1 concealment plan + tracker: [`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md)
- Per-session narrative + every live-measured fact: `session-logs/` dated handoffs + `.superpowers/sdd/progress.md`

**Last updated:** 2026-08-11

---

## 🔴 SECOND INTERACTIVE INTRUSION — 2026-08-11 08:55:10 UTC. THE CREDENTIAL WAS HANDED OFF.

**A fifth external actor (`185.180.222.178`) opened a Logon Type 10 desktop session, stayed 38.9 seconds,
opened Task Manager twice, and disconnected. Zero impact.** Full write-up:
[`INC-2026-002`](../incidents/INC-2026-002-credential-handoff-intrusion.md).

**The headline is not the intrusion, it is where the credential came from.** `45.142.193.145` — the actor
that originally cracked this password on 2026-08-06 — re-validated it at 08:51:27, and **3m34s later a
completely different address logged in**. That address has **zero failed logons across 30 days**; it arrived
already holding the credential. Neither interactive actor across both incidents ever guessed a password
here. **The ~15,000 guesses this host absorbed came from entirely separate infrastructure.** Mapped as
**T1650 Acquire Access**.

- **The two sessions replicate each other almost exactly** — 2× Type 3 validation seconds apart → Type 10 →
  clipboard redirection on → shell in <4s → Task Manager twice via `explorer.exe` → disconnect without
  logging off. Two independent actors, three days apart, same ~40-second routine. That indicates a
  **standardised access-triage procedure and probably shared tooling**, and it is a stronger finding than
  either session alone.
- **Zero impact, verified:** 0 events across `4720/4722/4726/4728/4732`; `4697` exactly **14** (the
  documented noise floor) in a 32 ms burst; the lone `4698` characterised as a Windows Defender scan task
  from operator maintenance on 08-10; **no outbound network at all** (8 × `EventCode=3`, all inbound RDP,
  corroborated by the brake's `max_distinct_dst:1`); NSG verified afterwards still clean 5-rule baseline,
  **no deny residue — the brake correctly never fired.**
- **Residual:** disconnected, not logged off, so **resident and reconnectable**. Credential now burned
  across **at least five actors** and being actively re-validated and traded.

**▶ TIER-1 RESULT: NULL.** This was the first landing since the instrumentation was disguised, and dwell went
**down** (38.9s vs 54.1s). "They left because they saw the instrumentation" is **not supported**. Honest
limit: n=1 vs n=1, so the defensible claim is the *absence of lengthening*, not that concealment hurt. Full
analysis + the phase-by-phase table: [`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md).

**▶ NEXT LEVER (USER's call, not started): Tier 2 — furnishing.** The session surfaced a better candidate for
the real tell: **Server Manager auto-launches and shows a server with no roles**, at +7.6s, before Task
Manager was ever opened. That says "worthless box" far louder than a process list. Tier 2 stays out of scope
until explicitly chosen.

### ✅ B9 DECIDED (USER, 2026-08-11): NO snapshot-and-teardown. The box stays live.

The long-open B9 question is **closed**. The host keeps running with the burned credential, the concealment
in place, and the watch continuing. Every prior "if the box is ever parked" caveat is now conditional on a
future decision rather than a pending one.

---

## 🔴 FIRST INTRUSION — 2026-08-08 02:03:32 UTC. B8 CAPTURE ACHIEVED.

**A human operator established an interactive RDP session (Logon Type 10) from `113.203.61.61`, stayed
54 seconds, opened Task Manager twice, and disconnected.** That is the first genuine hands-on-keyboard
compromise of the operation and the event this whole build existed to capture. Full write-up:
[`incidents/INC-2026-001-first-interactive-intrusion.md`](../incidents/INC-2026-001-first-interactive-intrusion.md).

**PUBLISHED 2026-08-10.** The incident report + B8 triage section + the 4697 characterisation went public
in `5634d1b..fd039a7` (fast-forward, no force, scrub-clean at both layers). **Public tip `fd039a7`, repo
0/0 in sync.**

- **Four distinct external actors** used the credential inside ~30 hours. The other three did nothing but
  **Type 3 validations lasting 0.0s** — automated brute-forcers confirming a hit, not using it. One
  re-validated on a **~15-hour** schedule.
- **The credential went live 2026-08-06 ~17:04; first compromise came 3h48m later.**
- **Zero impact.** No accounts created, no persistence, no files, no C2, no fan-out. The auto-brake
  correctly never fired. The human triaged the box, judged an empty server not worth deploying on, and left
  — direct evidence for a hypothesis we had only been able to speculate about.
- **This landed at 02:03 UTC while nobody was watching.** Superseding Decision 1 (leave the box up
  unattended) is what made the capture possible at all; under the old rule the box would have been off.
- **Residual:** the session was **disconnected, not logged off**, so it is resident and reconnectable, and
  the credential is burned across at least four actors.
- **Persistence evidence was incomplete and re-verification caught it.** The first pass omitted
  `EventCode=4697`; adding it surfaced **14 service installs** in the window. All 14 investigated and
  benign — Windows **per-user service instances** created on every interactive logon. The conclusion held,
  the evidence didn't. **Output is a baseline: this host emits exactly 14 × 4697 per interactive logon**,
  so real signals are a count above 14, a binary outside `System32`, or a random-looking name.

**✅ TIER-1 CONCEALMENT EXECUTED AND VERIFIED 2026-08-10 (USER-approved 2026-08-08) — and its result is
now in (NULL, see the 2026-08-11 section above).** This operator opened Task Manager twice, which listed
`Sysmon64.exe` and `splunkd.exe`, and the host was named `vm-honeypot-win`. "They saw the instrumentation"
competed with "the box was empty" and was at least as well supported, so we concealed the instrumentation
and re-ran the experiment. Sysmon (service, driver and binary) and the Windows host were renamed, the data
plane was verified intact end-to-end, and the reboot cleared this intruder's resident session. **Exactly one
variable changed. Full plan, ripple-check evidence, the ✅ execution tracker and the result:
[`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md).**

---

## Prior state before the intrusion (kept for continuity)

**Phase 5 — honeypot-opening (Part B, live op). THE BOX IS OPEN, FULLY RE-ARMED, AND UNDER ACTIVE SPRAY
(as of 2026-07-30, session 46).** B7 complete and the catch-both expansion is fully live:
**two** weak local admins are planted (`backup` + a decoy named `Administrator`), the 🔴 RED
`honeypot-weak-cred-logon` tripwire has fired live on both, and the account-lockout wall is cleared.
**Still B8** — attended watch + capture the post-exploitation telemetry (Sysmon EID1/3/22 in
`index=honeypot`) as Phase-5 fixtures. Then **B9** teardown (restore path already dry-run proven from
`honeypot-preopen-20260717`).

**2026-08-05 — THE PASSWORD WAS THE BLOCKER, and it has been changed.** Six days of running the box 24/7
under the new Decision 1 produced **zero landings** against roughly **15,000 real password guesses** on
the planted `Administrator` (4625 `Sub_Status=0xC000006A`, ~110-120/hour, all genuinely tested since
lockout is `Never`). Nothing was broken; every gate stayed green. The original password simply was not in
the wordlists in play — exactly the risk session 42 flagged when the account was picked. Actions taken:
complexity policy **Disabled** and minimum length **0** in `secpol.msc`, then both decoys repointed at
top-ranked RDP-spray base terms sourced from published honeypot research (the Specops 4.6M-password
dataset). Which term went on which account stays in the gitignored creds file and the session ledger, out
of every published doc. Both verified `Enabled`, in Administrators, with `PasswordExpires` blank. Two new B8 dashboard panels ship the evidence: wrong-password guesses by account
and source IP, and a Sub_Status failure-reason breakdown that makes a returning lockout wall visible at a
glance. Full reasoning + the source rankings live in the opening runbook's B7.3. **Expect a fast answer:
at that guess rate a top-of-list password gets tried early, so hours not days — and 24-48 hours of silence
would itself indicate hash-based or credential-stuffing tooling rather than a dictionary.**

**Full re-arm re-proven live 2026-07-30 (session 46), every gate green:**
- **Phase A** — A1 ok · A2 `configured:true/unknown/error` · A3 all 8 keys SET · A5 `stale:false`, exactly
  +1 post/min · A6 both honeypot workflows Active · A7 clean 5-rule NSG baseline. **A4 retired** with Falcon.
- **Phase B** — B1 **135** /15m · B2 **193** EID3 /24h · B3 **37** failed logons /15m (no rediscovery lag
  this power-on, see the runbook's corrected B8 note).
- **B4 tripwire liveness — NEW GATE, authored this session.** Nothing previously proved the *alarm*, only
  the brake and the data plane. Both saved searches Enabled with a populated Next Scheduled Time, the
  Splunk webhook action verified pointing at `/webhook/honeypot-logon-alert`, and the full
  `4624 → UF → Splunk → saved search → n8n → Discord` chain proven by a real operator logon firing the
  amber backstop (Type 10, which also re-vindicates "never allowlist logon types").
- **Phase C** — the dry-run flipped the **real** NSG (`access:Deny, state:Succeeded`) and reverted clean;
  the SP secret still authenticates. `trips` incremented exactly +1 (4 → 5), confirming the counter is
  per-trip. The one historically unexplained trip left no NSG residue, so it was attended and reverted
  (session-45 bookkeeping), not an unattended real fire.

**Both live decisions are now SETTLED (USER, 2026-07-30):**
1. ✅ **Overnight posture — Decision 1 SUPERSEDED. The box stays running between sessions.** Session 45
   measured that a multi-day gap prunes the box off botnet target lists (first external touch ~80 min
   after boot, 4625 down to 2 in 24h vs a historical ~8,000/day), so deallocate-when-unattended worked
   directly against ever catching a landing. Accepted in exchange: containment no longer waits on a human,
   which is fine because both layers are automated and fail closed. Cost is continuous credit burn.
2. ✅ **Sign-off 2 RE-SIGNED without Falcon.** Bounds are now the static NSG envelope + the auto-brake's
   NSG egress-deny + attended monitoring. The trial ended 2026-07-28; what was lost is the fast-contain
   layer and the EDR feed, not the floor (brake survival verified in code).

Both are written up in [`honeypot-opening-runbook.md`](../honeypot-opening-runbook.md) under **Standing
decisions + sign-offs**, which is the source of truth.
