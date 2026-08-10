# Honeypot — Where we are right now

**What this is:** the live situational snapshot for the honeypot operation, split out of the master
checklist so that the "read this first" page can change every session without churning the phase index.

- Phase-by-phase deliverable index: [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)
- Active Tier-1 concealment plan + tracker: [`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md)
- Per-session narrative + every live-measured fact: `session-logs/` dated handoffs + `.superpowers/sdd/progress.md`

**Last updated:** 2026-08-10

---

## 🔴 THE BOX WAS BROKEN INTO — 2026-08-08 02:03:32 UTC. B8 CAPTURE ACHIEVED.

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

**▶ NEXT MOVE — Tier-1 concealment (execution IN PROGRESS 2026-08-10, USER-approved 2026-08-08).** The
operator opened Task Manager twice, which lists `Sysmon64.exe` and `splunkd.exe`, and the host is named
`vm-honeypot-win`. "They saw the instrumentation" competes with "the box was empty" and is at least as well
supported, so we conceal the instrumentation and re-run the experiment. **Full plan + checkbox tracker:
[`TIER1-CONCEALMENT.md`](TIER1-CONCEALMENT.md).**

- **Still open:** the B9 decision — snapshot and tear down, or keep running. Deliberately not decided;
  Tier 1 assumes the box stays up.

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
