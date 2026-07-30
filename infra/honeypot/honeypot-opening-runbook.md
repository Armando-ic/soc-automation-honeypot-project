# Honeypot-opening runbook (re-arm -> open -> monitor)

**What this is:** the living, copy-paste operational runbook for the honeypot-opening live operation:
**re-arm** the safety brake, **open** the box, **monitor** for a landing. It is the matched partner of
[`b9-teardown-runbook.md`](b9-teardown-runbook.md) (teardown). The steps were promoted here from the
session-42/44 handoffs so they live in one place instead of a dated record. Every power-on you re-run
Phase A+B+C from this doc (Decision 2 interlock).

**Source-of-truth boundary (do not duplicate, to avoid `/lint` drift):**
- The **alert/saved-search SPL + names** are owned by [`honeypot-brake-triggers.md`](honeypot-brake-triggers.md)
  §3. This runbook references them; it does not re-copy the SPL.
- The **brake thresholds + behavior** are code (`grounding-service`), pinned by tests.
- The **NSG rules** are owned by [`nsg-rules.md`](nsg-rules.md).
- This doc owns the **operational sequence + exact commands** only.

## Golden rules (hard-won)

- **USER drives every live/az/RDP/Splunk step hands-on.** Never fire az/live/paid commands from an agent.
- **Attended posture is ongoing, not a one-shot gate.** The planted creds survive every restart, so the
  box reopens on every power-on: **re-arm on every power-on** (Decision 2). Decision 1's
  deallocate-when-unattended was **superseded 2026-07-30** and the box now stays up between sessions —
  see [Standing decisions](#standing-decisions--sign-offs) for why.
- **`configured:true` is necessary but NOT sufficient** — it reads identical whether the SP secret is
  healthy or expired. Only a live NSG flip (Phase C) proves the write path.
- **SOC-side heartbeat != honeypot eyes.** A green feeder proves the SOC chain posts, not that the honeypot
  ships events. Phase B (EID3 count) is the separate proof.
- **`stale:true` is ALWAYS a real fault.** Never explain it away as "the brake must have fired."
- **`sourcetype=XmlWinEventLog`, never `*Sysmon*`.** **Never allowlist logon types** (a `backup` logon
  lands as Type 3 AND Type 10).
- **No inline secret paste.** Load the weak password + SP creds from the gitignored files on the box; use
  the `SET`/`EMPTY` awk pattern to check `.env`.

## Prereqs — where the boxes are

- VMs: `vm-soc-v2-splunk` (10.0.0.5) + `vm-soc-v2-n8n` (10.0.0.6) in `rg-soc-v2-azure-central-us`;
  `vm-honeypot-win` + NSG `nsg-honeypot` in `rg-honeypot`.
- Start (SOC boxes first, honeypot LAST per the interlock):
  `az vm start -g rg-soc-v2-azure-central-us -n vm-soc-v2-splunk` / `... -n vm-soc-v2-n8n` /
  `az vm start -g rg-honeypot -n vm-honeypot-win`. Verify all `running` with `az vm list -d -o table`.
- n8n box shell: `ssh -i C:/Users/Owner/.ssh/vm-soc-v2-linux-key.pem azureuser@<n8n-public-ip>` then
  `sudo -i` then `cd /root/soc-src`. `grounding-service` has no host port map, so hit it from **inside the
  container**: `docker exec grounding-service curl -s localhost:8000/...`.

---

## Phase A — read-only re-arm (all non-state-changing)

Run on the **n8n box** (`/root/soc-src` as root) unless noted.

```bash
# A1 grounding-service up                                   -> {"status":"ok"}
docker exec grounding-service curl -s localhost:8000/health

# A2 THE ARMING CHECK  -> {"configured":true,"access":"unknown","provisioning_state":"error"}
#    unknown/error is CORRECT pre-trip. configured:false = NSG half unarmed = STOP.
docker exec grounding-service curl -s localhost:8000/brake/nsg-status

# A3 brake .env keys (prints key + SET/EMPTY only, never values) -> all 8 SET
awk -F= '/^(BRAKE_ENABLED|AZURE_TENANT_ID|AZURE_CLIENT_ID|AZURE_CLIENT_SECRET|HONEYPOT_SUBSCRIPTION_ID|HONEYPOT_NSG_RG|HONEYPOT_NSG_NAME|SPLUNK_HOST_IP)=/{print $1, ($2==""?"EMPTY":"SET")}' grounding-service/.env

# A4 RETIRED 2026-07-30 - skip it. The CrowdStrike trial ended 2026-07-28, so there is no fast-contain
#    layer left to arm and this check no longer gates anything. The NSG egress-deny floor is the whole
#    brake now, and Phase C is what proves it. (Was: FALCON_PINNED_AID -> SET.)

# A5 feeder liveness (run TWICE, ~90s apart) -> stale:false BOTH times, total_posts HIGHER the 2nd time
docker exec grounding-service curl -s localhost:8000/brake/feed-status
```

**A6 (n8n browser UI):** confirm the **Active** toggle is ON for BOTH `honeypot-brake` and
`honeypot-host-feeder`. (A climbing A5 counter proves both transitively.)

**A7 (local PowerShell, `az`):** exactly 5 outbound rules, NO `honeypot-brake-egress-deny`:
```powershell
az network nsg rule list -g rg-honeypot --nsg-name nsg-honeypot --query "[?direction=='Outbound'].{p:priority,n:name,a:access,ports:destinationPortRange}" -o table
```
Expect: `allow-splunk-telemetry` 1000/9997, `allow-dns` 1010/53, `allow-web` 1020 (Ports renders blank -
cosmetic), `deny-soc-private` 4000, `deny-all-other-egress` 4096. If `honeypot-brake-egress-deny` is
present (leftover trip): `az network nsg rule delete -g rg-honeypot --nsg-name nsg-honeypot -n honeypot-brake-egress-deny`.

## Phase B — does the brake have EYES (the check Phase A cannot see)

**Splunk Web**, time picker Last 60 min. Three checks, and only the first two gate.

```spl
# B1 LIVENESS (GATES) — is the brake's data source alive at all?
index=honeypot sourcetype=XmlWinEventLog earliest=-15m | stats count
```
Expect **> 0**. Zero here while A5 says `stale:false` is the blind-but-green trap = Sysmon/UF didn't
restart cleanly = **STOP** and fix the honeypot data-plane.

```spl
# B2 CAPABILITY (GATES) — is Sysmon NetworkConnect actually configured?
index=honeypot sourcetype=XmlWinEventLog EventCode=3 earliest=-24h | stats count
```
Expect **> 0**. This proves the brake *can* see egress fan-out. A single-digit count is normal and fine;
long-lived outbound sessions emit one EID3 at establishment and nothing after.

> **Two ways B2 reads 0 on a perfectly healthy box. Check both before you diagnose anything.**
>
> 1. **You just booted after a long downtime.** B2's window is 24 hours, but the box may only have been up
>    for two minutes of it, so there is almost nothing for it to count. Give the UF a few minutes to
>    reconnect - its own 9997 session and the first DNS lookups each emit an EID3 - then re-run. If B1 is
>    already healthy, B2 is measuring the outage, not a fault.
> 2. **Falcon died on 2026-07-28.** The sensor's phone-home used to be one of the steady EID3 contributors,
>    so the benign baseline is permanently smaller than every pre-07-28 measurement in these notes.
>
> Both are the same failure mode that cost an hour on 2026-07-27: a gate drifting away from the thing it
> claims to measure. B1 is the honest liveness signal. If B1 is green and B2 is 0, wait and re-run B2
> before touching anything.

```
# B4 TRIPWIRE (GATES) - is the ALARM actually wired, not just the telemetry?
```
**Added 2026-07-30.** B1-B3 prove the honeypot is shipping events and A1-A7 prove the brake can act on
them. **Neither one proves anything will tell you the box fell.** A Splunk restart after a multi-day
deallocation, a search left disabled during an investigation, or a webhook action that lost its URL all
leave every other check in this runbook green while the operation is silently pointless - you would be
watching a Discord channel that is structurally incapable of lighting up. Two parts, both cheap:

1. **Saved searches are alive (read-only).** Splunk Web -> Settings -> Searches, reports, and alerts ->
   filter for `honeypot`. Both `honeypot-weak-cred-logon` (primary) and `honeypot-any-logon` (backstop)
   must show **Enabled** *and* a populated **Next Scheduled Time**. An enabled search with an empty next
   run is not scheduled and will never fire. Names are owned by
   [`honeypot-brake-triggers.md`](honeypot-brake-triggers.md) §3.
2. **Delivery works end to end ($0, bypasses Splunk).** Fire the B7.2 synthetic payload and confirm a
   🔴 HONEYPOT COMPROMISED embed lands in Discord. That proves webhook -> n8n -> Discord independently of
   whether Splunk is scheduling anything.

Part 1 green + part 2 green = the alarm is real. Either one red = **STOP**, fix it before you rely on the
watch. (Naming note: Phase B's checks B1-B4 are unrelated to Part B's operational steps B1-B9.)

```spl
# B3 PRESSURE (INFORMATIONAL, NEVER GATES) — is anyone actually knocking?
index=honeypot source="WinEventLog:Security" EventCode=4625 earliest=-15m | stats count
```
Zero here means only that the farm has not found you yet (see the rediscovery note under B8). It is
**not** a data-plane fault and must not stop the op.

> **Why three checks and not one.** This phase used to gate on `EventCode=3 earliest=-15m | stats count`
> alone. On 2026-07-27 that returned **0** on a completely healthy box and read as a data-plane failure,
> costing about an hour of debugging. Root cause: EID3 volume here is dominated by *inbound* 3389
> brute-force, so the old gate silently measured "is someone attacking us" rather than "does the brake
> have eyes." Those two come apart exactly when you power on after a multi-day gap. Live proof from that
> session: 129 Sysmon events in the same 15-minute window (B1 healthy), EID3 = 8 over 24h (B2 healthy),
> and 4625 = 0 (B3 quiet). All three facts true at once, nothing broken.

## Phase C — the gating dry-run (the ONE state-changing step; do only after A+B green)

The only proof the SP secret still authenticates + the NSG write path fires post-restart. Run on the still-
CLOSED box; revert promptly.

```bash
# C1 (n8n box) build a 160-distinct payload (198.18/15 = RFC-2544 test space) + fire it -> {"message":"Workflow was started"}
PAYLOAD=$(python3 -c 'import json;print(json.dumps({"events":[{"dst_ip":f"198.18.{i//254}.{i%254}","dst_port":443} for i in range(160)],"source":"dryrun"}))')
curl -s -X POST http://10.0.0.6:5678/webhook/honeypot-brake -H 'content-type: application/json' -d "$PAYLOAD"
```
- **C2 Discord:** 🔴 AUTO-BRAKE FIRED, `reason:egress_fanout`, `distinct_dst:160`, `source:dryrun`.
  The embed still carries its "Falcon contain action submitted (AID-pinned)" line. **After 2026-07-28 that
  line is cosmetic** - the Falcon nodes now error against a dead trial, which is harmless because they are
  all non-halting and the alert hangs off `nsg_deny`, not off the Falcon chain. Judge the trip by the NSG,
  which is C3.
- **C3 confirm the real NSG flipped (local PowerShell):**
  ```powershell
  az network nsg rule show -g rg-honeypot --nsg-name nsg-honeypot -n honeypot-brake-egress-deny --query "{access:access,state:provisioningState}" -o json
  ```
  Expect `{"access":"Deny","state":"Succeeded"}`. **This is the proof `nsg-status` can never give.**
- **C5 REVERT (mandatory, promptly):**
  ```powershell
  az network nsg rule delete -g rg-honeypot --nsg-name nsg-honeypot -n honeypot-brake-egress-deny
  ```
  That single delete is the whole revert now. The old second half of this step ("then Lift Containment in
  the CrowdStrike console") **retired 2026-07-30** - the trial ended, contain never actually lands, so
  there is nothing to lift.
- **C6 confirm clean:** `docker exec grounding-service curl -s localhost:8000/brake/nsg-status` back to
  `{"configured":true,"access":"unknown","provisioning_state":"error"}`.

**FAILURE (SP secret expired):** C1 `fired:false`/`brake_error`, or C3 shows no rule -> `az ad sp credential
reset` for `honeypot-brake-sp`, update `AZURE_CLIENT_SECRET` in the box `.env`, `cd /root/soc-src/grounding-service
&& docker compose up -d --build --force-recreate grounding-service`, re-run Phase C.

---

## Standing decisions + sign-offs

Adopted 2026-07-24 unless noted. Do not re-litigate the ones still standing.

- **Decision 1 - deallocate-when-unattended: SUPERSEDED 2026-07-30.** The honeypot now **stays running
  between sessions**. The original rule (deallocate whenever nobody is attending) turned out to work
  directly against the goal: a multi-day gap prunes the box off the botnet target lists, so every power-on
  bought roughly 80 minutes of dead time and pressure collapsed to 2 failed logons in 24h against a
  historical ~8,000/day (measured 2026-07-27, see the rediscovery note under B8). The tradeoff accepted in
  exchange: containment no longer depends on a human being awake. Both safety layers are automated and
  fail closed, the NSG egress-deny is enforced at the Azure control plane rather than in the OS, and
  Splunk records the telemetry whether or not anyone is watching. **Attendance now buys live capture and
  judgment, not containment.** Cost is continuous Azure credit burn.
  - **"Honeypot 24/7" is meaningless unless `vm-soc-v2-splunk` and `vm-soc-v2-n8n` are up 24/7 too.**
    The auto-brake is not on the honeypot. Its only built feeder is the n8n `honeypot-host-feeder`
    workflow, which every minute calls `/brake/host-feed` on `grounding-service`, and that endpoint runs
    `host_feed_spl()` **as a search against Splunk** (`build_honeypot_host_feeder_workflow.py`, `app.py`).
    So the live chain is: honeypot Sysmon -> UF -> **Splunk** -> feeder -> **n8n** -> `/brake/evaluate` ->
    NSG deny via the SP. **Splunk down = the brake is blind** (the feeder returns no events and the
    tripwire saved searches never run). **n8n down = the brake is dead and no Discord alert fires at all.**
    An open honeypot with either box down keeps only the *static* NSG envelope, which is exactly the
    posture Sign-off 2 declines to rely on alone.
  - **Verified 2026-07-30 (`az resource list --resource-type "Microsoft.DevTestLab/schedules"`):**
    `vm-honeypot-win` has **no** auto-shutdown schedule, so the honeypot itself stays up. But
    `shutdown-computevm-vm-soc-v2-splunk` and `shutdown-computevm-vm-soc-v2-n8n` **do** exist. Left in
    place, they kill the brake nightly (~23:00 ET) while the honeypot stays wide open - strictly worse
    than the old Decision 1, which at least parked the bait along with the safety net. Disable both:
    ```powershell
    az vm auto-shutdown -g rg-soc-v2-azure-central-us -n vm-soc-v2-splunk --off
    az vm auto-shutdown -g rg-soc-v2-azure-central-us -n vm-soc-v2-n8n --off
    ```
    Leave the `vm-soc-v2-iris` and `vm-soc-v2-win` schedules alone - neither is in the live-op path.
  - **Parking the box means `az vm deallocate`, never an in-guest Windows shutdown.** Shutting down from
    inside RDP leaves Azure reporting **`VM stopped`**, which still reserves and **bills compute**. Only
    `VM deallocated` stops the compute meter.
- **Decision 2 - power-on re-arm interlock + no auto-start: STANDS.** Bring the safety net up before the
  bait, and keep `vm-honeypot-win` off any auto-start schedule. Superseding Decision 1 makes power-ons
  rarer, not exempt.
  - **The literal order, since "A+B+C first, honeypot last" cannot be followed as written.** Phase B reads
    `index=honeypot` for events in the last 15 minutes, so it is impossible before the honeypot is
    running. Do it in this order: **(1)** start `vm-soc-v2-splunk` + `vm-soc-v2-n8n`, **(2)** Phase A
    (SOC-side, read-only, honeypot still down), **(3)** start `vm-honeypot-win` LAST, **(4)** Phase B once
    the UF has had a few minutes to reconnect, **(5)** Phase C dry-run + revert. The interlock's real
    intent is that the brake is armed and proven before the bait is reachable, not that every phase
    literally precedes the power-on.
- **Sign-off 1 - single feeder: STANDS.** B4 network backstop unbuilt; killing Sysmon/UF blinds the
  fan-out trip.
- **Sign-off 2 - brake bounds FAN-OUT only: RE-SIGNED 2026-07-30 without Falcon.** Concentrated
  single-dest harm and DNS/53 exfil still trip nothing. The original sign-off bounded that residual risk
  with "the static NSG envelope + Falcon + attended monitoring"; the CrowdStrike trial ended 2026-07-28
  and a second extension was refused in writing, so the bounds are now **the static NSG envelope + the
  auto-brake's NSG egress-deny + attended monitoring**. What was lost is the fast-contain layer and the
  EDR detections feed, not the floor: the brake was verified in code (`build_honeypot_brake_workflow.py`)
  to fire `nsg_deny` before Falcon is ever attempted, to hang the Discord alert off `nsg_deny` rather than
  the Falcon chain, and to keep every Falcon node non-halting. Arguably the remaining control is the
  stronger one, since the NSG is enforced outside the guest OS where a host-level compromise cannot reach it.

## B7 — open the box (point of no return)

- **B7.1 create the PRIMARY tripwire** `honeypot-weak-cred-logon`. Full spec (SPL, three-way severity) is in
  [`honeypot-brake-triggers.md`](honeypot-brake-triggers.md) §3(b) — for catch-both the filter is `user IN ("acct1","acct2")`. Splunk saved alert settings: **Scheduled**,
  Cron `* * * * *`, **Time Range Last 5 minutes** (NOT 24h - that re-fires the same logon ~1440x/day),
  Trigger alert when Number of Results > 0, **Trigger: For each result**, Action Webhook ->
  `http://10.0.0.6:5678/webhook/honeypot-logon-alert`. Confirm it saves **Enabled** with a populated **Next
  Scheduled Time**. (The BACKSTOP `honeypot-any-logon` §3(a) persists across deallocation.)
- **B7.2 prove the RED path pre-plant ($0, bypasses Splunk).** On the n8n box:
  ```bash
  PAYLOAD=$(python3 -c 'import json;print(json.dumps({"search_name":"honeypot-weak-cred-logon","sid":"synthetic_red_test","results_link":"http://vm-soc-v2-splunk:8000/en-US/app/search/search","result":{"_time":"1784908200","src_ip":"203.0.113.10","user":"backup","Logon_Type":"3","ComputerName":"vm-honeypot-win"}}))')
  curl -s -X POST http://10.0.0.6:5678/webhook/honeypot-logon-alert -H 'content-type: application/json' -d "$PAYLOAD"
  ```
  Expect a 🔴 HONEYPOT COMPROMISED embed keyed on `honeypot-weak-cred-logon`. (Amber/UNRECOGNIZED/nothing = fix before planting.)
- **B7.3 PLANT (confirm with USER first).** RDP into the honeypot as your operator admin. Plant the weak
  cred(s) B7 chose (live choice in the ledger; catch-both = a service-shaped account + one named after the
  hottest farm target). Each one: `lusrmgr.msc` -> New User, password from the gitignored **creds file**
  (typed into the GUI dialog, never chat), "must change at next logon" UNCHECKED, "password never expires"
  CHECKED, then add it to local **Administrators**. 3389 is already internet-facing. **Box is OPEN once a
  weak account is an enabled admin.**
  - **PRE-CHECK the lockout threshold first, or the plant is decorative.** `net accounts` -> the
    `Lockout threshold` line must read `Never`. This box shipped with **10**, and at the observed spray
    rate the hottest account sat locked essentially continuously: measured 2026-07-24, of 74 post-creation
    attempts only **10** were real password guesses before the threshold tripped, then **64** bounced off
    `0xC0000234` (account locked out). Even a correct guess would have been refused. Clear it with
    `net accounts /lockoutthreshold:0` and re-verify. Note this also removes lockout protection for the
    operator account, which is the right tradeoff on a honeypot but is a real change.
  - **`Administrator` on this box is NOT the built-in RID-500 account.** Azure provisioning *renames*
    RID-500 to whatever admin username you specified, so here **`mandoaic` is RID-500** and the name
    `Administrator` was free to take. What B7 planted is an ordinary local account (RID 1001) wearing the
    name the whole spray farm targets. Two consequences: it is **not** exempt from account lockout the way
    a real RID-500 is (see the pre-check above), and **B9 restore deletes it rather than disabling it**.
    Verify which account holds RID-500 before assuming anything:
    `Get-LocalUser | Select-Object Name,Enabled,SID | Format-Table -AutoSize`
  - **Set the password via the GUI or `Read-Host -AsSecureString`, never `net user <acct> <password>`.**
    `net.exe` is a separate binary, so that form is captured verbatim in **Sysmon EID1 `CommandLine`**,
    ships to `index=honeypot`, shows up in the B8 process panel, and would ride along in any exported
    Phase-5 fixture. That publishes your own honeypot credential. The safe PowerShell form is
    `Set-LocalUser -Name <acct> -Password (Read-Host -AsSecureString)`.
  - **The password, not the account name, decides whether the box falls.** A hot account with a
    non-dictionary password absorbs thousands of attempts and never opens. Pick from the top of a real RDP
    spray list. If the complexity policy rejects it, disable it in `secpol.msc` -> Password Policy.
- **B7.4 prove the REAL RED.** RDP in as `backup` from an **external** network (phone hotspot / RD client on
  cellular - PC network untouched). Expect the real 🔴 RED embed (Type 3 and/or Type 10). **Note that logon
  as YOUR baseline** so a real attacker (a third IP) is not confused with it.

## B8 — monitor + capture

- Import/confirm the [`honeypot-attacker-session-b8.xml`](dashboards/honeypot-attacker-session-b8.xml)
  dashboard in Splunk ("Honeypot - Attacker Session (B8)").
- **Loop:** a 🔴 RED from an UNFAMILIAR external IP = a real landing -> set the dashboard **Incident Window**
  to `[alert time -> now]` -> read the process / network / DNS panels. That's the Phase-5 fixture capture.
- No landing by the end of an attended window -> **leave the box running** and pick the watch back up next
  session (Decision 1 superseded 2026-07-30). Deallocating is now a deliberate act, not the default: if you
  do park it, you re-run Phase A+B+C on the way back up and you eat the rediscovery lag below.

### Expect a rediscovery lag on every power-on (measured 2026-07-27)

**A multi-day deallocation prunes you off the botnet target lists, and the spray does not resume the
moment you boot.** The public IP is Standard SKU / Static so it never changes across a deallocate, but
scanners that hit a dead address drop it and you have to be found again by fresh sweeps.

Measured on 2026-07-27 after a 3-day gap: box up ~18:3x UTC, **first external touch at 19:49 UTC** (~80
min later) - two 4625s for user `Test` from `45.142.193.145`, bracketed by the matching inbound EID3
connections. Before that, 4625 = **2 in 24h** against a historical ~8,000/day on the same address.

**The lag is variable, not a fixed 80 minutes - it tracks how recently the address was last seen
answering.** Counter-measurement on 2026-07-30, also after a 3-day gap: **37 failed logons in the first
15 minutes**, roughly 148/hour, no dead time at all. The difference is what the address was doing before
it went dark. Going into the 07-27 boot it had been dropped for days; going into the 07-30 boot it had
spent all of 07-27 under active spray, so the farm still had it. Practical read: **check B3 before you
assume you have an hour of backlog time** - some power-ons hand you a live box immediately.

Practical consequences:
- **Budget the first 1-2 hours after any power-on as dead time.** Do the backlog, not the watching.
- **Do not diagnose a quiet box as broken.** Run Phase B's three checks; if B1 and B2 pass, the stack is
  fine and B3 is just telling you the farm hasn't arrived.
- **This measurement is what killed Decision 1** (resolved 2026-07-30, see Standing decisions). Deallocating
  when unattended is what causes the pruning, so it worked directly against ever catching a landing. The box
  now stays up between sessions and the lag only applies after a deliberate park or an Azure-side restart.

## B9 — teardown

When the capture is done or the operation ends: [`b9-teardown-runbook.md`](b9-teardown-runbook.md)
(Step 0 forensic snapshot FIRST; the snapshot->disk recovery half is dry-run proven).
