# 0D-2 — handoff to the next Claude instance (2026-06-29)

**Read `infra/honeypot/session-logs/HANDOFF.md` first** — the "🟢 0D-2" block is the canonical, full state. This doc is a
short pointer + the **open decisions** the user wants to work through next session (with analysis already done).

> **UPDATE 2026-06-29 (cont. session):** Q1 + #10 + Q2 **RESOLVED** — poller **ACTIVE**, #10 bounded-watermark
> **shipped+deployed** (live `/falcon/state` unchanged), synthetic Contain-recommended demo **path-validated**
> (run 282 / Iris #250; evidence `falcon-0d2-validation.md` §6). Commits `de814c8`, `1502679`, `08bf78c` on
> `ai-upgrade` (unpushed) + this update. **Remaining:** deallocate VMs (+ optional clean `falcon-contain` run;
> organic real-attacker capture). Q3 watchdog still **deferred**. The Q1–Q3 analysis below is retained for the
> organic-capture follow-on.

## Start here
- Branch **`ai-upgrade`** in `SOC_Automation_Project`. **NOT pushed.** This session's commits: **`ea285ef..eb18dc3`** (6).
- Key docs (this repo, `infra/honeypot/`): `falcon-poller-build.md` (runbook), `falcon-alerts-field-map.md` (us-2 schema),
  `falcon-0d2-validation.md` (e2e evidence), `build_falcon_poller_workflow.py` + `build_falcon_contain_workflow.py` (the
  two n8n workflow generators → `JSON/falcon-alert-poller.json`, `JSON/falcon-contain.json`).
- Conventions: never `git add -A` (keep `Personal/`, `.playwright-mcp/`, `__pycache__/` out); commit trailer
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`; hands-on steps use a **"Where:"** header + numbered commands.

## State — 0D-2 functionally COMPLETE + verified all-green (2026-06-29)
- **Poll → triage** (`falcon-alert-poller`): LIVE, EICAR empty-IOC e2e green (Iris #245, idempotent, no 422). Cron **INACTIVE**.
- **Backend hardened** (review #4 map-sort, #5 real-host): deployed to the live `soar-grounding-service` image + smoke-verified.
- **Human-fired Contain** (`falcon-contain`): round-trip `normal→contained→normal` validated, AID-pinned, `wait_lift`=120s.
- Re-confirmed via a read-only live sweep (`/health`, `/falcon/state`, `/falcon/map` smoke) + 23 passing `test_falcon.py` tests.

## Live state the fresh instance MUST know (NOT in git)
- VMs **`vm-soc-v2-n8n` + `vm-soc-v2-splunk` are RUNNING** — ⚠️ deallocate when done: `az vm deallocate -g rg-soc-v2-azure-central-us -n <vm>`.
- grounding-service runs the **HARDENED** image; poller state `watermark=2026-06-29T15:11:34.51Z`, `seen=[<EICAR composite_id>]`. Host left **`normal`**.
- n8n: `falcon-alert-poller` + `falcon-contain` both imported + cred-bound (`Crowdstrike Falcon Account`); poller **INACTIVE**.
- **Deploy mechanism** = base64 over `az vm run-command` (n8n VM is Linux; `/root/soc-src` is non-git) — needs **per-action USER approval**
  (hands-on boundary; the auto-mode classifier blocks autonomous VM writes). `pytest` is a **dev-only** dep (not in the prod image) →
  verify deploys via **live route smoke**, not in-container pytest.

---

## Open decisions for next session (raised by the user) — analysis below, the user wants to decide these

### Q1 — Why is the poller cron INACTIVE, and do we need it ACTIVE?
- **Why inactive:** in n8n a workflow only auto-fires its trigger when toggled **Active**. We built + validated the poller via
  manual **Test workflow** runs and never flipped it Active — on purpose (during build you don't want a 15-min cron firing real
  triage + Iris/Discord every tick; activation is a conscious operational choice).
- **What Active buys you:** the Schedule Trigger fires **every 15 min unattended** → Falcon alerts pulled → triaged → Iris/Discord,
  no human clicking. That is the entire point of a *poller*. The Splunk path already runs autonomously (active `honeypot-triage`
  webhook); the **Falcon source only feeds the loop autonomously once the poller is Active.**
- **Caveats:** runs only while `vm-soc-v2-n8n` is up (auto-deallocates ~23:00 ET; alerts arriving while down are caught on the next
  tick after start via the watermark/seen catch-up). Each tick re-pulls EICAR (deduped, never re-triaged). A future IOC alert would
  auto-triage → if high-severity → "Contain recommended". Cost = a few Falcon API calls per tick.
- **Recommendation:** activate when you want autonomous operation (the intended end state) — ideally **paired with #10** so a
  fresh/empty state can't silently break the poll while unattended. Keep inactive while iterating or for on-demand demos only.

### Q2 — alert → "Contain recommended" demo: pursue it?
- **Pros:** completes the flagship end-to-end (real alert → triage → high+IOC → verifier passes → "Contain recommended" → human
  fires `falcon-contain` → contained→normal). Exercises the verifier's `severity_supported` gate + IOC enrichment (AbuseIPDB/GreyNoise)
  on a real attacker IP. Best artifact for employers.
- **Cons / blocker:** gated on a **credential-access / IOC-bearing, high-severity Falcon alert** that doesn't exist yet — Falcon's
  honeypot detections so far are behavioral **Execution** (EICAR), `source_ips` empty. The RDP brute force visible in Splunk (85
  IPs/24h) hasn't tripped a Falcon credential-access conviction.
- **Ways to get one (trade-offs):** (a) **wait for organic compromise** (keep the poller Active to catch it) — purest, unpredictable
  timing; (b) **generate on-host attack behavior** Falcon convicts — forces it but reintroduces synthetic activity (project moved
  away from synthetic Atomic data), risky on an exposed box, and a locally-run tool's IOC is a hash not an external `src_ip` (so the
  IP-enrichment leg still wouldn't fire); (c) **synthetic injection** of a crafted high+IOC alert object through `/falcon/map` →
  triage — proves the **software path** (gate → contain-recommended) deterministically now, clearly labeled as path-validation.
- **Recommendation:** do the **synthetic-injection path-validation** now (cheap; proves the gate + contain-recommendation), AND keep
  the poller Active to capture an organic one for the "real" demo.

### Q3 — Watchdog (auto-lift): build it?
- **Pros:** defense-in-depth — auto-restores honeypot egress if a contain ever gets stuck (lift fails + nobody acts); "self-healing"
  is a nice autonomy talking point; completes the runbook's C.10 spec.
- **Cons (why deferred):** a naïve watchdog is a **racy auto-actuator** — a 15-min tick can observe a *legitimate in-progress* human
  contain and **prematurely lift it** (review #2, HIGH); its single lift has no verify → **false all-clear** (#3); and it **can't run
  during the 23:00-ET n8n shutdown** (#12) — exactly when an unattended stuck-contain matters most. A *safe* version needs a
  coordination marker (`contain_active`/`contained_since` in state) + a `should_auto_lift` helper + lift-verify — real code for a net
  you may never trip, while the human `falcon-contain` already self-lifts + escalates to a manual-lift alarm.
- **Recommendation:** keep deferred. If you want real overnight resilience, build it **off n8n** (a small always-up scheduled task
  running `scripts/falcon-contain-roundtrip.ps1`'s lift leg), not as an n8n branch — that's the only design that closes the real gap.

### #10 — bounded-watermark hardening: do it?
- **What:** `load_state` returns `watermark=""` on a missing state file; the FQL is `created_timestamp:>='{watermark}'`, so an empty
  watermark (fresh volume + skipped seed) → `created_timestamp:>=''` → **400 every tick (silent poll failure)** or an unbounded
  historical pull. Fix: return a bounded `now-24h` ISO8601 default when state is empty (TDD: one helper + a test).
- **Pros:** removes a latent foot-gun; cheap, well-contained, TDD-able; **matters most once the poller is Active** (a silent 400-loop
  with nobody watching = no triage, no alarm).
- **Cons:** low probability today (state lives on a persistent volume + the seed is in place); needs another **code deploy** (rebuild +
  recreate, re-bakes the embedding model ~few min, needs USER approval).
- **Recommendation:** do it **together with activating the poller** (one deploy + activate). Lower priority if staying manual/on-demand.

---

## Remaining work / Phase-0-close checklist
- [x] **Q1 activate poller — DONE** (ACTIVE) · [x] **#10 bounded-watermark — DONE** (shipped+deployed) · [x] **Q2 synthetic Contain-recommended demo — DONE** (run 282 / Iris #250, §6). **Q3 watchdog still deferred.**
- [ ] (optional, cosmetic) Clean GREEN `falcon-contain` run — `wait_lift`=120 (committed JSON has it).
- [ ] **Organic** alert→Contain demo — still open; the now-active poller is the capture net (Q2 option a).
- [ ] **Deallocate the SOC VMs** when done (cost). State + judge survive on volumes; everything auto-resumes on next start.
- [ ] Push `ai-upgrade` to the `honeypot` remote if/when you want it off-box (currently local-only).
