# Phase 4 - Splunk investigation agent: the single paid live run (Task 17)

**Status:** ready to run. **Date:** 2026-07-12. **Driver:** USER, hands-on. **Cost:** ~one bounded Opus loop
(<= 8 model turns / <= 4 Splunk queries) for the one alert, plus the paid triage node. Everything else in this runbook
is $0.

This is the hands-on runbook for **Task 17**, the last piece of Phase 4: the single paid live run of the Splunk
investigation agent against real honeypot data, plus the ablation measurement and the portfolio evidence. Task 16
(read-only role + live capture) is done, and the deploy-wiring prerequisite is fixed in code. This runbook is the
**publish step**, so its commits are USER-directed and it ends by pushing.

You (the USER) run every paid, live, Splunk, and hands-on step. The internet-exposed honeypot host `vm-honeypot-win`
stays **LOCKED** the entire time - nothing here logs into it or changes it. We only touch the automation box
(`vm-soc-v2-n8n`, `10.0.0.6`) and read from the SIEM (`vm-soc-v2-splunk`, `10.0.0.5`).

> **Read this before you start - what the live data can and cannot show.** `index=honeypot` is brute-force only (4625
> failed logons, no successful auth, no Sysmon, no post-exploit telemetry). Two consequences are baked into the code
> and you should expect them, not fight them:
> - **The live severity ablation will almost certainly be NOT MET.** `severity_supported` passes on the T1110
>   credential-access hot tactic ALONE (with or without scope), and grounded HIGH needs a successful auth
>   (`success_count > 0`) that brute-force data never produces. So removing `scope_evidence` will NOT flip
>   `severity_supported` on real honeypot data. That is correct behavior, documented, and the honest NOT-MET fallback
>   (Part 6) covers it.
> - **The grounding demonstration therefore comes from TWO places:** (a) an **offline synthetic fixture** (Part 3, $0)
>   that proves the grounding flip deterministically, and (b) the **live run** (Part 4), whose real value is proving
>   the deployed agent actually investigates real alerts and produces a real, honest scope narrative (brute-force
>   breadth), with the `scope_findings_grounded` channel as the only live ablation lever - and only if the live model
>   populates `scope_findings`. Never dress up self-authored or synthetic data as a real attacker incident, and never
>   write synthetic events into live Splunk.

> **Correction to the plan's wording (deliverable #2).** The plan says the delta is "attributable via
> `scope_severity_supported`". There is **no check named `scope_severity_supported`**. The real runs.jsonl check
> names are `severity_supported`, `scope_findings_grounded`, and `scope_notes_honesty`. On honeypot data the only one
> that can move under the ablation is **`scope_findings_grounded`**. This runbook uses the real names.

> **Secrets discipline (do not skip):** every credential lives in the gitignored `SOC-Automation-Project.md` at the
> repo root. Never type a password inline into a command that lands in shell history - fill secrets by editing a
> `chmod 600` `.env` in an editor instead (the tee-blank-keys -> `nano` -> `chmod 600` flow in steps 1.2 and 2.5).
> Never paste a secret into this committed doc. Public IPs are placeholders (`<n8n-public-ip>`, `<splunk-public-ip>`);
> substitute your home-restricted IPs at run time and do not write them back. In any evidence you keep, the raw
> `/investigate` output and `runs.jsonl` lines carry the **real attacker `src_ip`** - those stay in the gitignored
> `splunk-investigator/reports/` and only a **scrubbed** vault page (Part 5) ever leaves the repo.

---

## Deliverable map (plan Task 17 -> this runbook)

| Plan deliverable | Where |
|---|---|
| 1. Deploy updated grounding-service + import JSON; `/investigate` reachable, `/health` green | Part 1, Part 2 |
| 2. Ablation: triage with vs without the scope bundle, attribute the delta | Part 3 (offline, reliable) + Part 4 (live) |
| 3. Capture the agentic transcript; run it through the two-layer scrub gate | Part 4 (capture) + Part 5.1 (scrub) |
| 4. Scrubbed vault page separating grounded claims from advisory narrative | Part 5.2 |
| 5. Honest NOT-MET fallback | Part 6 |
| Runbook + evidence doc + vault page + scrub gate; USER-directed commits | Part 0 (push) + Part 7 |

---

## Part 0 - Pre-flight: push the code, then bring the boxes up

The deployed container runs whatever is on `origin`, so the local Session-32/34/35 commits must be pushed **before**
you rebuild on the box. Pushing is gated on the two-layer scrub gate and your approval.

### 0.1 Confirm the local commits that need to ship

**Where:** your local machine, repo root `f:\Claude_Code\Skills-Learning\SOC-Automation-Honeypot-Project`.

```bash
git -C "f:/Claude_Code/Skills-Learning/SOC-Automation-Honeypot-Project" log --oneline origin/ai-upgrade..HEAD
git -C "f:/Claude_Code/Skills-Learning/SOC-Automation-Honeypot-Project" status --short
```

**Expected:** the ahead-of-origin commits (Task-16 runbook + deploy-wiring fix, plus the Session-35 commits once you
make them - the transcript patch, the rows-free transcript fix, the scope-grounding demo, the `reports/` gitignore,
and this runbook). `status` should also show pre-existing uncommitted changes you are **not** shipping in this code
push: the untracked `session-logs/` files, and the already-modified (tracked) `vault/index.md` - that one is left for
the Part 5/7 vault publish, not this push.

> The Session-35 code changes are **USER-directed commits**: `grounding-service/grounding_service/app.py` (surface +
> row-free transcript), `grounding-service/tests/test_investigate.py`, `grounding-service/grounding_service/scope_grounding_demo.py`
> + `grounding-service/tests/test_scope_grounding_demo.py`, `splunk-investigator/splunk_investigator/agent.py`
> (`_summarize_no_rows`) + `splunk-investigator/tests/test_agent.py`, `splunk-investigator/.gitignore` (`reports/`
> rule), and this runbook. Stage them with **exact-path** `git add` (never `git add -A`), and use the trailer
> `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Do NOT commit `session-logs/`, `.superpowers/`,
> or `vault/index.md` in this code push (the vault files land later, in Part 7).

### 0.2 Two-layer scrub gate (MUST pass before push)

**Where:** your local machine, repo root. Run both scanners over the working tree + the diff you are about to push.

```bash
gitleaks detect --source . --no-banner
gitleaks protect --staged --no-banner      # after you stage, before you commit
trufflehog git file://. --since-commit origin/ai-upgrade --only-verified --fail
```

**Expected:** gitleaks `0 leaks`, trufflehog `0 verified` (0/0). Then the third layer - the **semantic-audit
Workflow** - is run by Claude (a 5-lens pass looking for home IPs, reused passwords, Azure/CrowdStrike IDs, and any
live-looking value the regex scanners miss). Do not push until all three are clean and you have approved.

### 0.3 Push

**Where:** your local machine. Only after 0.2 is clean and you say go.

```bash
git -C "f:/Claude_Code/Skills-Learning/SOC-Automation-Honeypot-Project" push origin ai-upgrade
```

**Verify:** `git rev-parse --short origin/ai-upgrade` now equals your local `HEAD`, and
`git rev-list --count origin/ai-upgrade..HEAD` is `0`.

### 0.4 Start the VMs

**Where:** your local machine (Azure CLI or portal).

```powershell
az vm start --resource-group rg-soc-v2-azure-central-us --name vm-soc-v2-splunk
az vm start --resource-group rg-soc-v2-azure-central-us --name vm-soc-v2-n8n
az vm list --resource-group rg-soc-v2-azure-central-us --show-details --query "[].{name:name, power:powerState}" -o table
```

**Verify:** both show `PowerState/running`.

### 0.5 Telemetry health check

**Where:** Splunk Web (`http://<splunk-public-ip>:8000`, log in as `mydfir`) > Search & Reporting, time picker **Last
60 minutes**.

```spl
index=honeypot | stats count by source sourcetype
```

**Verify:** non-zero rows including `WinEventLog` (classic 4625). If empty, the honeypot forwarder is down - fix that
first, or every capture below returns nothing and looks like a code bug when it isn't.

---

## Part 1 - Deploy the updated grounding-service  (deliverable #1)

**Where:** SSH to the automation box from your local machine.

```bash
ssh -i C:/Users/Owner/.ssh/vm-soc-v2-linux-key.pem azureuser@<n8n-public-ip>
```

### 1.1 Pull the pushed code onto the box

```bash
cd /root/soc-src
sudo git fetch origin
sudo git checkout ai-upgrade
sudo git pull --ff-only origin ai-upgrade
git log --oneline -1
```

**Verify:** `git log --oneline -1` shows the same HEAD short-hash you pushed in 0.3. If `pull` reports anything other
than a fast-forward, stop and reconcile - a divergent box checkout means the rebuild ships the wrong code.

### 1.2 Put ONLY the Anthropic key in the compose-dir `.env` (Splunk password comes later, in 2.5)

**Where:** same SSH session. The `.env` MUST sit next to the compose file (`/root/soc-src/grounding-service/.env`) -
compose loads interpolation vars from the compose file's directory, not the repo root.

> **Why the Splunk password is deferred:** with `SPLUNK_PASSWORD` empty, `main.py` leaves the Splunk factory unwired,
> so `/investigate` returns `splunk_not_configured` ($0) - which lets Part 2's public-IP wiring check stay genuinely
> free. If both secrets were present now, that same check would fire a **paid** Opus loop (see 2.4). So we wire Claude
> first, prove everything at $0, then add the Splunk password as the final step (2.5) right before the one paid run.

Fill the file by editing it (never on a command line, so no secret lands in shell history), leaving `SPLUNK_PASSWORD`
blank for now:

```bash
sudo tee /root/soc-src/grounding-service/.env >/dev/null <<'EOF'
ANTHROPIC_API_KEY=
SPLUNK_PASSWORD=
EOF
sudo nano /root/soc-src/grounding-service/.env    # paste ONLY the ANTHROPIC_API_KEY value; leave SPLUNK_PASSWORD= blank
sudo chmod 600 /root/soc-src/grounding-service/.env
```

- `ANTHROPIC_API_KEY` = the `sk-ant-Lds...` key (NOT the revoked `7MV` key), from `SOC-Automation-Project.md`.
- `SPLUNK_PASSWORD` = leave blank until 2.5.

**Verify (no secret echoed):**

```bash
sudo grep -c '^ANTHROPIC_API_KEY=sk-ant-' /root/soc-src/grounding-service/.env   # expect 1
sudo grep -c '^SPLUNK_PASSWORD=..*'        /root/soc-src/grounding-service/.env   # expect 0 (still blank)
```

Expect `1` then `0` (Anthropic key set, Splunk password still blank).

### 1.3 Confirm the external docker network exists

```bash
docker network inspect soar-net >/dev/null 2>&1 && echo "soar-net exists" || echo "MISSING"
```

**Verify:** `soar-net exists`. If `MISSING`, create it once with `docker network create soar-net` (the compose file
declares it `external: true` and errors otherwise).

### 1.4 Rebuild + recreate (the `--build` is load-bearing)

The Dockerfile now pip-installs `splunk-investigator` + `malware-triage`; a plain `--force-recreate` reruns the stale
image where `/investigate` ImportErrors to a silent-empty result. You MUST `--build`.

```bash
cd /root/soc-src
docker compose -f grounding-service/docker-compose.yml up -d --build --force-recreate
```

**Verify:** `docker compose -f grounding-service/docker-compose.yml ps` shows `grounding-service` (and `qdrant`) `Up`.

---

## Part 2 - Prove `/investigate` is wired, at $0  (Splunk password still blank)

Every check in this part is genuinely **$0** - it runs with `SPLUNK_PASSWORD` still blank, so `/investigate` can never
reach the paid Opus loop (it stops at the `splunk_not_configured` gate). The one paid loop is deliberately saved for
the Part 4 pipeline run. Run these in ascending order; each rejects a specific silent-inert failure mode. You add the
Splunk password in 2.5, AFTER these all pass.

**Where:** the SSH session on the n8n box (the service listens on the docker network, so reach it via `docker exec`).

### 2.1 Health

```bash
docker exec grounding-service curl -s http://localhost:8000/health
```

**Expected:** `{"status":"ok"}` (the code returns `"ok"`, not the literal word "green").

### 2.2 Engines actually installed (rejects the `flags:[]` silent-inert bug)

```bash
docker exec grounding-service python -c "import splunk_investigator, malware_triage, splunklib; print('ok')"
```

**Expected:** `ok`. An ImportError here means the `--build` didn't take - the exact Session-34 bug.

### 2.3 Endpoint + pregate live, private IP -> `no_pivot` ($0)

```bash
docker exec grounding-service curl -s -X POST http://localhost:8000/investigate \
  -H 'Content-Type: application/json' \
  -d '{"alert":{"src_ip":"10.0.0.99","host":"","user":"","event_time":"","alert_text":"wiring check"}}'
```

**Expected exactly:**
`{"investigated":false,"scope_evidence":{"claims":[],"queries_run":[]},"transcript":[],"flags":["no_pivot"],"advisory_reasoning":""}`

Note `"transcript":[]` is present (the Session-35 patch). `flags:["no_pivot"]` proves the pregate ran. An empty
`flags:[]` here would mean the engine isn't installed (go back to 2.2).

### 2.4 Claude factory + pregate reach the Splunk gate, public IP -> `splunk_not_configured` ($0)

With `SPLUNK_PASSWORD` still blank, a public-IP POST proves the Claude factory is wired AND the pregate admits a public
IP AND the code reaches the Splunk gate - all at $0, because it stops at `splunk_not_configured` before any paid call.

Use a **genuinely routable** IP. Do NOT use `203.0.113.x` / TEST-NET here: on Python 3.12 those classify as private
and misleadingly return `no_pivot`, masking the check.

```bash
docker exec grounding-service curl -s -X POST http://localhost:8000/investigate \
  -H 'Content-Type: application/json' \
  -d '{"alert":{"src_ip":"8.8.8.8","host":"","user":"","event_time":"1782768779","alert_text":"wiring check"}}'
```

**Expected exactly:** `flags:["splunk_not_configured"]`, `investigated:false`. That is the target result - it confirms
everything up to the Splunk leg is wired.

Other outcomes and what each means:

| Response `flags` | Meaning | What to do |
|---|---|---|
| `["splunk_not_configured"]` | **target** - Claude wired, Splunk password (correctly) still blank | proceed to 2.5 |
| `["claude_not_configured"]` | `ANTHROPIC_API_KEY` missing/mis-set in `.env` (checked first) | fix 1.2, redeploy |
| `[]` (empty) | engine not installed (2.2 failed) | fix the `--build` (1.4) |
| `["no_pivot"]` | you used a private/TEST-NET IP - use `8.8.8.8` | re-run with a routable IP |

> **There is no free positive `investigated:true` proof, by design.** The only way to get `investigated:true` is a
> public IP with BOTH secrets wired, and that spends a paid Opus loop. So we don't chase it here. The Splunk leg itself
> was already proven at $0 in Task 16 (the read-only `oneshot` over `10.0.0.5:8089`), so `splunk_not_configured` here +
> that Task-16 proof = the whole wiring is confirmed without paying. The first (and only) `investigated:true` is the
> Part 4 run.

**Record** the 2.1-2.4 outcomes in Results.

### 2.5 Add the Splunk password (the final wiring step, still $0)

Now, and only now, add the Splunk password and reload the container's env. This does NOT spend anything by itself - it
just wires the Splunk factory so the Part 4 pipeline run can investigate.

**Where:** the SSH session on the n8n box.

```bash
sudo nano /root/soc-src/grounding-service/.env    # fill SPLUNK_PASSWORD= (phase4_investigator pw from SOC-Automation-Project.md)
sudo grep -c '^SPLUNK_PASSWORD=..*' /root/soc-src/grounding-service/.env   # expect 1 now
cd /root/soc-src
docker compose -f grounding-service/docker-compose.yml up -d --force-recreate    # env reload (no --build needed)
```

**Verify (stays $0 - do NOT re-run the public-IP curl now; with both secrets set it would fire a paid loop):**
re-run only the free checks 2.1 (`/health`) and 2.3 (private-IP -> `no_pivot`). Both must still pass. The box is now
fully wired; the next `/investigate` that reaches a public IP (the Part 4 run) is the one paid loop.

### 2.6 Confirm the workflow JSON is current in n8n

**Where:** n8n editor (`http://<n8n-public-ip>:5678`) > `honeypot-triage`.

The regenerated `JSON/honeypot-triage.json` (Session 34: verbatim `scope_findings` prompt) must be the one loaded. If
you haven't re-imported since Session 34, import `JSON/honeypot-triage.json` now (n8n > workflow > ... menu > Import
from File). Confirm the graph has the **investigate** node between **Parse Alert** and **Build Opus Input**.

**Verify:** the workflow is **INACTIVE** (toggle off, top of the editor). It stays inactive for the whole run - see the
cost guardrail in Part 4.

---

## Part 3 - The offline grounding demo  (deliverable #2, reliable half, $0)

Before spending anything, run the deterministic proof of the grounding flip. This is the same `/verify` adapter the
live pipeline uses, on two labeled-synthetic fixtures, and it is regression-locked by a test - so it can never
silently start lying.

**Where:** your local machine, repo root (or the n8n box - either has the code).

```bash
cd "f:/Claude_Code/Skills-Learning/SOC-Automation-Honeypot-Project/grounding-service"
../malware-triage/.venv/Scripts/python -m grounding_service.scope_grounding_demo > ../splunk-investigator/reports/scope-grounding-demo.md
../malware-triage/.venv/Scripts/python -m pytest tests/test_scope_grounding_demo.py -q
```

**Verify:** the pytest line is `5 passed`, and `reports/scope-grounding-demo.md` shows, for BOTH scenarios,
`scope_findings_grounded` / `severity_supported` flipping **PASSED -> FAILED** and `verification_passed`
**True -> False** when `scope_evidence` is removed. This artifact is synthetic (RFC 5737 TEST-NET-3 IP, fixture
successful-auth), so it is safe to keep and to reference from the vault page as the deterministic grounding proof.

> Why this exists: on brute-force honeypot data the LIVE severity ablation can't move (Part 4), so this offline demo
> is what actually proves the grounding logic. The live run then proves the deployed agent investigates real alerts.
> Together: "the mechanism works (here's the proof), and it's really deployed (here's the live run)."

---

## Part 4 - The single paid live run + capture + live ablation  (deliverables #2, #3)

> **COST GUARDRAIL (hard rule).** `/investigate` has **no endpoint-level dedup or budget** (the daily-budget / dedup
> knobs are not wired at the endpoint). An ACTIVE workflow would pay one Opus investigation loop **per public-IP
> alert** every 15 minutes. So: keep the workflow **INACTIVE**, and trigger **exactly ONE** full execution using the
> test-event method below. Per-alert cost is bounded by `MAX_TURNS=8` / `MAX_QUERIES=4`, but cross-alert cost is not -
> the only thing stopping a runaway bill is you firing exactly one alert. There is no in-band token readout; check the
> Anthropic console afterward for the actual spend.

### 4.1 Arm exactly one full execution

**Where:** n8n editor > `honeypot-triage`, workflow INACTIVE, **full graph connected** (do NOT disconnect the Webhook
wire - unlike Task 16's capture, here we WANT the whole paid path to run once).

1. Click the **Webhook** node > **Listen for test event**. n8n now listens once at
   `http://10.0.0.6:5678/webhook-test/honeypot-triage` and will run the full graph for the next POST it receives, then
   stop listening.

### 4.2 Fire one real alert from Splunk

**Where:** Splunk Web, logged in as `mydfir` (ad-hoc `sendalert` needs the admin session). Time picker **Last 24
hours**. This is the live saved-search SPL, pointed at the **test** URL, capped to one row:

```spl
index=honeypot EventCode=4625
| eval src_ip=coalesce(src_ip, Source_Network_Address)
| where isnotnull(src_ip) AND src_ip!="-"
        AND NOT (cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("172.16.0.0/12",src_ip)
                 OR cidrmatch("192.168.0.0/16",src_ip) OR cidrmatch("127.0.0.0/8",src_ip))
| stats count, values(user) as user, values(ComputerName) as ComputerName,
        earliest(_time) as earliest, latest(_time) as latest by src_ip
| where count >= 1
| sort -count
| eval ComputerName=mvindex(ComputerName,0), user=mvindex(user,0)
| head 1
| sendalert webhook param.url="http://10.0.0.6:5678/webhook-test/honeypot-triage"
```

**Verify:** the search returns 1 row and the `sendalert` completes. In n8n, exactly ONE execution appears and it runs
the FULL graph (Webhook -> Parse Alert -> retrieve -> investigate -> Build Opus Input -> Opus triage -> verify ->
Discord/IRIS). Because the workflow is inactive and you only fired once, this is your one paid run. Do **not** click
"Listen for test event" again.

> If the search returns 0 rows (quiet window), widen the time picker or lower nothing else - the honeypot is
> brute-forced constantly, so a 24h window almost always has a public attacker IP. Confirm the fired row's `earliest`
> is epoch-seconds (Task 16 confirmed this; `event_time` must be a usable anchor or the time-bounded queries render
> to no-claim).

### 4.3 Capture the agentic transcript + the scope evidence (deliverable #3)

**Where:** n8n editor > `honeypot-triage` > **Executions** > open the execution from 4.2.

1. Click the **investigate** node > **output**. Copy the full JSON response. It now includes (Session-35 patch):
   `investigated`, `scope_evidence.claims`, `scope_evidence.queries_run`, **`transcript`** (the turn-by-turn decision
   trace: which entity-bound query per turn, params, summarized result, and the concluding turn), `flags`,
   `advisory_reasoning`.
2. Click the node that POSTs to **/verify** (the HTTP Request node after the format node) > **input**. Copy the full
   `verify_body` JSON: `{result, retrieved, enrichment_results, scope_evidence, run_meta}`. Note its `run_meta.run_id`
   - that's the WITH-scope runs.jsonl line.
3. Save both to the gitignored `reports/` dir on your local machine (they carry the real attacker IP):

**Where:** your local machine.

```bash
cd "f:/Claude_Code/Skills-Learning/SOC-Automation-Honeypot-Project/splunk-investigator/reports"
# paste the investigate-node output into this file:
nano t17-investigate-raw.json
# paste the verify_body (from the /verify node input) into this file:
nano t17-verify-body.json
```

**Verify:** `reports/` already ignores these (`git check-ignore splunk-investigator/reports/t17-investigate-raw.json`
prints the path). `t17-investigate-raw.json` has a non-empty `transcript` array and a `queries_run` list in entity-
bound order. This is the portfolio transcript.

### 4.4 The live ablation: re-verify WITHOUT the scope bundle

The pipeline's own `/verify` call (4.3 step 2) is the **WITH-scope** line. Now produce the **WITHOUT-scope** line by
re-POSTing the SAME `verify_body` with `scope_evidence` nulled and a new `run_id`. This is a $0 verifier call (no
model).

**Where:** the n8n box (the service is on the docker network).

```bash
# On the n8n box, from a copy of t17-verify-body.json placed there (scp it or paste with nano):
#   produce the without-scope variant: scope_evidence -> null, run_id -> "<orig>-without"
python3 - <<'PY' < t17-verify-body.json > t17-verify-body-without.json
import sys, json
b = json.load(sys.stdin)
b["scope_evidence"] = None
b["run_meta"] = dict(b.get("run_meta", {}))
b["run_meta"]["run_id"] = (b["run_meta"].get("run_id", "t17") + "-without")
json.dump(b, sys.stdout)
PY

cat t17-verify-body-without.json | docker exec -i grounding-service \
  curl -s -X POST http://localhost:8000/verify -H 'Content-Type: application/json' -d @-
```

**Verify:** the response is a runs.jsonl record (has `check_results`). Now pull the last two lines (WITH then WITHOUT)
and print each line's `run_id` next to the three scope-check statuses:

```bash
docker exec grounding-service sh -c 'tail -2 /data/runs.jsonl' | python3 - <<'PY'
import sys, json
SCOPE = ("severity_supported", "scope_findings_grounded", "scope_notes_honesty")
for line in sys.stdin:
    r = json.loads(line)
    checks = {c["name"]: c["status"] for c in r["check_results"] if c["name"] in SCOPE}
    print(r["run_id"], checks)
PY
```

**Interpret (record the actual outcome honestly):**
- If the live model populated `scope_findings` (verbatim copy of a claim): the WITH line shows
  `scope_findings_grounded: passed`, the WITHOUT line shows `scope_findings_grounded: failed` (fail-closed). **That
  flip is the live grounding demonstration** - attribute it to the specific claim in `scope_evidence` the model
  copied.
- If `scope_findings` came back empty: `scope_findings_grounded` is `passed` on both lines (vacuous), no delta. That
  is the **expected** case if the T13-1 prompt tune hasn't fully landed on the live model. Record it plainly - the
  offline demo (Part 3) carries the grounding proof, and this is a Part 6 NOT-MET note, not a failure to hide.
- `severity_supported` will read `passed` on BOTH lines on honeypot data (T1110 hot tactic). Do not report a severity
  delta that isn't there.

### 4.5 Copy out the WITH-scope runs.jsonl line

```bash
docker exec grounding-service sh -c 'tail -2 /data/runs.jsonl' > /tmp/t17-runs.jsonl
# scp /tmp/t17-runs.jsonl to your local reports/ dir, or read it inline
```

Keep the two runs.jsonl lines with the raw capture in `reports/`. Note the named volume `grounding_runs` persists
prior lines, so isolate yours by `run_id`.

---

## Part 5 - Scrub gate, then the vault page  (deliverables #3, #4)

### 5.1 Two-layer scrub gate on the raw evidence

The raw `reports/` files carry the real attacker IP and live results. They stay gitignored forever. Before you write
anything into the **committed** vault page, scrub-gate the *content you plan to publish*:

**Where:** your local machine, repo root.

```bash
gitleaks detect --source . --no-banner
trufflehog filesystem splunk-investigator/reports/ --only-verified --fail
```

**Expected:** 0 / 0. Then Claude runs the **semantic-audit Workflow** (5-lens) over the drafted vault page text to
catch a real IP / host / home-IP / credential the regex scanners miss. Only publish text that clears all three.

### 5.2 Write the scrubbed vault page (deliverable #4)

**Where:** new subproject folder (Phase 4 is an agent sub-project, not a single detection rule):
`vault/subprojects/2026-07-12-splunk-investigation-agent/`.

Create `README.md` there with these sections (mirror `report.py`'s GROUNDED vs ADVISORY split):

1. **What it is** - a bounded, entity-scoped Splunk investigation agent that grounds triage severity in real query
   results, out of model control.
2. **Grounded scope claims** (from `scope_evidence`, the out-of-model ground truth) - render the real run's
   `distinct_targets` / `repeat_offender` / `auth_outcome` claims. With `success_count = 0` (brute-force), present
   `distinct_targets` / `repeat_offender` as **brute-force breadth**: "N distinct accounts attempted from this source
   over M days," NOT as a compromise.
3. **Advisory transcript** (clearly separated, model narrative) - the entity-bound query order + the conclusion, in a
   dynamically-sized fence, labeled advisory (not ground truth).
4. **The grounding mechanism** - link/embed the offline demo result (`scope-grounding-demo.md`) as the deterministic
   proof that removing `scope_evidence` fails the report closed.
5. **All attacker IPs redacted** to `x.x.x.x`; no host names beyond `vm-honeypot-win`.

Then add the standard cross-links: a dated line in `vault/log.md` and an entry in `vault/index.md` (which is currently
stale - fix the entry while you're there).

**Verify:** the page renders grounded vs advisory as two visually distinct sections, every attacker IP is `x.x.x.x`,
and the scrub gate (5.1) passed on the final text.

---

## Part 6 - Honest NOT-MET fallback  (deliverable #5)

Fill in whichever is true. On the expected brute-force-only outcome, state it plainly:

- **Live "real incident changed scope/severity" criterion: NOT MET.** `index=honeypot` is brute-force only; there is
  no post-exploitation telemetry (no successful auth, no Sysmon, no encoded PowerShell), because the honeypot host is
  locked and the companion honeypot-opening spec has not landed (its Falcon safety gate is being reassessed). So no
  real incident escalated severity via grounded scope.
- **What the live run DID demonstrate (met):** the deployed agent reachably investigates real alerts, runs
  entity-bound queries in a bounded loop, and produces an honest brute-force-breadth scope narrative with grounded
  `distinct_targets` / `repeat_offender` claims.
- **The grounding logic is demonstrated by the offline synthetic fixture (Part 3)**, labeled synthetic, matching the
  Phase-2 ("informative outcome, not a failure") and Phase-3 ("synthetic by necessity, accepted fallback") precedents.
- **No synthetic events were written to live Splunk**, and no self-authored / synthetic data is presented as a real
  attacker incident.

---

## Part 7 - Publish  (USER-directed commits)

Follow `finishing-a-development-branch`. The vault page + any evidence-summary doc are the committed artifacts; the raw
`reports/` files are NOT (gitignored). Commits are USER-directed: stage with **exact-path** `git add`, use the
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer, keep `session-logs/` and
`.superpowers/` uncommitted, no em dashes. Push only after your final scrub-gate pass and your go-ahead.

---

## Results (fill this in as you go - this is the Task-17 artifact)

### Part 0 - push + boxes
- [ ] Session-35 commits made (exact-path add, trailer): _____
- [ ] Two-layer scrub gate clean (gitleaks 0 / trufflehog 0 / semantic Workflow 0): _____
- [ ] Pushed; `origin/ai-upgrade` == local HEAD: _____
- [ ] Both VMs running; honeypot telemetry healthy: _____

### Part 1-2 - deploy + liveness
- [ ] Box pulled to HEAD `______`; `.env` has Anthropic key only at 1.2 (grep 1/0); `soar-net` exists.
- [ ] `up -d --build --force-recreate` OK; `grounding-service` Up.
- [ ] 2.1 `/health` = `{"status":"ok"}`: _____
- [ ] 2.2 `import splunk_investigator, malware_triage, splunklib` = ok: _____
- [ ] 2.3 private-IP -> `no_pivot`, `transcript:[]` present: _____
- [ ] 2.4 public-IP `8.8.8.8` -> flags `["splunk_not_configured"]` (the $0 target): _____
- [ ] 2.5 Splunk password added (grep count 1); env-reload recreate OK; 2.1 + 2.3 still green: _____
- [ ] 2.6 workflow JSON current (investigate node present), workflow INACTIVE.

### Part 3 - offline grounding demo ($0)
- [ ] `test_scope_grounding_demo.py` = 5 passed.
- [ ] `scope-grounding-demo.md` shows both channels flip PASSED->FAILED, verification True->False.

### Part 4 - the one paid run  (redact src_ip)
- One alert fired via Listen-for-test-event, workflow INACTIVE: _____
- `investigate` node `investigated`: _____ ; `flags`: _____
- Grounded claims returned (`auth_outcome` success/fail counts, `distinct_targets`, `repeat_offender`): _____
- Transcript captured (turn count, query order, conclusion): _____
- Live ablation `scope_findings_grounded` WITH vs WITHOUT: _____ / _____  (delta? attribute to claim: _____)
- `severity_supported` WITH vs WITHOUT (expect passed/passed on honeypot): _____ / _____
- Anthropic console spend for the run: _____

### Part 5 - scrub + vault
- [ ] Scrub gate on published text clean (0/0 + semantic Workflow): _____
- [ ] Vault page `vault/subprojects/2026-07-12-splunk-investigation-agent/README.md` written; grounded vs advisory
      visually separated; IPs redacted.
- [ ] `vault/log.md` + `vault/index.md` updated.

### Part 6 - honest outcome
- Live "real incident changed scope/severity": **NOT MET / MET** (circle) - reason: _____
- Grounding demonstrated via: offline synthetic fixture (Part 3) / live `scope_findings_grounded` flip (circle).
- No synthetic events written to live Splunk: _____

### Sign-off
- Task 17 complete, Phase 4 done: _____ (date)
