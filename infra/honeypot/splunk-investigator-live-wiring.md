# Phase 4 - Splunk investigation agent: live-wiring runbook (Task 16)

**Status:** ready to run. **Date:** 2026-07-12. **Driver:** USER, hands-on. **Cost:** $0 (no paid model call in this task).

This is the hands-on runbook for **Task 16** of the Phase-4 Splunk investigation agent. Phase 4 is offline-complete
and published (public tip `71f85ff`); the four live-wiring blockers LB-1..LB-4 are already fixed in code. Task 16 is
the **confirm + capture + provision** step that has to happen on the live boxes before the single paid live run
(Task 17). Everything here is either read-only or a one-time read-only-role creation. Nothing here spends Claude
tokens and nothing here touches the internet-exposed honeypot host (`vm-honeypot-win` stays LOCKED). We only touch
the SIEM (`vm-soc-v2-splunk`) and the automation box (`vm-soc-v2-n8n`).

## What Task 16 has to produce

1. A **read-only Splunk role** `phase4_investigator` scoped to `index=honeypot` ONLY, plus a dedicated user, plus a
   3-part acceptance test that proves it can't write and can't read the self-authored `mydfir-project` index.
2. A **captured real webhook payload** confirming the `result` row shape, and specifically that `earliest`/`latest`
   arrive as **epoch seconds** (the LB-1 fix assumes this). This is the one genuinely-unverified assumption.
3. The **search-head timezone**, recorded for the evidence trail.
4. A **schema capture** of the 5 catalog queries (read-only `oneshot` per query) diffed against the hand-authored
   reference envelopes in `splunk-investigator/fixtures/envelopes/`, so we know the live field names + string typing
   match what the parser expects.
5. (Optional) The exact Splunk **truncation `messages` text** on a capped search, to validate the capped-incomplete
   detector.
6. The **grounding-service deploy env** notes for Task 17.

At the end you fill in the **Results** section at the bottom. That filled-in doc is the Task-16 artifact.

> **Secrets discipline (do not skip):** every credential in this runbook lives in the gitignored
> `SOC-Automation-Project.md` at the repo root. Never type a password inline into a command that lands in shell
> history, and never paste a value into this committed doc. Use the `read -s` pattern shown below so the password
> never hits history. Public IPs are shown as placeholders (`<splunk-public-ip>`, `<n8n-public-ip>`) - substitute
> your real home-restricted IPs at run time and do not write them back into this committed doc. When you record a
> captured payload in the Results section, **redact the real attacker `src_ip`** to `x.x.x.x` and keep only field
> names + formats.

---

## Part 0 - Pre-flight

### 0.1 Start the VMs

**Where:** your local machine (PowerShell with the Azure CLI, or the Azure portal).

`vm-soc-v2-splunk` auto-shuts-down at 11 PM Eastern, so it is probably stopped. Start both the SIEM and the
automation box:

```powershell
az vm start --resource-group rg-soc-v2-azure-central-us --name vm-soc-v2-splunk
az vm start --resource-group rg-soc-v2-azure-central-us --name vm-soc-v2-n8n
```

**Verify (expected output):** each command returns to the prompt with no error. Confirm both are running:

```powershell
az vm list --resource-group rg-soc-v2-azure-central-us --show-details --query "[].{name:name, power:powerState}" -o table
```

Expect `PowerState/running` for both `vm-soc-v2-splunk` and `vm-soc-v2-n8n`. (Portal path if you prefer clicking:
Resource groups > `rg-soc-v2-azure-central-us` > select the VM > Start > wait for status **Running**.)

### 0.2 Reach the consoles

**Where:** your local machine, browser.

- Splunk Web: `http://<splunk-public-ip>:8000` (the Splunk VM's public IP; the NSG only lets your home IP in on
  `:8000`). Log in as the admin user `mydfir` (password in `SOC-Automation-Project.md`).
- n8n editor: `http://<n8n-public-ip>:5678` (the same URL you normally open n8n on). You will need this in Part 2.

> `<splunk-public-ip>` and `<n8n-public-ip>` are **two different Azure public IPs on two different VMs** - don't
> reuse one for the other. Both are in `SOC-Automation-Project.md`.

**Verify:** Splunk Web loads and you can see the search app. n8n editor loads and you can see the
`honeypot-triage` workflow in the workflow list.

### 0.3 Telemetry health check

**Where:** Splunk Web > Search & Reporting.

Confirm the honeypot is actually shipping logs before you rely on live data. Set the time picker to **Last 60
minutes** and run:

```spl
index=honeypot | stats count by source sourcetype
```

**Verify (expected output):** non-zero `count` rows, including `WinEventLog` (the classic-text 4625 source; NOT
`XmlWinEventLog`). If this is empty, the honeypot forwarder or the box is down; fix that before continuing (a dead
pipeline here would make every later capture return nothing and look like a code bug when it isn't).

---

## Part 1 - Read-only Splunk role `phase4_investigator`  (STATE-CHANGING)

This is the one step that changes Splunk config. It gives the investigation agent a least-privilege identity: it can
`search index=honeypot` and nothing else. `mydfir-project` (your self-authored ART / T1059.001 lab data) is
deliberately excluded so the agent can never dress up self-authored data as a real attacker incident.

### 1.1 Create the role

**Where:** Splunk Web, logged in as `mydfir`. Settings > Users and authentication > **Roles** > **New Role**
(on some 10.x builds this is Settings > Access controls > Roles).

> **Why from scratch (do NOT inherit `user`):** Splunk role inheritance is strictly additive - you cannot turn OFF a
> capability or shrink an index allowlist that comes in from an imported role. The default `user` role already grants
> `output_file` (write) and `srchIndexesAllowed = *` (all non-internal indexes). If you inherit `user`, the role would
> silently keep the ability to `| outputlookup` and to read `index=mydfir-project`, and the acceptance test in 1.3
> would fail even though the UI looks locked down. So we build this role with NO inheritance and grant exactly one
> capability.

- **Name:** `phase4_investigator`
- **Inherit from:** **nothing.** Do NOT import `user`, `power`, or `admin`. Leave the inherited-roles selection empty.
- **Capabilities tab:** grant exactly **one** capability: **`search`**. That is all the agent needs to POST a search
  job to the management API and all you need to run the acceptance searches. Leave every other capability unchecked.
  With nothing inherited there is nothing to turn off - the role simply has none of the write/response caps
  (`output_file` behind `| outputlookup`, `run_collect` behind `| collect`, `schedule_search`,
  `rest_access_server_endpoints` behind `| rest`, any `edit_*`/`delete_*`).
- **Indexes tab:**
  - `srchIndexesAllowed` (Indexes this role can search): **`honeypot` ONLY**. Do NOT tick `mydfir-project` or
    "All non-internal indexes" / `*`.
  - `srchIndexesDefault` (Indexes searched by default): **`honeypot`** (so a bare `search` with no explicit index
    still scopes to honeypot).

Save.

### 1.2 Create the user

**Where:** Splunk Web, `mydfir`. Settings > Users and authentication > **Users** > **New User**.

- **Name:** `phase4_investigator` (a dedicated user, same name as the role is fine).
- **Assign role:** `phase4_investigator` ONLY. If the New-User form auto-adds `user`, **remove it** - leaving `user`
  on this account would re-introduce `output_file` (write) and `srchIndexesAllowed = *` and break the acceptance test.
- **Set password:** generate a strong one, then **save it into `SOC-Automation-Project.md`** under a new
  "Phase 4 read-only Splunk user" entry. Do not paste it anywhere else.

**Verify:** the new user appears in the Users list with role `phase4_investigator` and no other roles.

### 1.3 Acceptance test (all three MUST hold)

**Where:** Splunk Web. Log OUT of `mydfir` and log IN as `phase4_investigator`, then run each search in Search &
Reporting (time picker: Last 24 hours). (If the minimal `search`-only role can't open Search & Reporting in the UI,
run the same three checks via the REST `oneshot` from Part 4.1 instead - that is the exact path the service uses and
needs only the `search` capability.)

1. **Write is denied:**
   ```spl
   | makeresults | outputlookup phase4_accept_test.csv
   ```
   **Expected:** an error / "command not allowed" (no capability). It must NOT write a file.

2. **The self-authored index is invisible:**
   ```spl
   search index=mydfir-project | head 1
   ```
   **Expected:** `0 results` (or an "index not found / not authorized" notice). It must NOT return rows.

3. **The honeypot index is searchable:**
   ```spl
   search index=honeypot | head 1
   ```
   **Expected:** exactly one event row returns.

If any of the three is wrong, go back to 1.1 and fix the role's index allowlist / capabilities before continuing.
Record the three outcomes in the Results section. Then log back in as `mydfir` for the rest of the runbook (the
capture steps below use the `phase4_investigator` credentials over the API, not the Splunk Web session).

---

## Part 2 - Capture the real webhook payload  (the headline unknown)

Goal: confirm the live `result` row shape and, specifically, that `earliest`/`latest` are **epoch seconds** (an
integer or a `.NNNNNN`-fractional string), not a pre-formatted time string. If they were a formatted string, `normalize_event_time()`
can't parse them, `event_time` falls back to `''`, and the whole time-bounded investigation goes inert (fail-safe,
but it produces no scope). We want to know that before the paid run, not during it.

The honeypot is internet-exposed and gets brute-forced constantly, and the saved search runs every 15 minutes, so
there is very likely already a real execution to read. Try 2A first; fall back to 2B if there are no recent
Splunk-triggered executions.

### 2A - Read an existing n8n execution (preferred, zero-touch)

**Where:** n8n editor > `honeypot-triage` workflow > **Executions** tab.

1. Open the `honeypot-triage` workflow, click the **Executions** tab.
2. Find a recent execution whose trigger was the Splunk webhook (not a Falcon-poller run). If you are unsure, open
   a few and look at the first node.
3. Click into the execution, then click the **Webhook** node, and view its **output** JSON. The `body` object is the
   exact raw payload Splunk POSTed.

**What to confirm (expected shape):** under `body.result` you should see:

| field | expected format |
|---|---|
| `src_ip` | a single dotted-quad IPv4 string, no `:port` suffix, not an array |
| `count` | numeric string (e.g. `"7"`) |
| `user` | account string (e.g. `"Administrator"`) |
| `ComputerName` | `"vm-honeypot-win"` |
| `earliest` | **epoch seconds**, e.g. `"1751208600"` or `"1751208600.000000"` (Splunk serializes `earliest(_time)` with a `.NNNNNN` suffix - see `repeat_offender.json`). NOT a slashed date `"07/03/2025:00:00:00"`, NOT 13-digit millis. |
| `latest` | epoch seconds, with or without the `.NNNNNN` suffix |

Also confirm the row is a **single object** under `body.result` (not an array `body.results[...]`, not a bare
top-level array). If the row is an array, that is the highest-leverage break: every entity field would read
`undefined` and the investigation would silently produce zero scope.

> The format of `earliest`/`latest` is the whole point: if it **parses as epoch seconds** (an int like `1751208600`
> or a float like `1751208600.000000`), `normalize_event_time()` handles it and **the fix works** - a `.000000`
> suffix is expected and fine, do NOT treat it as drift or "fix" it. Only a slashed/formatted date
> (`"07/03/2025:00:00:00"`) or 13-digit millis makes `normalize_event_time()` return `''`, in which case you'd add
> `| eval event_time=strftime(latest,"%Y-%m-%dT%H:%M:%S")` to the saved search (see honeypot-triage-build.md
> Section D). Record what you actually see.

### 2B - Fire a controlled test alert (fallback - only if 2A has no data, and ONLY after breaking the graph)

> **Cost warning (read before doing this):** n8n's "Listen for test event" runs a **full manual execution of the
> entire connected workflow** when the test URL is hit - that includes the **paid** Opus triage node, the **paid**
> verify node, and the Iris/Discord actions. It is NOT free and it can open a real Iris case / Discord ping from an
> operator-fired alert. Disabling the downstream nodes is NOT enough (n8n passes a disabled node's input straight
> through to the next node). To capture the payload at $0 you MUST physically disconnect the Webhook node's output
> wire first. Prefer 2A whenever there is any recent execution to read.

1. **Where:** n8n editor > `honeypot-triage`. **Disconnect** the wire from the **Webhook** node's output to
   **Parse Alert** (click the connection, delete it). Now nothing downstream can run.
2. **Where:** n8n editor > click the **Webhook** node > **Listen for test event**. n8n listens at
   `http://10.0.0.6:5678/webhook-test/honeypot-triage`.
3. **Where:** Splunk Web, logged in as `mydfir` (the ad-hoc `sendalert` needs the admin session, not the read-only
   role). Time picker: **Last 24 hours**. Run the live SPL with the threshold relaxed, pointed at the TEST url:
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
4. **Where:** back in n8n, the manual execution runs **only the Webhook node** (the wire is cut), so no paid call
   fires. Read the Webhook node's output `body` and confirm the same shape table as 2A.
5. **Where:** n8n editor - **reconnect** the Webhook -> Parse Alert wire and save, so the live pipeline is whole again.

**Verify:** the execution shows ONLY the Webhook node ran (no Opus/verify/Iris nodes), and `body.result` has the six
fields above with `earliest`/`latest` as epoch seconds. (An ad-hoc `sendalert` sends empty
`search_name`/`results_link`; expected and fine - display-only fields that never reach `/investigate` or `/verify`.)

---

## Part 3 - Confirm the search-head timezone

This is mostly a formality because the epoch path is timezone-independent (LB-1 renders absolute epoch bounds), but
we record it for the evidence trail and in case the naive-`strftime` event_time variant is ever adopted.

### 3.1 Account setting

**Where:** Splunk Web > top-right user menu > **Preferences** > **Time zone**.

A brand-new user like `phase4_investigator` defaults to **Default System Timezone**, which means Splunk renders times
in the OS timezone of the search-head host (confirm that in 3.3, which is then authoritative for this user). If you
want to read the preference as `phase4_investigator` itself, log in as that user first; otherwise reading it as
`mydfir` plus the on-box `timedatectl` in 3.3 is sufficient, since the phase4 user inherits the same system default.
Record the value.

### 3.2 Confirming SPL

**Where:** Splunk Web > Search.

```spl
| makeresults
| eval now=now()
| eval tz=strftime(now,"%Z %z"), rendered=strftime(now,"%Y-%m-%d %H:%M:%S")
| table tz rendered
```

**Verify:** `tz` shows the offset the session renders in (e.g. `UTC +0000` or `EDT -0400`), and `rendered`
matches wall-clock in that zone. Record both.

### 3.3 On-box OS timezone (only if 3.1 said "Default System Timezone")

**Where:** SSH to the search head from your local machine.

```bash
ssh -i C:/Users/Owner/.ssh/vm-soc-v2-linux-key.pem azureuser@<splunk-public-ip>
timedatectl
```

**Verify:** note the `Time zone` line (e.g. `Etc/UTC (UTC, +0000)`). Record it.

---

## Part 4 - Schema capture: 5 catalog queries vs the reference envelopes

Confirm the live `output_mode=json` field names + string typing match the hand-authored envelopes in
`splunk-investigator/fixtures/envelopes/`. We use the read-only `phase4_investigator` credentials against the
management API `oneshot` endpoint, which returns the same results-envelope schema the parser consumes
(`{"preview":false,"messages":[...],"fields":[...],"results":[...]}`).

> Two harmless differences from the committed fixtures, do NOT flag them as drift: (1) the live envelope also carries
> a top-level `init_offset` key (e.g. `0`) that the fixtures omit and the parser ignores; (2) production reads results
> from the blocking-job results endpoint while this capture uses `oneshot` - both return the identical
> results-envelope schema, so `oneshot` is a valid shape proxy.

### 4.1 Set up a read-only capture session

**Where:** SSH to the search head (it can reach the management port on `localhost:8089`; the mgmt port is not
exposed off-box).

```bash
ssh -i C:/Users/Owner/.ssh/vm-soc-v2-linux-key.pem azureuser@<splunk-public-ip>
```

Set the read-only creds into the shell WITHOUT putting the password in history (the `-s` silences the echo; open
`SOC-Automation-Project.md` on your local machine, copy the phase4 password, and paste it at the silent prompt):

```bash
export SPLUNK_USERNAME=phase4_investigator
read -rs SPLUNK_PASSWORD && export SPLUNK_PASSWORD
```

**Verify the credentials + read-only scope in one shot:**

```bash
curl -sk -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
  "https://localhost:8089/services/search/jobs/oneshot" \
  --data-urlencode 'search=search index=honeypot | head 1' \
  --data-urlencode 'output_mode=json' \
  --data-urlencode 'earliest_time=-7d' --data-urlencode 'latest_time=now' | head -c 400
```

**Expected:** a JSON blob starting `{"preview":false,...}` with a `results` array containing one event. If you get a
401, the creds are wrong; if you get an authorization error, re-check Part 1.

### 4.2 Capture each of the 5 catalog queries

**Where:** same SSH session. Pick one real attacker IP from the honeypot to use as `<IP>` - reuse the `src_ip` you
saw in Part 2, or discover the current top attacker once the `oneshot` helper below is defined:
`oneshot "search index=honeypot EventCode=4625 | stats count by src_ip | sort -count | head 1"`. The IP stays on-box,
so it can be unredacted here. `<HOST>` is `vm-honeypot-win`, `<USER>` is `Administrator`. Use a generous
`earliest=-7d latest=now` window since we only care about field shape, not the anchoring math (that is validated by
the offline suite).

Run each and save the output. These mirror the templates in `splunk_investigator/catalog.py` with a `| head N`
matching each query's `result_cap`.

```bash
IP=<paste-one-real-attacker-ip>   # stays on-box; do NOT write it into the committed doc
HOST=vm-honeypot-win
USER=Administrator

oneshot () {
  curl -sk -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
    "https://localhost:8089/services/search/jobs/oneshot" \
    --data-urlencode "search=$1" \
    --data-urlencode 'output_mode=json' \
    --data-urlencode 'earliest_time=-7d' --data-urlencode 'latest_time=now' \
    "${@:2}"   # forwards any extra --data-urlencode args (e.g. Part 5's count=5)
}

# 1. logon_outcomes_for_ip  (cap 1)
oneshot "search index=honeypot (EventCode=4624 OR EventCode=4625) src_ip=\"$IP\" | stats count(eval(EventCode=4624)) as success_count, count(eval(EventCode=4625)) as fail_count | head 1" > /tmp/env_logon.json

# 2. processes_by_user  (cap 50)  -- likely 0 rows on honeypot (no Sysmon EventID=1), that is fine; we want the envelope shape
oneshot "search index=honeypot EventID=1 host=\"$HOST\" User=\"$USER\" | stats count by host, User, Image | rename User as user, Image as image | head 50" > /tmp/env_processes.json

# 3. repeat_offender  (cap 1)
oneshot "search index=honeypot EventCode=4625 src_ip=\"$IP\" earliest=-90d latest=now | addinfo | stats earliest(_time) as first_seen, latest(_time) as last_seen, values(info_min_time) as info_min_time | eval days_active=round((last_seen-first_seen)/86400,1) | eval floored=if(first_seen<=info_min_time+300,\"true\",\"false\") | head 1" > /tmp/env_repeat.json

# 4. user_targets_for_ip  (cap 1)
oneshot "search index=honeypot EventCode=4625 src_ip=\"$IP\" | stats dc(user) as distinct_user_count | head 1" > /tmp/env_targets.json

# 5. encoded_powershell_on_host  (cap 1)  -- likely 0 rows on honeypot (brute-force only), envelope shape still valid
oneshot "search index=honeypot EventCode=4104 host=\"$HOST\" ScriptBlockText=\"*-EncodedCommand*\" | stats count | head 1" > /tmp/env_encoded.json
```

**Verify:** each `/tmp/env_*.json` starts `{"preview": false,` and has `fields` + `results` keys. A 0-row query
still returns a valid envelope (empty or single-row `results`), which is all we need for shape.

### 4.3 Diff against the reference envelopes

Compare the **field names** and the **string typing** (Splunk serializes every `results[].*` value as a string, e.g.
`"success_count":"0"`) against the committed fixtures:

- `/tmp/env_logon.json`    vs  `splunk-investigator/fixtures/envelopes/logon_outcomes_for_ip.json`
- `/tmp/env_processes.json` vs `splunk-investigator/fixtures/envelopes/processes_by_user.json`
- `/tmp/env_repeat.json`    vs  `splunk-investigator/fixtures/envelopes/repeat_offender.json`
- `/tmp/env_targets.json`   vs  `splunk-investigator/fixtures/envelopes/user_targets_for_ip.json`
- `/tmp/env_encoded.json`   vs  `splunk-investigator/fixtures/envelopes/encoded_powershell_on_host.json`

You can eyeball them, or `scp` the `/tmp/env_*.json` files to your local machine and diff the `fields[].name` list
and one `results[]` row against each fixture.

**What "pass" looks like:** the `fields[].name` set and the `results[]` keys match the fixture (`success_count` +
`fail_count`; `host`+`user`+`image`+`count`; `first_seen`+`last_seen`+`info_min_time`+`days_active`+`floored`;
`distinct_user_count`; `count`), and every value is a JSON **string** (e.g. `"success_count":"0"`, never a bare `0`).

**If there is drift** (a renamed/new field, or a value that isn't a string): note it in Results, then it becomes a
small code follow-up (adjust the literal field names in `splunk_investigator/catalog.py` and/or the fixtures, and
re-run the engine suite green). Do NOT patch code inside this task without flagging it; the fixture-diff guard in the
suite is what enforces the match.

**Cleanup:** `rm /tmp/env_*.json` when done (they may contain a real attacker IP).

---

## Part 5 - (Optional) Capture the truncation `messages` text

Validates the capped-incomplete detector (pairs with the LB-4 `count=result_cap+1` overflow guard). Only worth doing
if it is quick on your data.

**Where:** the SSH capture session from Part 4.

Force a search with a tiny result cap and look at the top-level `messages` array (the `oneshot` helper now forwards
the extra `count=5` arg):

```bash
oneshot "search index=honeypot EventCode=4625" --data-urlencode 'count=5' | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('messages',[]), indent=2))"
```

**Verify / record:** copy the exact `type` and `text` of any WARN/INFO message Splunk emits about truncation or
partial results into Results. Note that a plain `count` cap may not itself emit a truncation message (it just limits
returned rows); if `messages` is empty on your data, record that and move on. This one is genuinely nice-to-have - the
engine's own `result_cap+1` overflow guard (LB-4) is already unit-tested, so an empty `messages` here is not a failure.

---

## Part 6 - grounding-service deploy env notes (for Task 17)

These are the environment variables the `grounding-service` container (on `vm-soc-v2-n8n`, `10.0.0.6`) needs so
`/investigate` can reach Splunk with the read-only role. Record the final values in Results; do NOT put the password
here.

| var | value | notes |
|---|---|---|
| `SPLUNK_HOST` | `10.0.0.5` | Splunk mgmt, reached from the n8n box over the VNet |
| `SPLUNK_PORT` | `8089` | management API |
| `SPLUNK_SCHEME` | `https` | |
| `SPLUNK_USERNAME` | `phase4_investigator` | the read-only role user from Part 1 |
| `SPLUNK_PASSWORD` | (from `SOC-Automation-Project.md`) | never inline |
| `INVESTIGATE_ENABLED` | `1` | turns the `/investigate` stage on |
| `INVESTIGATE_LIVE_INDEXES` | `honeypot` | must stay `honeypot` ONLY |
| `ANTHROPIC_API_KEY` | (from `SOC-Automation-Project.md`, prefix `sk-ant-Lds`) | needed for Task 17's paid run, NOT this task |

Budget knobs (defaults are fine for Task 17; listed so you know the dials):
`INVESTIGATE_MODEL=claude-opus-4-8`, `INVESTIGATE_MAX_TURNS=8`, `INVESTIGATE_MAX_QUERIES=4`,
`INVESTIGATE_DAILY_BUDGET=200`, `INVESTIGATE_LOOKAHEAD_S=3600`, `INVESTIGATE_DEDUP_WINDOW_S=3600`.

---

## Part 7 - Honest-outcome caveats (read before Task 17)

Task 16 confirms the plumbing; it does NOT guarantee the paid run will show a dramatic grounded-severity change.
Be honest about what the live honeypot data can and can't demonstrate:

- **`index=honeypot` is brute-force only.** There is no post-exploitation telemetry (no Sysmon process trees, no
  encoded PowerShell) because the honeypot host is locked. So `processes_by_user` and `encoded_powershell_on_host`
  will typically return 0 rows on live data. That is correct behavior, not a bug.
- **Grounded HIGH is demonstrable; grounded CRITICAL is not (yet).** The attacker-IP `auth_outcome` path (a real
  successful logon after failures) can back a grounded HIGH. Grounded CRITICAL needs a post-exploit conjunction that
  the live data doesn't contain. If no real post-exploitation incident materializes, the "investigation changed
  scope/severity" criterion is honestly marked **NOT MET** in Task 17 and the artifact is labeled a synthetic/fixture
  demonstration. **Never inject synthetic events into live Splunk to fake a real incident.**
- **The `scope_findings` prompt-populate gap (T13-1) is still open.** The deployed prompt never tells the model to
  echo scope claims into `scope_findings`, so the *headline* grounding is not fully demonstrable until a prompt-tuning
  step with the live model (that is a Task-17-adjacent tweak, tracked separately). The grounded severity-*backing*
  path (LB-2, `ctx.src_ip`/`ctx.pivot_host` + `scope_evidence` threaded into `/verify` out of model control) IS wired
  and live.

---

## Results (fill this in as you go - this is the Task-16 artifact)

### Part 1 - read-only role  -- DONE 2026-07-12
- [x] Role `phase4_investigator` created **from scratch** (imports nothing), capability = `search` only, `srchIndexesAllowed=honeypot`, `srchIndexesDefault=honeypot`.
- [x] User `phase4_investigator` created, `user` role removed, password saved to `SOC-Automation-Project.md`.
- [x] Acceptance (a) `| outputlookup` DENIED: **pass** (permission error).
- [x] Acceptance (b) `index=mydfir-project | head 1` = 0/denied: **pass** (0 results).
- [x] Acceptance (c) `index=honeypot | head 1` = rows: **pass** (1 row).

### Part 2 - webhook payload  (redact src_ip to x.x.x.x)  -- DONE 2026-07-12 (2A, real production exec)
- Capture method used (2A existing exec / 2B test fire): **2A** - a live `executionMode: production` run, Splunk user-agent.
- `body.result` fields present: **all six** - `src_ip` (dotted-quad, redacted), `count` (`"14"`), `user` (`"administrator"`, lowercase), `ComputerName` (`"vm-honeypot-win"`), `earliest`, `latest`.
- `earliest` format: **epoch seconds, float** - `"1782768757.163"` (10-digit integer part + millisecond fraction).
- `latest` format: **epoch seconds, float** - `"1782768779.753"`.
- Row is a single object under `body.result` (yes/no): **yes** (not an array).
- **Verdict:** **parses as epoch seconds, LB-1 assumption HOLDS.** No live-SPL change needed. Note: fraction is `.NNN` (ms) not the fixtures' `.NNNNNN` (us) - both `float()`-parse fine.

### Part 3 - timezone  -- DONE 2026-07-12
- Account TZ preference: Default System Timezone (search head renders UTC, confirmed by SPL below).
- Confirming-SPL `tz`: **`UTC +0000`** (rendered `2026-07-12 22:04:27`). Search head is UTC.
- OS `timedatectl` (if applicable): not needed - SPL already shows UTC.
- Note: search head UTC + epoch-seconds anchoring = tz path is doubly safe (epoch bounds are absolute; even the optional naive-strftime variant would be self-consistent on a UTC head).

### Part 4 - schema capture  -- DONE 2026-07-12 (read-only role over mgmt API, real honeypot data)
- logon_outcomes_for_ip matches fixture: **YES** - fields `success_count`,`fail_count`; live `'0'`/`'375'` (real brute-force).
- processes_by_user matches fixture: **N/A - 0 rows** (no Sysmon `EventID=1` on honeypot); fields `[]`. Expected gap, NOT drift; fixture stays hand-authored best-guess (ties to the grounded-CRITICAL Task-17 caveat).
- repeat_offender matches fixture: **YES** - fields `first_seen`,`last_seen`,`info_min_time`,`days_active`,`floored`; time fields carry `.NNN` ms fraction.
- user_targets_for_ip matches fixture: **YES** - field `distinct_user_count`; live `'6'`.
- encoded_powershell_on_host matches fixture: **YES** - field `count`; live `'0'` (no EncodedCommand on honeypot).
- Any drift + follow-up needed: **NONE.** All values string-typed (validates `parse_envelope` no-coerce). Envelope carries the expected `init_offset:0`. Time fraction is `.NNN` (ms) vs fixtures' `.NNNNNN` (us) - both `float()`-parse fine, no code change. Optional cosmetic: refresh fixture time-values to ms precision for byte-fidelity (not required).

### Part 5 - truncation messages (optional)
- Captured `messages` type/text: _____

### Part 6 - env  -- DONE 2026-07-12
- Confirmed grounding-service env values recorded (password NOT here): **YES** - `SPLUNK_HOST=10.0.0.5`, `SPLUNK_PORT=8089`, `SPLUNK_SCHEME=https`, `SPLUNK_USERNAME=phase4_investigator` (password in `SOC-Automation-Project.md` under "Phase 4 read-only Splunk user"), `INVESTIGATE_ENABLED=1`, `INVESTIGATE_LIVE_INDEXES=honeypot`. `ANTHROPIC_API_KEY` (prefix `sk-ant-Lds`) for the Task-17 paid run only. Read-only role verified working over `https://10.0.0.5:8089` (the exact splunklib path the service uses).

### Sign-off
- Task 16 complete, ready for Task 17 (paid live run): _____ (date)
