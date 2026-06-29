# Synthetic real-IP Contain-recommended path-validation (0D-2, Q2)

Proves the flagship `alert → triage → gate → "Contain recommended"` path deterministically,
with a REAL AbuseIPDB-flagged IP and the real pipeline — **no box compromise**. Clearly labeled
`[SYNTHETIC PATH-VALIDATION]` so it is never mistaken for an organic catch. Recommend-only
(does NOT fire `falcon-contain`).

Injection seam = the same one the Falcon poller uses: a single POST of a crafted Falcon-shaped
body to the active `honeypot-triage` webhook (`http://10.0.0.6:5678/webhook/honeypot-triage`).
Bypasses the poller entirely → never touches `watermark`/`seen`.

Body template: `synthetic-demo-body.json` (substitute `<REAL_BAD_IP>` at run time).

## 1. Pick + verify a currently-flagged IP (local, key from creds file — never inline)

Where: local machine, PowerShell. Load `$abuseKey` from the gitignored creds file your usual way, then:

```powershell
$cand = '<CANDIDATE_IP>'   # from the AbuseIPDB blacklist or a current threat feed
Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$cand&maxAgeInDays=90" `
  -Headers @{ Key=$abuseKey; Accept='application/json' } | Select-Object -Expand data |
  Select-Object ipAddress, abuseConfidenceScore
```

Use an IP whose `abuseConfidenceScore` ≥ 90 (this is the exact call n8n's `enrich_abuseipdb` makes,
so a high score here guarantees a `malicious` verdict in the pipeline).

## 2. Fire the crafted alert (RDP to the Splunk VM = the real Splunk→n8n path)

Where: RDP to `vm-soc-v2-splunk` (10.0.0.5), PowerShell. Paste the body with the real IP substituted:

```powershell
$body = @'
{ ...contents of synthetic-demo-body.json with <REAL_BAD_IP> replaced... }
'@
Invoke-RestMethod -Method POST -Uri 'http://10.0.0.6:5678/webhook/honeypot-triage' `
  -ContentType 'application/json' -Body $body
```

## 3. Observe (the artifact)

- **DFIR-Iris:** a new HIGH alert titled `FALCON — [SYNTHETIC PATH-VALIDATION] SUCCESSFUL BRUTE-FORCE COMPROMISE
  (CRITICAL)` with `2.57.121.25` attached as a **MALICIOUS** IOC, a coherent 487-fail→success narrative, and
  fully-populated recommended actions.
- **Discord:** an embed titled `✅ HIGH — Falcon — [SYNTHETIC PATH-VALIDATION] Successful Brute-Force Compromise
  (Critical)` whose description ends `⚠️ Contain recommended — run falcon-contain for vm-honeypot-win`.
- (Optional) grounding-service `runs.jsonl` shows `verification_passed=true` (all 10 deterministic checks).

Notes:
- **Title says "(Critical)" but the badge is HIGH** — the parenthetical is the (synthetic) Falcon
  `severity_name`; Opus *independently triages* down to **high** for the honeypot's limited blast radius. That
  divergence is realistic, not a bug.
- The **advisory judge** logs `needs_human` by design (a conservative second opinion); it does NOT gate
  `verification_passed` and does NOT appear in the Iris/Discord view. Coherence (consistent `count`, no
  unsupported lateral-movement) keeps its notes to advisory polish rather than real contradictions.
- If severity ever lands `medium` (no "Contain recommended"), re-fire §2 — LLM variance; the coherent
  successful-compromise narrative makes high/critical the overwhelming outcome.
