# Security Incident Report — TEMPLATE

> Reusable escalation/incident writeup for honeypot (and comparable) activity. Fill every section;
> delete the _italic guidance_ as you go. The golden rule: **a busy lead should be able to read only
> section 1 and know what happened, whether it matters, and what you need from them.** Everything
> below section 1 is the evidence that backs it up.
>
> This template pairs with the automated triage: the AI's `submit_triage_result` gives you the
> mechanical fields (IOCs, ATT&CK, a first-pass severity). **Your job is the judgment the AI can't
> make** — calibrate severity to OUR environment, separate CONFIRMED from SUSPECTED, and state the ask.

| Field | Value |
|---|---|
| Report ID | INC-YYYY-NNN |
| Report date/time (UTC) | |
| Analyst | |
| Status | Open · Monitoring · Contained · Closed |
| Classification | TLP:AMBER (internal) |

---

## 1. Executive summary (BLUF — bottom line up front)

_2-4 sentences, plain English. WHO did WHAT to WHICH asset, the IMPACT (confirmed vs potential),
current STATUS, and the ONE thing you need from the reader. No jargon a manager wouldn't know. If they
stop reading here, they should still make the right decision._

## 2. Severity & confidence

| | |
|---|---|
| **Severity** | _Informational / Low / Medium / High / Critical_ |
| **Confidence** | _Low / Moderate / High_ |
| **Rationale** | _Why this rating FOR OUR ENVIRONMENT. Name the facts that drive it: was there a successful compromise or not? Is the asset production or a decoy? Don't just inherit the tool's default — calibrate it._ |

## 3. What happened

_Plain-language description of the observed activity. Reads like a paragraph, not a log dump._

## 4. Timeline (UTC)

| Time (UTC) | Event |
|---|---|
| | _Activity window start_ |
| | _Activity window end_ |
| | _Detection / alert fired_ |
| | _Response action(s)_ |

## 5. Affected assets

| Asset | Type | Role / exposure |
|---|---|---|
| | | |

## 6. Indicators of compromise (IOCs)

| Indicator | Type | Enrichment / verdict | Notes |
|---|---|---|---|
| | | | |

## 7. MITRE ATT&CK mapping

| Technique ID | Name | Tactic |
|---|---|---|
| | | |

## 8. Impact assessment

_Confirmed impact vs potential impact. Was anything actually accessed/changed? Blast radius? Be
explicit when the answer is "no confirmed impact" — that is itself the headline._

## 9. Response actions taken

| Action | By | When (UTC) | Result |
|---|---|---|---|
| | | | |

## 10. Recommendations / next steps

| Priority | Recommendation | Owner |
|---|---|---|
| | | |

## 11. Analyst assessment & the ask

_Your professional judgment in 1-3 sentences, your confidence, and EXPLICITLY what you need from the
reader: a decision, an approval, a resource, or just "no action needed, informing you per policy."_

---

## Appendix — evidence

_Splunk search / dashboard refs, screenshots, and the raw triage output (`submit_triage_result` JSON)._
