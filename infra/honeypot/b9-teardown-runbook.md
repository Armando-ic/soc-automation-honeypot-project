# B9 teardown runbook (honeypot-opening operation)

**What this is:** the exact procedure to close down the live honeypot once the B8 capture is done (or
the box is too compromised to keep running). The snapshot -> disk half of the recovery path was
**dry-run proven 2026-07-24**: `honeypot-preopen-20260717` produced a valid 127 GB Windows Gen2 disk
(`provisioningState: Succeeded`), which was then deleted clean. This runbook is the full teardown built
on that proof.

**When to run B9:** enough post-exploitation telemetry captured, OR the box is too compromised to
continue safely, OR you're ending the honeypot-opening operation. This is **distinct from parking the box**
with `az vm deallocate` - that just stops it; B9 restores or destroys it. (Parking used to be the standing
Decision 1 "deallocate-when-unattended" rule. That was **superseded 2026-07-30** - the box now stays
running between sessions, so a deallocate is a deliberate act. Reasoning lives in the opening runbook's
Standing decisions.)

**No Falcon step in this runbook.** The CrowdStrike trial ended 2026-07-28. Teardown never depended on it
- there is no contain to lift here - so nothing in the procedure below changes. Noted explicitly because
the session-45 handoff listed a "B9 lift step" that does not exist.

**Pre-open snapshot:** `honeypot-preopen-20260717` in `rg-honeypot` (Windows, Gen2, ~127 GB). Taken
2026-07-17, **before** any weak cred was planted, so restoring from it returns the box to the clean,
**closed** pre-open state.

What a restore actually undoes (verified on-box 2026-07-27, do not assume the earlier wording):
- **Both planted accounts are DELETED, not disabled.** `backup` (RID 1000) and `Administrator` (RID 1001)
  were each *created* on 2026-07-24, after this snapshot was taken, so neither exists in the restored
  image. Corrects an earlier draft of this doc that described putting "the built-in `Administrator` back
  to disabled" - that was wrong on two counts.
- **`Administrator` here is not the built-in RID-500 account.** Azure provisioning renamed RID-500 to the
  admin username, so on this box **`mandoaic` is RID-500** and survives the restore as the operator login.
  The planted `Administrator` is an ordinary RID-1001 account that merely wears the name.
- **Every password-policy weakening reverts too, because the snapshot predates all of it.** A restored box
  comes back with:
  - `Lockout threshold: 10` (cleared to `Never` live on 2026-07-27 via `net accounts /lockoutthreshold:0`)
  - `Password must meet complexity requirements: Enabled` (disabled live on 2026-08-05)
  - `Minimum password length` back to its shipped value (was set to 0 on 2026-08-05)

  That is the correct and safe direction for a restore, but it means **reopening is not just replanting the
  accounts** - you have to redo the policy work as well or the new decoys are decorative again. The
  reasoning for each change lives in the opening runbook's B7.3, and it is worth re-reading rather than
  re-deriving: the lockout wall alone silently refused ~87% of real password guesses for three days.

**Where:** all steps in local PowerShell (`az`, logged in as yourself). USER drives hands-on. Substitute
`<...>` placeholders from the command outputs; use `<YYYYMMDD>` = today.

---

## Step 0 — PRESERVE FORENSICS FIRST (do not skip)

Before overwriting or deleting anything, snapshot the **compromised** disk so the attacker's on-box
changes survive for later analysis (that on-box state is the point of the whole operation; Splunk only
has what Sysmon shipped).

```powershell
# 0.1 stop the VM (a consistent snapshot needs it deallocated)
az vm deallocate -g rg-honeypot -n vm-honeypot-win

# 0.2 get the current (compromised) OS disk id
az vm show -g rg-honeypot -n vm-honeypot-win --query "storageProfile.osDisk.managedDisk.id" -o tsv

# 0.3 snapshot it (the forensic evidence copy)
az snapshot create -g rg-honeypot -n honeypot-postexploit-<YYYYMMDD> --source "<os-disk-id-from-0.2>"
# verify:
az snapshot show -g rg-honeypot -n honeypot-postexploit-<YYYYMMDD> --query provisioningState -o tsv   # -> Succeeded
```

Splunk-side telemetry (`index=honeypot`) already persists independently on the Splunk box; this disk
snapshot preserves the file/registry/tooling artifacts Sysmon may not have captured.

---

## Path A — restore to pre-open (reuse the box, returns it CLOSED)

Best if you want to keep the honeypot infra for future sessions. Swaps the OS disk back to the clean
pre-open state.

```powershell
# A.1 confirm the VM is deallocated (Step 0.1 did this)

# A.2 match the original OS disk SKU
az disk show --ids "<os-disk-id-from-0.2>" --query "sku.name" -o tsv          # e.g. Standard_LRS / Premium_LRS

# A.3 create a fresh disk from the pre-open snapshot (match the SKU from A.2)
az disk create -g rg-honeypot -n vm-honeypot-win-os-restored-<YYYYMMDD> --source honeypot-preopen-20260717 --sku <sku-from-A.2>
az disk show -g rg-honeypot -n vm-honeypot-win-os-restored-<YYYYMMDD> --query provisioningState -o tsv   # -> Succeeded

# A.4 note the OLD (compromised) OS disk name for deletion later
az vm show -g rg-honeypot -n vm-honeypot-win --query "storageProfile.osDisk.name" -o tsv

# A.5 swap the OS disk
az vm update -g rg-honeypot -n vm-honeypot-win --os-disk vm-honeypot-win-os-restored-<YYYYMMDD>

# A.6 start + verify
az vm start -g rg-honeypot -n vm-honeypot-win
#     RDP/console in as mandoaic -> confirm the `backup` account is GONE (restored to pre-open = closed).
#     The box is now CLOSED again. If you just want it parked, deallocate it.

# A.7 ONLY after A.6 boots clean AND the Step-0.3 forensic snapshot is Succeeded, delete the old disk
az disk delete -g rg-honeypot -n <old-os-disk-name-from-A.4> --yes
```

---

## Path B — full teardown (destroy the box)

Best if you're done with the honeypot entirely.

```powershell
# B.1 confirm the Step-0.3 forensic snapshot is Succeeded (your ONLY on-box evidence copy after this)
# B.2 delete the VM
az vm delete -g rg-honeypot -n vm-honeypot-win --yes
# B.3 delete its OS disk if not auto-removed
az disk delete -g rg-honeypot -n <os-disk-name> --yes
# B.4 (optional) delete the NIC
az network nic delete -g rg-honeypot -n <nic-name>
```

**KEEP (do not delete) unless truly done:** the static public IP, `nsg-honeypot`, and the VNet — reused
by the SOC infra and any future honeypot. **Deleting `nsg-honeypot` also drops the brake's egress floor.**

---

## Proven vs unproven

- **Proven (dry-run 2026-07-24):** snapshot `honeypot-preopen-20260717` -> valid provisioned disk -> deletes clean.
- **Unproven (inherent to real teardown, low-risk given the proof above):** the OS-disk **swap**
  (`az vm update --os-disk`) + boot. If a swap ever fails, the Path-B fallback is a fresh VM off the
  restored disk: `az vm create -g rg-honeypot -n vm-honeypot-win-restored --attach-os-disk <restored-disk-id> --os-type Windows` (then re-point the public IP / NSG).
