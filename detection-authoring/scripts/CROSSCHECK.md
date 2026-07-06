# Matcher faithfulness cross-check (dev-time)

The 4-tier gate's T3/T4 use an owned Sigma matcher. To prove it is faithful to
real Sigma semantics, cross-check it once against Zircolite (the community
offline Sigma engine) on the whole frozen corpus.

## Run it
1. In a SCRATCH venv (not detection-authoring/.venv): `pip install zircolite`,
   or clone https://github.com/wagga40/Zircolite and note the path to zircolite.py.
2. `detection-authoring/.venv/Scripts/python scripts/crosscheck_zircolite.py --zircolite <path/to/zircolite.py>`
3. Expected: "Owned matcher agrees with Zircolite on the whole corpus."

## If it disagrees
The matcher has a bug or the subset guard is letting through something the
matcher mis-models. Fix the matcher (or tighten the subset), re-run the pytest
suite, then re-run this check. Paste the final agreeing output into the vault
notes as the faithfulness evidence.
