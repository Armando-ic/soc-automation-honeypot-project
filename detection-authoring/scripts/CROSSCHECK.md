# Matcher faithfulness cross-check (dev-time)

The 4-tier gate's T3/T4 use an owned Sigma matcher. To prove it is faithful to
real Sigma semantics, cross-check it once against Zircolite (the community
offline Sigma engine) on the whole frozen corpus.

## Set up Zircolite (scratch venv, NOT detection-authoring/.venv)

Zircolite is not on PyPI; clone it and install its deps in a throwaway venv so
they never mix with the package venv:

    git clone https://github.com/wagga40/Zircolite
    cd Zircolite
    python -m venv .venv-zircolite
    .venv-zircolite/Scripts/python -m pip install -r requirements.txt   # bash: .venv-zircolite/bin/python
    .venv-zircolite/Scripts/python zircolite.py --version               # sanity check

## Run the cross-check

Run it with OUR package venv (it imports the matcher + corpus) but point
`--python` at Zircolite's scratch venv (it runs zircolite.py, which needs
Zircolite's deps):

    ./.venv/Scripts/python scripts/crosscheck_zircolite.py \
        --zircolite /path/to/Zircolite/zircolite.py \
        --python    /path/to/Zircolite/.venv-zircolite/Scripts/python

Expected final line: "Owned matcher agrees with Zircolite on the whole corpus."

## If it disagrees
The matcher has a bug or the subset guard is letting through something the
matcher mis-models. Fix the matcher (or tighten the subset), re-run the pytest
suite, then re-run this check. Paste the final agreeing output into the vault
notes as the faithfulness evidence.
