"""The n8n pre-gate regex must be a strict SUPERSET of the engine prefilter:
for every engine-positive command, the pre-gate must also fire. Over-calling is
safe (an extra /deobfuscate call); under-calling would miss a real payload.

The pre-gate source is a SINGLE constant in the builder (N8N_PREGATE_SOURCE),
pasted verbatim into the JS node and imported here, so there is no transcription
drift between what ships and what is tested."""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))  # so build_honeypot_triage_workflow imports

from build_honeypot_triage_workflow import N8N_PREGATE_SOURCE  # noqa: E402
from malware_triage import corpus, prefilter  # noqa: E402

N8N_PREGATE = re.compile(N8N_PREGATE_SOURCE, re.IGNORECASE)

# One genuinely engine-positive probe per prefilter kind, including the -e / -ec
# short-forms that the parent plan's regex missed. Each probe is asserted to be
# BOTH engine-positive (so it is a valid superset test case) AND n8n-positive.
PROBES = {
    "enc_encodedcommand": "powershell -encodedcommand VwByAGkAdABlAC0ASABvAA==",
    "enc_enc": "powershell -enc VwByAGkAdABlAC0ASABvAA==",
    "enc_en": "powershell -en VwByAGkAdABlAC0ASABvAA==",
    "enc_ec": "powershell -ec VwByAGkAdABlAC0ASABvAA==",
    "enc_e": "powershell -e VwByAGkAdABlAC0ASABvAA==",
    "frombase64": "[System.Convert]::FromBase64String('SGVsbG8gd29ybGQ=')",
    "gzip": "New-Object System.IO.Compression.GzipStream($ms,$mode)",
    "deflate": "New-Object System.IO.Compression.DeflateStream($ms,$mode)",
    "io_compression": "using System.IO.Compression;",
    "hex": "$b = 4d5a90000300000004000000ffff0000b800000000000000",
    "char_array": "[char]104 + [char]101 + [char]108 + [char]108 + [char]111",
}


def test_n8n_pregate_is_superset_of_engine_over_corpus():
    samples = corpus.load_samples()
    assert samples, "corpus is empty"
    for s in samples:
        if prefilter.has_encoded_payload(s.command):
            assert N8N_PREGATE.search(s.command), f"n8n pre-gate missed engine-positive sample {s.id}"


def test_n8n_pregate_covers_every_engine_kind():
    for name, probe in PROBES.items():
        assert prefilter.has_encoded_payload(probe), f"probe not engine-positive: {name}"
        assert N8N_PREGATE.search(probe), f"n8n pre-gate missed engine-positive kind: {name}"


def test_n8n_pregate_linear_time_on_adversarial_input():
    # Anchored/linear regex (no nested unbounded quantifiers): a long non-matching
    # flood must return fast. Canary against a future edit introducing catastrophic
    # backtracking. 'g' is not a hex char and starts no keyword, so no branch matches.
    evil = "g" * 200_000
    start = time.perf_counter()
    N8N_PREGATE.search(evil)
    assert time.perf_counter() - start < 1.0
