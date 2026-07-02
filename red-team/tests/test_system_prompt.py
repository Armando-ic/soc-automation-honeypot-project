import importlib.util

from red_team.harness.system_prompt import load_system_prompt, load_tool_def
from tests.conftest import REPO


def _load_generator():
    src = REPO / "infra" / "honeypot" / "build_honeypot_triage_workflow.py"
    spec = importlib.util.spec_from_file_location("gen_wf", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # side effects are __main__-guarded (Task 3 Step 0), so import is safe
    return mod


def test_system_prompt_byte_matches_generator():
    assert load_system_prompt() == _load_generator().PROMPT


def test_system_prompt_is_the_deployed_options_system():
    prompt = load_system_prompt()
    assert prompt.startswith("You are a Tier 1 SOC analyst")
    assert "submit_triage_result" in prompt


def test_tool_def_is_parsed_object_matching_generator_schema():
    td = load_tool_def()
    assert td["name"] == "submit_triage_result"
    assert isinstance(td["input_schema"], dict)      # parsed object, not a JSON string
    assert td["input_schema"] == _load_generator().SCHEMA
