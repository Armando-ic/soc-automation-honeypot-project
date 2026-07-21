import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import doc_lint


def test_scope_includes_top_level_and_excludes_noise(repo):
    repo.write("README.md")
    repo.write("infra/honeypot/RUNBOOK.md")
    repo.write("infra/honeypot/session-logs/HANDOFF.md")   # excluded (session-logs)
    repo.write("grounding-service/README.md")
    repo.write("grounding-service/.venv/x.md")             # excluded (.venv)
    repo.write("vault/README.md")
    repo.write("lint-log.md")                              # excluded (own journal)
    repo.write("notes.txt")                                # not markdown

    got = {str(p.relative_to(repo)).replace("\\", "/") for p in doc_lint.iter_scope_files(repo)}
    assert got == {
        "README.md",
        "infra/honeypot/RUNBOOK.md",
        "grounding-service/README.md",
        "vault/README.md",
    }


def test_slugify_matches_github_anchors():
    assert doc_lint._slugify("Sub Section") == "sub-section"
    assert doc_lint._slugify("Status & Context") == "status--context"  # spaced punct -> double hyphen
    assert doc_lint._slugify("Multi-word Heading") == "multi-word-heading"


def test_heading_slugs_ignores_fenced_code(repo):
    # The `# Not A Heading` line is a shell comment inside a fenced block, not an
    # ATX heading; a fence-blind extractor would wrongly slug it. (~~~ fences here
    # to avoid nesting a triple-backtick block inside this plan; the code treats
    # ``` and ~~~ identically.)
    text = "# Real One\n~~~\n# Not A Heading\n~~~\n## Real Two\n"
    assert doc_lint._heading_slugs(text) == {"real-one", "real-two"}
