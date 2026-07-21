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


def test_md_link_broken_and_ok(repo):
    repo.write("vault/architecture/current-state.md", "# Current state\n")
    src = repo.write(
        "README.md",
        "See [ok](vault/architecture/current-state.md) and [bad](vault/missing.md).\n",
    )
    findings = doc_lint.check_md_links(src, repo, src.read_text())
    msgs = [f.message for f in findings]
    assert any("vault/missing.md" in m for m in msgs)
    assert not any("current-state.md" in m for m in msgs)


def test_md_link_anchor(repo):
    repo.write("vault/x.md", "# Title Here\n## Sub Section\n")
    src = repo.write("README.md", "[a](vault/x.md#sub-section) [b](vault/x.md#nope)\n")
    findings = doc_lint.check_md_links(src, repo, src.read_text())
    assert [f for f in findings if "#nope" in f.message]
    assert not [f for f in findings if "#sub-section" in f.message]


def test_wiki_link_resolution(repo):
    repo.write("vault/runbooks/splunk-mcp-setup.md", "x")
    repo.write("vault/architecture/current-state.md", "x")
    src = repo.write("vault/README.md", "[[runbooks/splunk-mcp-setup]] and [[nonexistent-page]]\n")
    index = doc_lint.build_vault_index(repo)
    findings = doc_lint.check_wiki_links(src, repo, src.read_text(), index)
    msgs = [f.message for f in findings]
    assert any("nonexistent-page" in m for m in msgs)
    assert not any("splunk-mcp-setup" in m for m in msgs)


def test_wiki_link_relative_and_folder_local_resolve(repo):
    # The vault links heavily via ../-relative and same-folder bare-stem refs.
    # Both must resolve Obsidian-style, not flag broken/ambiguous.
    repo.write("vault/detections/t1.md", "x")
    src1 = repo.write("vault/decisions/0001-x.md", "See [[../detections/t1]]\n")
    repo.write("vault/subprojects/a/spec.md", "x")
    repo.write("vault/subprojects/b/spec.md", "x")   # makes bare 'spec' ambiguous vault-wide
    src2 = repo.write("vault/subprojects/a/README.md", "See [[spec]]\n")
    index = doc_lint.build_vault_index(repo)
    assert doc_lint.check_wiki_links(src1, repo, src1.read_text(), index) == []  # ../-relative resolves
    assert doc_lint.check_wiki_links(src2, repo, src2.read_text(), index) == []  # same-folder [[spec]] resolves


def test_links_and_wikilinks_ignored_in_code(repo):
    # Inline `code` spans, an image embed, and fenced blocks must not produce link
    # findings. (~~~ fence to avoid nesting a ``` block inside this plan.)
    src = repo.write(
        "vault/README.md",
        "Inline `[[nope]]` and `[x](does/not/exist.md)` are ignored.\n"
        "An image ![alt](diagram.png) is not a link.\n"
        "~~~\n[[alsonope]] and [y](also/missing.md)\n~~~\n",
    )
    index = doc_lint.build_vault_index(repo)
    assert doc_lint.check_md_links(src, repo, src.read_text()) == []
    assert doc_lint.check_wiki_links(src, repo, src.read_text(), index) == []
