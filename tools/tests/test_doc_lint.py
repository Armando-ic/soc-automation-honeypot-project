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


def test_relative_date_phrases(repo):
    src = repo.write("README.md", "Fixed yesterday.\nDeploy 3 days ago.\nAbsolute 2026-07-21 is fine.\n")
    findings = doc_lint.check_relative_dates(src, repo, src.read_text())
    msgs = " ".join(f.message for f in findings)
    assert "yesterday" in msgs
    assert "3 days ago" in msgs
    assert "2026-07-21" not in msgs


def _fm(status="active"):
    return f"---\nstatus: {status}\nupdated: 2026-07-21\nrelated: [[x]]\n---\n"


def test_vault_subproject_missing_files(repo):
    repo.write("vault/subprojects/2026-01-01-thing/README.md", _fm())
    # missing spec.md, plan.md, runbook.md, notes.md
    findings = doc_lint.check_vault_structure(repo)
    assert any("spec.md" in f.message and "notes.md" in f.message for f in findings)


def test_vault_adr_numbering_and_sections(repo):
    repo.write("vault/decisions/0001-a.md", _fm() + "## Status\n## Context\n## Decision\n## Consequences\n")
    repo.write("vault/decisions/0003-c.md", _fm() + "## Status\n")  # gap (no 0002) + missing sections
    findings = doc_lint.check_vault_structure(repo)
    joined = " ".join(f.message for f in findings)
    assert "not contiguous" in joined
    assert "context" in joined  # 0003 missing sections; message emits the lowercase slug


def test_vault_adr_duplicate_number(repo):
    repo.write("vault/decisions/0001-a.md", _fm() + "## Status\n## Context\n## Decision\n## Consequences\n")
    repo.write("vault/decisions/0001-b.md", _fm() + "## Status\n## Context\n## Decision\n## Consequences\n")
    findings = doc_lint.check_vault_structure(repo)
    assert any("duplicate ADR number" in f.message for f in findings)


def test_vault_frontmatter_missing_key(repo):
    repo.write("vault/architecture/current-state.md", "---\nstatus: active\nupdated: 2026-07-21\n---\n# X\n")
    findings = doc_lint.check_vault_structure(repo)
    assert any("related" in f.message for f in findings)


# ADRs are immutable (vault/CLAUDE.md) and in practice carry a {status, date} frontmatter
# shape (per the actual decisions/ files) rather than the schema's default {status, updated,
# related}. detections/ pages instead derive their required keys from the sibling _template.md
# (last_run, not updated). Both are per-directory frontmatter shapes.

def test_vault_adr_frontmatter_accepts_status_date(repo):
    # status + date is the full ADR shape; the default updated/related must not be demanded.
    repo.write("vault/decisions/0001-x.md",
               "---\nstatus: active\ndate: 2026-04-27\n---\n"
               "## Status\n## Context\n## Decision\n## Consequences\n")
    findings = doc_lint.check_vault_structure(repo)
    assert not any("frontmatter missing key" in f.message for f in findings)


def test_vault_adr_frontmatter_requires_date(repo):
    # The ADR shape is still enforced: status alone is missing date (and only date;
    # the ': date' / no-'updated' check avoids the 'date' substring inside 'updated').
    repo.write("vault/decisions/0001-x.md",
               "---\nstatus: active\n---\n"
               "## Status\n## Context\n## Decision\n## Consequences\n")
    findings = doc_lint.check_vault_structure(repo)
    fm = [f for f in findings if "frontmatter missing key" in f.message]
    assert fm and all(": date" in f.message and "updated" not in f.message for f in fm)


def _detection_template():
    return ("---\nstatus: untested\ntechnique_id: T<id>\ntactic: <x>\n"
            "last_run: YYYY-MM-DD\nrelated: [[x]]\n---\n## Description\n")


def test_vault_detection_frontmatter_from_template(repo):
    # A page carrying the template's keys (last_run, no updated) must not be flagged.
    repo.write("vault/detections/_template.md", _detection_template())
    repo.write("vault/detections/t1.md",
               "---\nstatus: saved-search-active\ntechnique_id: T1059.001\ntactic: Execution\n"
               "last_run: 2026-05-12\nrelated: [[x]]\n---\n## Description\n")
    findings = doc_lint.check_vault_structure(repo)
    assert not any(f.file == "vault/detections/t1.md" and "frontmatter missing key" in f.message
                   for f in findings)


def test_vault_detection_frontmatter_requires_template_key(repo):
    # The template shape is enforced: a page missing tactic + last_run is flagged for both.
    repo.write("vault/detections/_template.md", _detection_template())
    repo.write("vault/detections/t1.md",
               "---\nstatus: observed\ntechnique_id: T1059.001\nrelated: [[x]]\n---\n## Description\n")
    findings = doc_lint.check_vault_structure(repo)
    assert any(f.file == "vault/detections/t1.md" and "frontmatter missing key" in f.message
               and "tactic" in f.message and "last_run" in f.message for f in findings)


def test_vault_readme_keeps_default_frontmatter_shape(repo):
    # A folder README is an index, not a content page: it keeps the default
    # {status, updated, related} shape even when a sibling _template.md declares
    # technique_id/tactic/last_run, so it must not inherit the template's keys.
    repo.write("vault/detections/_template.md", _detection_template())
    repo.write("vault/detections/README.md",
               "---\nstatus: active\nupdated: 2026-04-30\nrelated: [[x]]\n---\n# Coverage index\n")
    findings = doc_lint.check_vault_structure(repo)
    assert not any(f.file == "vault/detections/README.md" and "frontmatter missing key" in f.message
                   for f in findings)


def test_vault_template_sections(repo):
    repo.write("vault/detections/_template.md", "## Detection\n## Logic\n## Coverage\n")
    repo.write("vault/detections/T1059.md", _fm() + "## Detection\n## Logic\n")  # missing Coverage
    findings = doc_lint.check_vault_structure(repo)
    assert any("coverage" in f.message.lower() for f in findings)


def test_vault_template_h1_title_not_required(repo):
    # The template's H1 is a per-page title placeholder, not a shared section: a page
    # with its own H1 must not be flagged as missing the template's title heading.
    repo.write("vault/detections/_template.md", "# T<id> - <name>\n## Detection\n## Logic\n")
    repo.write("vault/detections/t1.md", _fm() + "# T1059 - PowerShell\n## Detection\n## Logic\n")
    findings = doc_lint.check_vault_structure(repo)
    assert not any("template section" in f.message for f in findings)


def test_orphan_vault_page(repo):
    repo.write("vault/README.md", _fm() + "See [[architecture/current-state]]\n")
    repo.write("vault/architecture/current-state.md", _fm() + "linked\n")
    repo.write("vault/concepts/lonely.md", _fm() + "nobody links here\n")
    findings = doc_lint.check_vault_orphans(repo)
    orphans = [f.file for f in findings]
    assert "vault/concepts/lonely.md" in orphans
    assert "vault/architecture/current-state.md" not in orphans  # it is linked


def test_orphan_respects_resolution_and_exemptions(repo):
    repo.write("vault/log.md", "journal, never wiki-linked\n")
    repo.write("vault/CLAUDE.md", "agent context, never wiki-linked\n")
    repo.write("vault/subprojects/a/spec.md", _fm() + "reached only via same-folder bare stem\n")
    repo.write("vault/subprojects/b/spec.md", _fm() + "other spec (makes 'spec' ambiguous)\n")
    repo.write("vault/subprojects/a/README.md", _fm() + "See [[spec]]\n")
    orphans = {f.file for f in doc_lint.check_vault_orphans(repo)}
    assert "vault/log.md" not in orphans                 # exempt (journal)
    assert "vault/CLAUDE.md" not in orphans               # exempt (agent context)
    assert "vault/subprojects/a/spec.md" not in orphans   # inbound via same-folder [[spec]]


def test_run_aggregates_and_sorts(repo):
    repo.write("README.md", "[bad](missing.md)\nyesterday\n")
    findings = doc_lint.run(repo)
    checks = {f.check for f in findings}
    assert "link" in checks and "relative-date" in checks
    assert findings == sorted(findings, key=lambda f: (f.file, f.line, f.check))
