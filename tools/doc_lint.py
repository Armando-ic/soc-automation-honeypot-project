"""Tier-1 deterministic documentation linter for the honeypot repo.

Stdlib-only, reports-only. Usage: python tools/doc_lint.py [repo_root]
Checks: broken internal links, relative-date phrases, vault structural conformance.
"""
from __future__ import annotations

import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

IN_SCOPE_FILES = ("README.md", "ARCHITECTURE.md", "CLAUDE.md")
IN_SCOPE_DIRS = ("infra/honeypot", "grounding-service", "triage-verifier", "vault")
EXCLUDE_PARTS = {
    ".venv", "site-packages", "session-logs", "Personal",
    ".playwright-mcp", ".cache", "splunk-mcp-main", "red-team",
}
EXCLUDE_NAMES = {"LICENSE.md", "lint-log.md"}


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    check: str
    message: str


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def iter_scope_files(root: Path) -> list[Path]:
    out: set[Path] = set()
    for name in IN_SCOPE_FILES:
        p = root / name
        if p.is_file():
            out.add(p)
    for d in IN_SCOPE_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in base.rglob("*.md"):
            if set(p.relative_to(root).parts) & EXCLUDE_PARTS:
                continue
            if p.name in EXCLUDE_NAMES:
                continue
            out.add(p)
    return sorted(out)


INLINE_CODE_RE = re.compile(r"`[^`]*`")


def _content_lines(text: str, blank_code: bool = False):
    """Yield (lineno, line) for prose lines, skipping fenced code blocks (delimited
    by triple-backtick or triple-tilde fences) so that `#` comment lines and example
    [links] inside code samples are never parsed as real headings or links. With
    blank_code=True, inline `code` spans are removed too (used by the link checks).
    Heading extraction passes blank_code=False so a heading that itself contains an
    inline-code span keeps that text for slugging."""
    in_fence = False
    fence = ""
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not in_fence and (stripped.startswith("```") or stripped.startswith("~~~")):
            in_fence, fence = True, stripped[:3]
            continue
        if in_fence:
            if stripped.startswith(fence):
                in_fence, fence = False, ""
            continue
        yield i, (INLINE_CODE_RE.sub("", line) if blank_code else line)


def _slugify(text: str) -> str:
    # GitHub-style anchor: lowercase, drop punctuation, then each whitespace char
    # becomes ONE hyphen. Deliberately NOT re.sub(r"\s+", ...) (run-collapsing) and
    # NO trailing .strip("-"): github-slugger does neither, so those would make the
    # checker both miss real broken anchors and false-flag correct ones like
    # "#status--context" (from a "Status & Context" heading).
    s = text.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"\s", "-", s)
    return s


def _heading_slugs(text: str) -> set[str]:
    slugs = set()
    for _, line in _content_lines(text):
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m:
            slugs.add(_slugify(m.group(1)))
    return slugs


def _section_slugs(text: str) -> set[str]:
    """Heading slugs for H2..H6 only. Skips the page's H1 title, which is per-page
    (a detection's '# T<id> - <name>', an ADR's '# NNNN - slug') and is NOT a shared
    'required section' - counting it would false-flag every templated page as missing
    the placeholder title. Used by the ADR + template-section conformance checks;
    anchor resolution keeps _heading_slugs so a link may still target an H1."""
    slugs = set()
    for _, line in _content_lines(text):
        m = re.match(r"^#{2,6}\s+(.*)$", line)
        if m:
            slugs.add(_slugify(m.group(1)))
    return slugs


def run(root: Path) -> list[Finding]:
    return []


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    findings = run(root)
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"[{f.check}] {loc}  {f.message}")
    print(f"\n{len(findings)} finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
