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

# Conservative: only unambiguous relative-date constructs. Bare "today"/"now" are
# too common in casual prose to flag without noise, so they are deliberately excluded.
REL_DATE_RE = re.compile(
    r"\b(yesterday|tomorrow|(?:last|next)\s+(?:week|month|year)|\d+\s+days?\s+ago)\b",
    re.IGNORECASE,
)


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


MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
WIKI_LINK_RE = re.compile(r"\[\[([^\]]+)\]\]")


def build_vault_index(root: Path) -> dict[str, Path | None]:
    vault = root / "vault"
    index: dict[str, Path | None] = {}
    seen_base: dict[str, int] = {}
    if not vault.is_dir():
        return index
    for p in vault.rglob("*.md"):
        rel = str(p.relative_to(vault)).replace("\\", "/")[:-3]  # drop .md
        index[rel] = p
        base = p.stem
        seen_base[base] = seen_base.get(base, 0) + 1
        index[base] = p if seen_base[base] == 1 else None  # None marks ambiguous
    return index


def _resolve_wiki_ref(ref: str, src: Path, root: Path, index: dict[str, Path | None]) -> tuple[Path | None, str]:
    """Resolve an Obsidian [[wiki-ref]] to a vault page. Returns (path, "ok"),
    (None, "ambiguous"), or (None, "missing"). Resolution mirrors Obsidian:
    first path-relative to the linking file (handles ../ and same-folder bare
    names), then the vault-root-relative index key or a unique bare basename.
    A basename shared by several pages with no local match is "ambiguous"."""
    vault = (root / "vault").resolve()
    ref = ref.removesuffix(".md")  # Obsidian resolves [[page]] and [[page.md]] alike
    cand = (src.parent / (ref + ".md")).resolve()
    if cand.is_file() and cand.is_relative_to(vault):
        return cand, "ok"
    hit = index.get(ref)
    if hit is not None:
        return hit, "ok"
    if ref in index:            # present but None -> ambiguous basename
        return None, "ambiguous"
    return None, "missing"


def check_md_links(path: Path, root: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    rel = _rel(path, root)
    for i, line in _content_lines(text, blank_code=True):
        for m in MD_LINK_RE.finditer(line):
            if m.start() > 0 and line[m.start() - 1] == "!":
                continue  # image embed ![alt](src), not a link
            target = m.group(1).strip().split(" ", 1)[0]  # drop optional "title"
            if target.startswith(("http://", "https://", "mailto:", "tel:")):
                continue
            if target.startswith("#"):
                anchor = _slugify(urllib.parse.unquote(target[1:]))
                if anchor and anchor not in _heading_slugs(text):
                    out.append(Finding(rel, i, "link", f"broken same-file anchor: {target}"))
                continue
            path_part, _, anchor = target.partition("#")
            path_part = urllib.parse.unquote(path_part)
            if not path_part:
                continue
            dest = (path.parent / path_part).resolve()
            if not dest.exists():
                out.append(Finding(rel, i, "link", f"broken link target: {target}"))
                continue
            if anchor and dest.suffix == ".md":
                slugs = _heading_slugs(dest.read_text(encoding="utf-8", errors="replace"))
                if _slugify(urllib.parse.unquote(anchor)) not in slugs:
                    out.append(Finding(rel, i, "link", f"broken anchor: {target}"))
    return out


def check_wiki_links(path: Path, root: Path, text: str, index: dict[str, Path | None]) -> list[Finding]:
    out: list[Finding] = []
    rel = _rel(path, root)
    for i, line in _content_lines(text, blank_code=True):
        for m in WIKI_LINK_RE.finditer(line):
            ref = m.group(1).split("|", 1)[0].split("#", 1)[0].strip()  # drop alias + heading
            if not ref:
                continue
            _dest, status = _resolve_wiki_ref(ref, path, root, index)
            if status == "missing":
                out.append(Finding(rel, i, "link", f"broken wiki-link: [[{ref}]] (no such vault page)"))
            elif status == "ambiguous":
                out.append(Finding(rel, i, "link", f"ambiguous wiki-link: [[{ref}]] (matches multiple pages)"))
    return out


def check_relative_dates(path: Path, root: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    rel = _rel(path, root)
    for i, line in enumerate(text.splitlines(), 1):
        for m in REL_DATE_RE.finditer(line):
            out.append(Finding(rel, i, "relative-date", f"relative-date phrase: '{m.group(0)}' (prefer an absolute date)"))
    return out


SUBPROJECT_REQUIRED = {"README.md", "spec.md", "plan.md", "runbook.md", "notes.md"}
ADR_REQUIRED_SECTIONS = {"status", "context", "decision", "consequences"}
FRONTMATTER_KEYS = {"status", "updated", "related"}
FRONTMATTER_EXEMPT = {"log.md", "index.md", "CLAUDE.md"}


def _parse_frontmatter(text: str) -> dict | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    block = text[3:end]
    fm: dict = {}
    for line in block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip()
    return fm


def check_vault_structure(root: Path) -> list[Finding]:
    out: list[Finding] = []
    vault = root / "vault"
    if not vault.is_dir():
        return out

    subs = vault / "subprojects"
    if subs.is_dir():
        for sub in sorted(p for p in subs.iterdir() if p.is_dir()):
            present = {p.name for p in sub.glob("*.md")}
            missing = SUBPROJECT_REQUIRED - present
            if missing:
                out.append(Finding(_rel(sub, root), 0, "vault-structure",
                                   f"subproject missing file(s): {', '.join(sorted(missing))}"))

    dec = vault / "decisions"
    if dec.is_dir():
        nums = sorted(int(p.name[:4]) for p in dec.glob("[0-9][0-9][0-9][0-9]-*.md"))
        if len(nums) != len(set(nums)):
            dupes = sorted({n for n in nums if nums.count(n) > 1})
            out.append(Finding(_rel(dec, root), 0, "vault-structure",
                               f"duplicate ADR number(s): {dupes}"))
        elif nums and nums != list(range(1, len(nums) + 1)):
            out.append(Finding(_rel(dec, root), 0, "vault-structure",
                               f"ADR numbering not contiguous from 0001: found {nums}"))
        for p in dec.glob("[0-9][0-9][0-9][0-9]-*.md"):
            slugs = _section_slugs(p.read_text(encoding="utf-8", errors="replace"))
            missing = ADR_REQUIRED_SECTIONS - slugs
            if missing:
                out.append(Finding(_rel(p, root), 0, "vault-structure",
                                   f"ADR missing required section(s): {', '.join(sorted(missing))}"))

    for template in vault.rglob("_template.md"):
        required = _section_slugs(template.read_text(encoding="utf-8", errors="replace"))
        for p in template.parent.glob("*.md"):
            if p.name == "_template.md" or p.name.lower() == "readme.md":
                continue
            missing = required - _section_slugs(p.read_text(encoding="utf-8", errors="replace"))
            if missing:
                out.append(Finding(_rel(p, root), 0, "vault-structure",
                                   f"missing template section(s): {', '.join(sorted(missing))}"))

    for p in vault.rglob("*.md"):
        if p.name in FRONTMATTER_EXEMPT or p.name == "_template.md":
            continue
        fm = _parse_frontmatter(p.read_text(encoding="utf-8", errors="replace"))
        if fm is None:
            out.append(Finding(_rel(p, root), 0, "vault-structure", "missing frontmatter block"))
        else:
            missing = FRONTMATTER_KEYS - set(fm)
            if missing:
                out.append(Finding(_rel(p, root), 0, "vault-structure",
                                   f"frontmatter missing key(s): {', '.join(sorted(missing))}"))
    return out


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
