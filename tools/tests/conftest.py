from pathlib import Path
import pytest


class _Repo(type(Path())):
    """A tmp Path carrying a .write(rel, content) helper for building fixture trees.
    We subclass the concrete Path class and add a method rather than assigning
    `tmp_path.write = ...`, which raises because pathlib.Path uses __slots__ and
    forbids attribute assignment. Path subclassing is supported on Python 3.12+;
    if the runtime is older and _Repo(...) fails to construct, fall back to a
    separate `write` fixture and pass both `repo` and `write` into each test.
    """

    def write(self, rel: str, content: str = "") -> Path:
        p = Path(self) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p


@pytest.fixture
def repo(tmp_path: Path) -> _Repo:
    """A minimal fake repo tree. Build files with repo.write('rel/path.md', 'body')."""
    return _Repo(str(tmp_path))
