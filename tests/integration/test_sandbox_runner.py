from pathlib import Path

import pytest

from llm_lab.execution.sandbox_runner import run_in_sandbox


@pytest.fixture
def temp_source(tmp_path: Path) -> Path:
    return tmp_path


def test_benign_code_returns_zero(temp_source: Path) -> None:
    src = temp_source / "main.py"
    src.write_text("print('ok')\n", encoding="utf-8")
    result = run_in_sandbox(src)
    assert result.return_code == 0
    assert "ok" in result.stdout
    assert not result.timed_out


def test_network_is_blocked(temp_source: Path) -> None:
    src = temp_source / "main.py"
    src.write_text(
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(2)\n"
        "s.connect(('1.1.1.1', 53))\n",
        encoding="utf-8",
    )
    result = run_in_sandbox(src)
    assert result.return_code != 0
    assert "Network is unreachable" in result.stderr or "[Errno" in result.stderr


def test_host_paths_are_not_readable(temp_source: Path) -> None:
    src = temp_source / "main.py"
    src.write_text(
        "from pathlib import Path\n"
        "p = Path('/host/.env')\n"
        "print(p.read_text())\n",
        encoding="utf-8",
    )
    result = run_in_sandbox(src)
    assert result.return_code != 0


def test_infinite_loop_times_out(temp_source: Path) -> None:
    src = temp_source / "main.py"
    src.write_text("while True:\n    pass\n", encoding="utf-8")
    result = run_in_sandbox(src, timeout_seconds=2)
    assert result.timed_out
    assert result.return_code is None


def test_fork_bomb_is_limited(temp_source: Path) -> None:
    src = temp_source / "main.py"
    src.write_text(
        "import os\n"
        "for _ in range(100):\n"
        "    os.fork()\n",
        encoding="utf-8",
    )
    result = run_in_sandbox(src)
    assert result.return_code != 0 or "Resource temporarily unavailable" in result.stderr
