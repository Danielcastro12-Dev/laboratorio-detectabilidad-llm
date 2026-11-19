from pathlib import Path

from llm_lab.execution.sandbox_runner import run_in_sandbox


def test_cannot_read_host_env_file(tmp_path: Path) -> None:
    src = tmp_path / "main.py"
    src.write_text("from pathlib import Path; print(Path('/host/.env').read_text())\n")
    result = run_in_sandbox(src)
    assert result.return_code != 0
    assert "/host/.env" not in result.stdout


def test_cannot_reach_external_network(tmp_path: Path) -> None:
    src = tmp_path / "main.py"
    src.write_text(
        "import socket\n"
        "s = socket.socket(); s.settimeout(2)\n"
        "s.connect(('1.1.1.1', 53))\n"
    )
    result = run_in_sandbox(src)
    assert result.return_code != 0
