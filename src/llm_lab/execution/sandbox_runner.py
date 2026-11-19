from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time_ns
from typing import Final

DEFAULT_TIMEOUT: Final[int] = 5
DEFAULT_MEMORY_MB: Final[int] = 256
DEFAULT_PIDS_LIMIT: Final[int] = 32
IMAGE_TAG: Final[str] = "llm-lab-sandbox:v0.2"


@dataclass(frozen=True)
class RunResult:
    return_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


def _now_ms() -> int:
    return time_ns() // 1_000_000


def run_in_sandbox(
    source: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT,
    extra_files: dict[str, str] | None = None,
) -> RunResult:
    """Execute a single Python source file inside an isolated Docker container."""
    if not source.is_file():
        raise FileNotFoundError(f"Source file not found: {source}")

    with TemporaryDirectory(prefix="llm-lab-run-") as tmp:
        tmp_path = Path(tmp)
        tmp_path.chmod(0o777)
        script_path = tmp_path / "script.py"
        script_path.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

        if extra_files:
            for name, content in extra_files.items():
                (tmp_path / name).write_text(content, encoding="utf-8")

        cmd = [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--memory={DEFAULT_MEMORY_MB}m",
            f"--pids-limit={DEFAULT_PIDS_LIMIT}",
            "--user=1000:1000",
            "--workdir=/workspace/output",
            "--tmpfs=/tmp:noexec,nosuid,size=50m",
            "-v",
            f"{tmp_path.as_posix()}:/workspace/output:rw",
            IMAGE_TAG,
            "python",
            "/workspace/output/script.py",
        ]

        start_ms = _now_ms()
        stdout = ""
        stderr = ""
        return_code: int | None = None
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return_code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            _stdout = exc.stdout or ""
            _stderr = exc.stderr or ""
            stdout = _stdout if isinstance(_stdout, str) else _stdout.decode("utf-8", errors="replace")
            stderr = _stderr if isinstance(_stderr, str) else _stderr.decode("utf-8", errors="replace")
        end_ms = _now_ms()

        return RunResult(
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_ms=max(0, end_ms - start_ms),
        )
