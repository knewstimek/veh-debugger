"""Bounded native fault injection against the production PipeClient."""
import subprocess
from pathlib import Path

from build_paths import RELEASE


def test_write_completion_race():
    result = subprocess.run([str(Path(RELEASE) / "ipc_transport_regression.exe")],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS pipe write-completion race" in result.stdout
