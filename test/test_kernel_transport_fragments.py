"""Force production RSP reads across every framing boundary, without TCP timing."""
import subprocess
from pathlib import Path

from build_paths import RELEASE


def run():
    result = subprocess.run([str(Path(RELEASE) / "kernel_transport_regression.exe")],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS KD read fragmentation" in result.stdout, result.stdout
    print(result.stdout.strip())


if __name__ == "__main__":
    run()
