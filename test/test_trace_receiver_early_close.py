"""Force a real producer-close-before-connect race through production receivers."""
import subprocess
from pathlib import Path

from build_paths import RELEASE


def run():
    result = subprocess.run([str(Path(RELEASE) / "trace_receiver_early_close.exe")],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS early-close artifact receivers" in result.stdout, result.stdout
    print(result.stdout.strip())


if __name__ == "__main__":
    run()
