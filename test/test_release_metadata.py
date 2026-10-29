"""Exercise release metadata preparation in isolated LF and CRLF repositories."""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_metadata_preparation_is_idempotent(newline):
    with tempfile.TemporaryDirectory(prefix="veh-release-metadata-") as directory:
        root = Path(directory)
        def write(relative, text):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text.replace("\n", newline).encode("utf-8"))
        for script in ("release.ps1", "prepare-release.ps1"):
            (root / "scripts").mkdir(exist_ok=True)
            shutil.copyfile(ROOT / "scripts" / script, root / "scripts" / script)
        write(".gitattributes", "* text eol=" + ("crlf" if newline == "\r\n" else "lf") + "\n")
        write("CMakeLists.txt", "project(VEHDebugger VERSION 1.2.1 LANGUAGES CXX)\n")
        write("src/mcp/mcp_server.cpp", '{"version", "1.2.1"}\n')
        write("extension/package.json", '{\n  "version": "1.2.1",\n  "name": "release-fixture"\n}\n')
        write("extension/package-lock.json", '{\n  "version": "1.2.1",\n  "packages": {\n    "": {\n      "version": "1.2.1",\n      "name": "release-fixture"\n    },\n    "dependency": {\n      "version": "8.7.6",\n      "name": "dependency"\n    }\n  }\n}\n')
        write("extension/CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n### Fixed\n- Synthetic fix.\n\n## 1.2.1 - 2026-01-01\n\n- Previous.\n")
        for arguments in (["git", "init", "--quiet"], ["git", "-c", "core.autocrlf=false", "add", "."]):
            subprocess.run(arguments, cwd=root, check=True, capture_output=True, timeout=10)
        command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                   "scripts/release.ps1", "-Version", "1.2.2", "-ReleaseDate", "2026-01-02", "-MetadataOnly"]
        def prepare():
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=25)
            assert result.returncode == 0, (result.stdout + result.stderr)[-2500:]
        prepare()
        package = json.loads((root / "extension/package.json").read_text(encoding="utf-8"))
        lock = json.loads((root / "extension/package-lock.json").read_text(encoding="utf-8"))
        assert package["version"] == lock["version"] == lock["packages"][""]["version"] == "1.2.2"
        assert lock["packages"]["dependency"]["version"] == "8.7.6"
        paths = ["CMakeLists.txt", "src/mcp/mcp_server.cpp", "extension/package.json",
                 "extension/package-lock.json", "extension/CHANGELOG.md", "docs/releases/v1.2.2.md"]
        before = {path: (root / path).read_bytes() for path in paths}
        prepare()
        assert before == {path: (root / path).read_bytes() for path in paths}
        assert before["extension/CHANGELOG.md"].count(b"## 1.2.2 - 2026-01-02") == 1
        assert newline.encode() in before["extension/package.json"]
