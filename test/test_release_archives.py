"""Release archive checks reject backup and undeclared runtime files."""
from pathlib import Path
import subprocess
import tempfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = [
    "veh-debug-adapter.exe", "veh-mcp-server.exe", "veh-remote-runner.exe",
    "vcruntime_net.dll", "vcruntime_net32.dll",
]


def inspect_archives(extra=None):
    with tempfile.TemporaryDirectory(prefix="veh-release-archives-") as directory:
        root = Path(directory)
        extension = root / "extension"
        extension.mkdir()
        with zipfile.ZipFile(extension / "veh-debugger-0.0.0-bin.zip", "w") as archive:
            for name in RUNTIME_FILES:
                archive.writestr(name, b"synthetic runtime")
        with zipfile.ZipFile(extension / "veh-debugger-0.0.0.vsix", "w") as archive:
            for name in RUNTIME_FILES:
                archive.writestr("extension/bin/" + name, b"synthetic runtime")
            archive.writestr("extension/package.json", "{}")
            if extra:
                archive.writestr("extension/bin/" + extra, b"not a release binary")
        verifier = root / "verify.ps1"
        verifier.write_text(
            "param([string]$Source,[string]$FixtureRoot)\n"
            "$ErrorActionPreference='Stop'\n"
            "$tokens=$null;$errors=$null\n"
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)\n"
            "if($errors.Count){throw 'Release script parse error'}\n"
            "$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-Archives'},$true)\n"
            "if($null -eq $function){throw 'Missing archive validator'}\n"
            "Invoke-Expression $function.Extent.Text\n"
            "$repoRoot=$FixtureRoot;$Version='0.0.0'\n"
            "Assert-Archives | Out-Null\n",
            encoding="utf-8",
        )
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(verifier),
             "-Source", str(ROOT / "scripts/release.ps1"), "-FixtureRoot", str(root)],
            capture_output=True, timeout=20,
        )


def test_declared_release_archives_are_accepted():
    result = inspect_archives()
    assert result.returncode == 0, (result.stdout + result.stderr)[-2000:]


@pytest.mark.parametrize("extra", [
    "old_veh-mcp-server_20260101_000000.exe",
    "vcruntime_net_old_deadbeef.dll",
    "nested/sidecar.bin",
], ids=["backup-exe", "backup-dll", "undeclared-file"])
def test_vsix_rejects_undeclared_runtime_files(extra):
    result = inspect_archives(extra)
    assert result.returncode != 0, "VSIX accepted an undeclared runtime file: " + extra
    assert b"five declared release files" in result.stderr, result.stderr[-2000:]
