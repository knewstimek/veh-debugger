[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

function Assert-Match {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if (-not (Select-String -LiteralPath $Path -Pattern $Pattern -Quiet)) {
        throw "$Description is not synchronized to $Version in $Path"
    }
}

Push-Location $repoRoot
try {
    $escapedVersion = [regex]::Escape($Version)
    Assert-Match 'CMakeLists.txt' "project\(VEHDebugger VERSION $escapedVersion LANGUAGES CXX\)" 'CMake project version'
    Assert-Match 'src\mcp\mcp_server.cpp' "\{`"version`", `"$escapedVersion`"\}" 'MCP server version'
    Assert-Match 'extension\CHANGELOG.md' "^## $escapedVersion - \d{4}-\d{2}-\d{2}$" 'Changelog release heading'

    $package = Get-Content -LiteralPath 'extension\package.json' -Raw | ConvertFrom-Json
    if ($package.version -ne $Version) {
        throw "Extension package version is not synchronized to $Version"
    }
    # Windows PowerShell 5 ConvertFrom-Json rejects package-lock's empty-string
    # root package key, so verify both root version entries in the raw JSON.
    $lockText = Get-Content -LiteralPath 'extension\package-lock.json' -Raw
    $lockVersionPattern = "`"version`"\s*:\s*`"$escapedVersion`""
    if ([regex]::Matches($lockText, $lockVersionPattern).Count -lt 2) {
        throw "Both extension lockfile versions must equal $Version"
    }

    if ($ValidateOnly) {
        Write-Host "Release metadata is synchronized to $Version."
        return
    }

    if (-not (Test-Path -LiteralPath 'build\CMakeCache.txt')) {
        Invoke-Checked 'cmake' @('-B', 'build', '-G', 'Visual Studio 17 2022', '-A', 'x64')
    }
    if (-not (Test-Path -LiteralPath 'build32\CMakeCache.txt')) {
        Invoke-Checked 'cmake' @('-B', 'build32', '-G', 'Visual Studio 17 2022', '-A', 'Win32')
    }
    Invoke-Checked 'cmake' @('--build', 'build', '--config', 'Release')
    Invoke-Checked 'cmake' @('--build', 'build32', '--config', 'Release', '--target', 'veh-debugger')

    $extensionBin = Join-Path $repoRoot 'extension\bin'
    New-Item -ItemType Directory -Path $extensionBin -Force | Out-Null
    $artifacts = @(
        @{ Source = 'build\bin\Release\veh-debug-adapter.exe'; Name = 'veh-debug-adapter.exe' },
        @{ Source = 'build\bin\Release\veh-mcp-server.exe'; Name = 'veh-mcp-server.exe' },
        @{ Source = 'build\bin\Release\vcruntime_net.dll'; Name = 'vcruntime_net.dll' },
        @{ Source = 'build32\bin\Release\vcruntime_net32.dll'; Name = 'vcruntime_net32.dll' }
    )
    foreach ($artifact in $artifacts) {
        if (-not (Test-Path -LiteralPath $artifact.Source)) {
            throw "Missing release artifact: $($artifact.Source)"
        }
        $destination = Join-Path $extensionBin $artifact.Name
        Copy-Item -LiteralPath $artifact.Source -Destination $destination -Force
        $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.Source).Hash
        $destinationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash
        if ($sourceHash -ne $destinationHash) {
            throw "Hash mismatch after copying $($artifact.Name)"
        }
    }

    Push-Location 'extension'
    try {
        Invoke-Checked 'npm.cmd' @('ci')
        Invoke-Checked 'npm.cmd' @('run', 'compile')
        $vsixName = "veh-debugger-$Version.vsix"
        Invoke-Checked 'npx.cmd' @('@vscode/vsce', 'package', '--no-git-tag-version', '--out', $vsixName)
    }
    finally {
        Pop-Location
    }

    $zipPath = Join-Path $repoRoot "extension\veh-debugger-$Version-bin.zip"
    $zipInputs = $artifacts | ForEach-Object { Join-Path $extensionBin $_.Name }
    Compress-Archive -LiteralPath $zipInputs -DestinationPath $zipPath -Force

    Write-Host "Prepared release assets:"
    Write-Host "  extension\$vsixName"
    Write-Host "  extension\veh-debugger-$Version-bin.zip"
    Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repoRoot "extension\$vsixName"), $zipPath |
        Format-Table -AutoSize
}
finally {
    Pop-Location
}
