[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$ReleaseDate = (Get-Date -Format 'yyyy-MM-dd'),

    [switch]$MetadataOnly,
    [switch]$SkipTests,
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$logDirectory = Join-Path $repoRoot "build\release-logs\$Version"
$releaseNote = Join-Path $repoRoot "docs\releases\v$Version.md"

function Read-Utf8File {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Replace-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Replacement,
        [int]$ExpectedCount = 1
    )
    $text = Read-Utf8File $Path
    $matches = [regex]::Matches($text, $Pattern)
    if ($matches.Count -ne $ExpectedCount) {
        throw "Expected $ExpectedCount version field(s) in $Path, found $($matches.Count)."
    }
    Write-Utf8File $Path ([regex]::Replace($text, $Pattern, $Replacement))
}

function Set-ReleaseMetadata {
    Replace-Checked (Join-Path $repoRoot 'CMakeLists.txt') `
        'project\(VEHDebugger VERSION \d+\.\d+\.\d+ LANGUAGES CXX\)' `
        "project(VEHDebugger VERSION $Version LANGUAGES CXX)"
    Replace-Checked (Join-Path $repoRoot 'src\mcp\mcp_server.cpp') `
        '\{"version", "\d+\.\d+\.\d+"\}' `
        "{`"version`", `"$Version`"}"
    Replace-Checked (Join-Path $repoRoot 'extension\package.json') `
        '(?m)^(  "version": ")\d+\.\d+\.\d+(",)$' `
        "`${1}$Version`${2}"

    $lockPath = Join-Path $repoRoot 'extension\package-lock.json'
    $lockText = Read-Utf8File $lockPath
    $lockPattern = '(?m)^(\s*"version": ")\d+\.\d+\.\d+(",)$'
    $lockMatches = [regex]::Matches($lockText, $lockPattern)
    if ($lockMatches.Count -lt 2) {
        throw "Expected at least two package-lock version fields, found $($lockMatches.Count)."
    }
    $lockIndex = 0
    $updatedLock = [regex]::Replace($lockText, $lockPattern, {
        param($match)
        $script:lockIndex++
        if ($script:lockIndex -le 2) {
            return $match.Groups[1].Value + $Version + $match.Groups[2].Value
        }
        return $match.Value
    })
    Write-Utf8File $lockPath $updatedLock

    $changelogPath = Join-Path $repoRoot 'extension\CHANGELOG.md'
    $changelog = Read-Utf8File $changelogPath
    $releaseHeading = "## $Version - $ReleaseDate"
    # \r?: in a CRLF checkout .NET's multiline $ does not match before \r, which
    # re-inserted the heading on every run and dirtied the tree before -Publish.
    if ($changelog -notmatch "(?m)^## $([regex]::Escape($Version)) - \d{4}-\d{2}-\d{2}\r?$") {
        $newline = if ($changelog.Contains("`r`n")) { "`r`n" } else { "`n" }
        $unreleasedHeader = "## Unreleased$newline$newline"
        if (-not $changelog.Contains($unreleasedHeader)) {
            throw 'CHANGELOG.md does not contain the expected Unreleased header.'
        }
        $changelog = $changelog.Replace(
            $unreleasedHeader,
            "## Unreleased$newline$newline$releaseHeading$newline$newline"
        )
        Write-Utf8File $changelogPath $changelog
    }

    if (-not (Test-Path -LiteralPath $releaseNote)) {
        $changelog = Read-Utf8File $changelogPath
        $sectionPattern = "(?ms)^## $([regex]::Escape($Version)) - \d{4}-\d{2}-\d{2}\s*\r?\n(?<body>.*?)(?=^## )"
        $section = [regex]::Match($changelog, $sectionPattern)
        if (-not $section.Success) {
            throw "Could not extract the $Version release section from CHANGELOG.md."
        }
        $noteText = "# VEH Debugger v$Version`r`n`r`n" + $section.Groups['body'].Value.Trim() + "`r`n"
        Write-Utf8File $releaseNote $noteText
    }
}

function Invoke-Logged {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [hashtable]$Environment = @{}
    )
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $logPath = Join-Path $logDirectory "$Name.log"
    $saved = @{}
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        foreach ($entry in $Environment.GetEnumerator()) {
            $saved[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
            [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
        }
        # Windows PowerShell promotes native stderr to NativeCommandError when
        # ErrorActionPreference is Stop. Build warnings belong in the log and
        # the native exit code remains the authoritative result.
        $ErrorActionPreference = 'Continue'
        & $Program @Arguments *> $logPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
        foreach ($entry in $Environment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $saved[$entry.Key], 'Process')
        }
    }
    if ($exitCode -ne 0) {
        Write-Host "[$Name] failed with exit code $exitCode. Last log lines:" -ForegroundColor Red
        Get-Content -LiteralPath $logPath -Tail 30
        throw "$Name failed. Full log: $logPath"
    }
    Write-Host "[$Name] passed" -ForegroundColor Green
}

function Test-NativeSuccess {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Program @Arguments *> $null
        return $LASTEXITCODE -eq 0
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
}

function Assert-PublicReleaseInputs {
    $diffCheck = @(git diff --check)
    if ($LASTEXITCODE -ne 0 -or $diffCheck.Count -ne 0) {
        throw "git diff --check failed:`n$($diffCheck -join "`n")"
    }

    $privacyPatterns = @(
        '([A-Za-z]:\\Users\\[^\\/[:space:]]+|/home/[^/[:space:]]+)',
        '(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)',
        'D:\\News\\'
    )
    foreach ($pattern in $privacyPatterns) {
        $findings = @(git grep -n -I -E -- $pattern -- `
            ':!extension/package-lock.json' ':!scripts/release.ps1' 2>$null)
        if ($LASTEXITCODE -eq 0 -and $findings.Count -ne 0) {
            throw "Public-release privacy scan found tracked content matching $pattern. Review it before release."
        }
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
            throw "git grep privacy scan failed with exit code $LASTEXITCODE."
        }
    }
}

function Assert-Archives {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $vsixPath = Join-Path $repoRoot "extension\veh-debugger-$Version.vsix"
    $zipPath = Join-Path $repoRoot "extension\veh-debugger-$Version-bin.zip"
    foreach ($path in @($vsixPath, $zipPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Missing release artifact: $path"
        }
    }

    $binaryArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $actual = @($binaryArchive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        $expected = @('vcruntime_net.dll', 'vcruntime_net32.dll', 'veh-debug-adapter.exe', 'veh-mcp-server.exe') | Sort-Object
        if (($actual -join "`n") -ne ($expected -join "`n")) {
            throw "Binary ZIP contents differ from the four declared release files: $($actual -join ', ')"
        }
    }
    finally {
        $binaryArchive.Dispose()
    }

    $vsixArchive = [System.IO.Compression.ZipFile]::OpenRead($vsixPath)
    try {
        $unsafe = @($vsixArchive.Entries | Where-Object {
            $_.FullName -match '(?i)(^|/)(test|challenges)(/|$)|\.log$|[A-Za-z]:|(^|/)\.env($|\.)'
        })
        if ($unsafe.Count -ne 0) {
            throw "VSIX contains release-unsafe entries: $($unsafe.FullName -join ', ')"
        }
    }
    finally {
        $vsixArchive.Dispose()
    }

    Get-FileHash -Algorithm SHA256 -LiteralPath $vsixPath, $zipPath |
        Select-Object Path, Hash
}

function Invoke-ReleaseTests {
    $tests = @(
        'test/test_step.py',
        'test/test_stepin.py',
        'test/test_bp_masking.py',
        'test/test_batch.py',
        'test/test_mcp_launch.py',
        'test/test_mcp_deep.py',
        'test/test_mcp_new_features.py',
        'test/test_trace_inaccessible_range.py',
        'test/test_trace_code_stream_failure.py',
        'test/test_mcp_profiles.py',
        'test/test_trace_heartbeat_long.py'
    )
    foreach ($test in $tests) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($test)
        Invoke-Logged $name 'py' @('-3', $test)
    }
    Invoke-Logged 'trace-parity-x64-x86' 'py' @(
        '-3', 'tools/run_trace_parity.py',
        '--build-dir', 'build',
        '--build-dir', 'build32'
    )
}

function Publish-Release {
    if ($SkipTests) {
        throw '-SkipTests cannot be combined with -Publish.'
    }
    $status = @(git status --porcelain)
    if ($status.Count -ne 0) {
        throw 'Publishing requires a completely clean worktree, including no untracked files.'
    }
    git ls-files --error-unmatch -- "docs/releases/v$Version.md" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Release note docs/releases/v$Version.md must be tracked before publishing."
    }
    $upstream = git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null
    if (-not $upstream) {
        throw 'The current branch has no upstream.'
    }
    git fetch --quiet origin
    if ($LASTEXITCODE -ne 0) {
        throw 'git fetch failed.'
    }
    if ((git rev-parse HEAD) -ne (git rev-parse $upstream)) {
        throw "HEAD must exactly match $upstream before publishing."
    }

    $tag = "v$Version"
    if (Test-NativeSuccess 'git' @('rev-parse', '-q', '--verify', "refs/tags/$tag")) {
        if ((git cat-file -t $tag) -ne 'tag' -or (git rev-list -n 1 $tag) -ne (git rev-parse HEAD)) {
            throw "$tag exists but is not an annotated tag for HEAD."
        }
    }
    elseif ($PSCmdlet.ShouldProcess($tag, 'Create and push annotated release tag')) {
        git tag -a $tag -m "VEH Debugger $tag"
        if ($LASTEXITCODE -ne 0) { throw "Failed to create $tag." }
        git push origin "refs/tags/$tag"
        if ($LASTEXITCODE -ne 0) { throw "Failed to push $tag." }
    }

    $vsixPath = Join-Path $repoRoot "extension\veh-debugger-$Version.vsix"
    $zipPath = Join-Path $repoRoot "extension\veh-debugger-$Version-bin.zip"
    if ($PSCmdlet.ShouldProcess($tag, 'Create or repair the GitHub Release and upload reviewed assets')) {
        if (Test-NativeSuccess 'gh' @('release', 'view', $tag)) {
            gh release upload $tag $vsixPath $zipPath --clobber
            if ($LASTEXITCODE -ne 0) { throw 'GitHub Release asset repair failed.' }
            gh release edit $tag --title $tag --notes-file $releaseNote --latest
        }
        else {
            gh release create $tag $vsixPath $zipPath --verify-tag --title $tag --notes-file $releaseNote --latest
        }
        if ($LASTEXITCODE -ne 0) { throw 'GitHub Release publication failed.' }

        $temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $verifyDirectory = Join-Path $temporaryRoot ("veh-release-verify-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $verifyDirectory | Out-Null
        try {
            gh release download $tag --dir $verifyDirectory
            if ($LASTEXITCODE -ne 0) { throw 'GitHub Release asset download verification failed.' }
            foreach ($localPath in @($vsixPath, $zipPath)) {
                $downloadedPath = Join-Path $verifyDirectory ([System.IO.Path]::GetFileName($localPath))
                if (-not (Test-Path -LiteralPath $downloadedPath)) {
                    throw "Published asset is missing: $downloadedPath"
                }
                $localHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $localPath).Hash
                $downloadedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $downloadedPath).Hash
                if ($localHash -ne $downloadedHash) {
                    throw "Published asset hash mismatch: $downloadedPath"
                }
            }
            $release = gh release view $tag --json tagName,name,isDraft,isPrerelease,assets | ConvertFrom-Json
            $assetNames = @($release.assets | ForEach-Object { $_.name } | Sort-Object)
            $expectedNames = @([System.IO.Path]::GetFileName($vsixPath), [System.IO.Path]::GetFileName($zipPath)) | Sort-Object
            if ($release.tagName -ne $tag -or $release.name -ne $tag -or $release.isDraft -or $release.isPrerelease -or
                ($assetNames -join "`n") -ne ($expectedNames -join "`n")) {
                throw 'Published GitHub Release metadata or asset set is incorrect.'
            }
        }
        finally {
            $resolvedVerifyDirectory = [System.IO.Path]::GetFullPath($verifyDirectory)
            if ($resolvedVerifyDirectory.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
                [System.IO.Path]::GetFileName($resolvedVerifyDirectory).StartsWith('veh-release-verify-')) {
                Remove-Item -LiteralPath $resolvedVerifyDirectory -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    if ($PSCmdlet.ShouldProcess($vsixPath, 'Publish the reviewed VSIX to Marketplace')) {
        $marketplace = npx.cmd --yes '@vscode/vsce' show knewstimek.veh-debugger --json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Marketplace pre-publication status check failed.' }
        if ($marketplace.versions[0].version -ne $Version) {
            npx.cmd --yes '@vscode/vsce' publish --packagePath $vsixPath
            if ($LASTEXITCODE -ne 0) { throw 'Marketplace publication failed.' }
            for ($attempt = 1; $attempt -le 60; $attempt++) {
                $marketplace = npx.cmd --yes '@vscode/vsce' show knewstimek.veh-debugger --json | ConvertFrom-Json
                if ($LASTEXITCODE -ne 0) { throw 'Marketplace post-publication status check failed.' }
                if ($marketplace.versions[0].version -eq $Version) { break }
                if ($attempt -lt 60) { Start-Sleep -Seconds 15 }
            }
        }
        if ($marketplace.versions[0].version -ne $Version) {
            throw "Marketplace latest version is $($marketplace.versions[0].version), expected $Version."
        }
    }
}

Push-Location $repoRoot
try {
    if (-not (Test-Path -LiteralPath '.git')) {
        throw 'release.ps1 must run from the VEH Debugger Git worktree.'
    }

    Set-ReleaseMetadata
    Assert-PublicReleaseInputs
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $PSScriptRoot 'prepare-release.ps1') -Version $Version -ValidateOnly
    if ($LASTEXITCODE -ne 0) {
        throw 'Release metadata validation failed.'
    }

    if ($MetadataOnly) {
        Write-Host "Release metadata and notes prepared for $Version."
        return
    }

    Invoke-Logged 'build-and-package' 'powershell.exe' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $PSScriptRoot 'prepare-release.ps1'), '-Version', $Version
    )
    if (-not $SkipTests) {
        Invoke-ReleaseTests
    }
    $hashes = Assert-Archives
    $hashes | Format-Table -AutoSize

    if ($Publish) {
        Publish-Release
    }
    else {
        $untracked = @(git status --porcelain | Where-Object { $_ -like '??*' })
        if ($untracked.Count -ne 0) {
            Write-Warning "$($untracked.Count) untracked path(s) remain. Publishing will refuse this worktree."
        }
        Write-Host "Release candidate $Version is prepared locally. Review, commit, and push before using -Publish."
    }
}
finally {
    Pop-Location
}
