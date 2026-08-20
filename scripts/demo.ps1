$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$OutDir = Join-Path ".tmp" "demo"
New-Item -ItemType Directory -Force $OutDir | Out-Null

if (-not $env:UV_CACHE_DIR) {
    $env:UV_CACHE_DIR = Join-Path $Root ".uv-cache"
}

$UvCommand = Get-Command uv -ErrorAction SilentlyContinue
if ($null -ne $UvCommand) {
    $Uv = $UvCommand.Source
}
else {
    $FallbackUv = Join-Path $env:USERPROFILE ".local\bin\uv.exe"
    if (Test-Path -LiteralPath $FallbackUv) {
        $Uv = $FallbackUv
    }
    else {
        throw "uv was not found on PATH. Install uv or add it to PATH."
    }
}

function Invoke-Demo {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [int] $ExpectedExitCode,
        [Parameter(Mandatory = $true)]
        [scriptblock] $Command
    )

    Write-Host ""
    Write-Host "== $Name =="
    & $Command
    $Status = $LASTEXITCODE
    if ($null -eq $Status) {
        $Status = 0
    }
    Write-Host "exit code: $Status (expected $ExpectedExitCode)"
    if ($Status -ne $ExpectedExitCode) {
        throw "Unexpected exit code for $Name"
    }
}

Invoke-Demo "safe application" 0 {
    & $Uv run piiflow scan examples/safe_app
}

Invoke-Demo "vulnerable application" 1 {
    & $Uv run piiflow scan examples/vulnerable_app
}

Invoke-Demo "compliant redacted email policy flow" 0 {
    & $Uv run piiflow scan examples/policy_apps/redacted_email.py --policy examples/policies/sanitized_email.yml
}

Invoke-Demo "wrong sanitizer policy violation" 1 {
    & $Uv run piiflow scan examples/policy_apps/wrong_email_sanitizer.py --policy examples/policies/sanitized_email.yml
}

Invoke-Demo "local financial allow rule" 0 {
    & $Uv run piiflow scan examples/policy_apps/local_financial.py --config examples/policy_apps/local_rules.yml --policy examples/policies/local_model.yml
}

$JsonOutput = Join-Path $OutDir "redacted_email.json"
Invoke-Demo "JSON output" 0 {
    & $Uv run piiflow scan examples/policy_apps/redacted_email.py --policy examples/policies/sanitized_email.yml --format json --output $JsonOutput
}

Write-Host ""
Write-Host "Demo complete. JSON output: $JsonOutput"
