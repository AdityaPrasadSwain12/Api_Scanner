param([switch]$Force)
$ErrorActionPreference = "Stop"

$target = Join-Path (Split-Path $PSScriptRoot -Parent) ".env"
if ((Test-Path -LiteralPath $target) -and -not $Force) {
    throw ".env already exists. Use -Force to replace it."
}
function New-RandomUrlSafe([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    # RandomNumberGenerator.Fill is unavailable in Windows PowerShell 5.1's
    # .NET Framework runtime. The instance API works there and in PowerShell 7.
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($buffer)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($buffer).Replace('+','-').Replace('/','_')
}
$content = @"
ENVIRONMENT=development
POSTGRES_PASSWORD=$(New-RandomUrlSafe)
SCANNER_API_KEY=$(New-RandomUrlSafe)
SECRET_ENCRYPTION_KEY=$(New-RandomUrlSafe)
ENGINE_RUNNER_TOKEN=$(New-RandomUrlSafe)
ZAP_API_KEY=$(New-RandomUrlSafe)
ALLOWED_TARGETS=vulnerable-api,host.docker.internal
ALLOW_PRIVATE_TARGETS=true
TARGET_SCOPE_MODE=deployment_allowlist
DASHBOARD_AUTH_MODE=api_key
"@
[IO.File]::WriteAllText($target, $content, [Text.UTF8Encoding]::new($false))
Write-Host "Created $target"
