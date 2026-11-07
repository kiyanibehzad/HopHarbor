# Future GitHub-hosted CI only. No installer or SDK is executed during preparation.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Sdk','Inno')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$ToolsRoot
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../docs/signing/tool-pins.json') -Raw | ConvertFrom-Json
if (!$env:GITHUB_ENV -or !$env:RUNNER_TEMP) { throw 'Expected a GitHub runner environment.' }
$root = [IO.Path]::GetFullPath($ToolsRoot)
$runnerRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd([char[]](92,47)) + [IO.Path]::DirectorySeparatorChar
if (!$root.StartsWith($runnerRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Keep tools inside the fresh runner temp scope.' }
if ($Mode -eq 'Sdk' -and (Test-Path -LiteralPath $root)) { throw 'Tool root must be new.' }
if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Tool root cannot be a reparse point.' }
New-Item -ItemType Directory -Path $root -Force | Out-Null
if ($Mode -eq 'Sdk') {
    $sdkDir = Join-Path $root 'sdk'
    $archive = Join-Path $root 'sdk.zip'
    if ((Test-Path -LiteralPath $sdkDir) -or (Test-Path -LiteralPath $archive)) { throw 'SDK paths must be new.' }
    Invoke-WebRequest -Uri $pins.dotnet_sdk.url -OutFile $archive
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA512).Hash
    if ($hash -ine $pins.dotnet_sdk.sha512) { throw 'SDK archive digest mismatch.' }
    Expand-Archive -LiteralPath $archive -DestinationPath $sdkDir
    $dotnet = Join-Path $sdkDir 'dotnet.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $dotnet
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') { throw 'Microsoft SDK executable verification failed.' }
    $env:DOTNET_ROOT = $sdkDir
    $env:DOTNET_MULTILEVEL_LOOKUP = '0'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $version = & $dotnet --version
    if ($LASTEXITCODE -ne 0 -or $version -cne $pins.dotnet_sdk.version) { throw 'SDK version mismatch.' }
    $env:DOTNET_EXE = $dotnet
    "DOTNET_EXE=$dotnet" | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
    "DOTNET_ROOT=$sdkDir" | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
    'DOTNET_MULTILEVEL_LOOKUP=0' | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
    'DOTNET_CLI_TELEMETRY_OPTOUT=1' | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
    @{ version=$version; sha512=$hash.ToLowerInvariant(); source=$pins.dotnet_sdk.url; executable_signature='Valid'; publisher=$signature.SignerCertificate.Subject } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'sdk-verification.json') -Encoding utf8
} else {
    $compilerHome = Join-Path $root 'inno'
    $installer = Join-Path $root 'innosetup.exe'
    if ((Test-Path -LiteralPath $compilerHome) -or (Test-Path -LiteralPath $installer)) { throw 'Inno paths must be new.' }
    Invoke-WebRequest -Uri $pins.inno.url -OutFile $installer
    $hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
    if ($hash -ine $pins.inno.sha256) { throw 'Inno installer digest mismatch.' }
    $install = Start-Process -FilePath $installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER','/PORTABLE=1','/NOICONS','/TASKS=',"/DIR=`"$compilerHome`"") -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw 'Pinned Inno setup failed.' }
    $iscc = Join-Path $compilerHome 'ISCC.exe'
    if (!(Test-Path -LiteralPath $iscc -PathType Leaf)) { throw 'ISCC missing.' }
    $version = & $iscc --version
    if ($LASTEXITCODE -ne 0 -or ($version -join ' ') -notmatch ('(?<![0-9])' + [regex]::Escape($pins.inno.version) + '(?![0-9])')) { throw 'Inno version mismatch.' }
    $env:ISCC = $iscc
    "ISCC=$iscc" | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
    @{ version=$pins.inno.version; sha256=$hash.ToLowerInvariant(); source=$pins.inno.url; actual_version_output=($version -join ' ') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'inno-verification.json') -Encoding utf8
}
