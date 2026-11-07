# Verification only. Never signs, imports certificates or changes trust/policy.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$CertificateSha256,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [Parameter(Mandatory=$true)][string]$ProductVersion,
    [Parameter(Mandatory=$true)][string]$FileVersion
)
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $Path
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected a regular signed PE file' }
$v = $item.VersionInfo
if ($v.ProductName -cne 'HopHarbor' -or $v.ProductVersion -cne $ProductVersion -or $v.FileVersion -cne $FileVersion) { throw 'Unexpected signed product metadata' }
$sig = Get-AuthenticodeSignature -LiteralPath $item.FullName
if ($sig.Status -ne 'Valid' -or !$sig.SignerCertificate -or !$sig.TimeStamperCertificate) { throw 'A valid timestamped Authenticode signature is required' }
$sha = [Security.Cryptography.SHA256]::Create()
try { $fingerprint = ([BitConverter]::ToString($sha.ComputeHash($sig.SignerCertificate.RawData))).Replace('-','') } finally { $sha.Dispose() }
if ($fingerprint -ine $CertificateSha256) { throw 'Publisher certificate differs from the approved certificate fingerprint' }
# Windows SDK tool, not an executable supplied in the returned signing artifact.
$tool = Get-Item -LiteralPath $SignTool
$toolSig = Get-AuthenticodeSignature -LiteralPath $tool.FullName
if ($tool.Name -ine 'signtool.exe' -or $toolSig.Status -ne 'Valid' -or !$toolSig.SignerCertificate -or $toolSig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') { throw 'Expected the authenticated Microsoft SDK SignTool' }
& $tool.FullName verify /pa /all /v /tw $item.FullName
if ($LASTEXITCODE -ne 0) { throw 'SignTool verification failed or returned warnings' }
