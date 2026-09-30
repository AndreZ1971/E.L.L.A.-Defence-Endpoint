<#
.SYNOPSIS
    Baut das EDEP-Modul für die PowerShell Gallery (optional signiert, optional veröffentlicht).

.DESCRIPTION
    1. Kopiert baseline/L1 nach out/EDEP (Ordnername = Modulname, wie Publish-Module verlangt).
    2. Prüft Manifest und Syntax aller Skripte.
    3. Signiert optional alle Skripte (-CertificateThumbprint), siehe Sign-EdepScripts.ps1.
    4. Veröffentlicht optional in der PowerShell Gallery (-Publish, API-Schlüssel aus $env:PSGALLERY_API_KEY).

.EXAMPLE
    .\tools\Build-EdepModule.ps1
.EXAMPLE
    .\tools\Build-EdepModule.ps1 -CertificateThumbprint 0123ABCD... -Publish -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$CertificateThumbprint,
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'baseline\L1'
$out = Join-Path $root 'out\EDEP'

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null

$manifest = Import-PowerShellDataFile (Join-Path $src 'EDEP.psd1')
foreach ($f in $manifest.FileList) {
    Copy-Item -LiteralPath (Join-Path $src $f) -Destination $out
}
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $out

# Syntax
$errors = 0
Get-ChildItem $out -Include *.ps1, *.psm1, *.psd1 -Recurse | ForEach-Object {
    $t = $null; $e = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$t, [ref]$e) | Out-Null
    foreach ($x in $e) { Write-Error "$($_.Name):$($x.Extent.StartLineNumber) $($x.Message)" -ErrorAction Continue; $errors++ }
}
if ($errors) { throw "$errors Syntaxfehler." }

$m = Test-ModuleManifest (Join-Path $out 'EDEP.psd1')
Write-Host "Modul $($m.Name) $($m.Version) gebaut: $out" -ForegroundColor Green

if ($CertificateThumbprint) {
    & (Join-Path $PSScriptRoot 'Sign-EdepScripts.ps1') -Path $out -CertificateThumbprint $CertificateThumbprint
}
elseif ($Publish) {
    throw 'Veröffentlichung nur signiert: -CertificateThumbprint angeben.'
}

if ($Publish) {
    if (-not $env:PSGALLERY_API_KEY) { throw 'Umgebungsvariable PSGALLERY_API_KEY fehlt.' }
    if ($PSCmdlet.ShouldProcess("PowerShell Gallery: $($m.Name) $($m.Version)", 'Veröffentlichen')) {
        Publish-Module -Path $out -NuGetApiKey $env:PSGALLERY_API_KEY -Repository PSGallery
        Write-Host 'Veröffentlicht.' -ForegroundColor Green
    }
}
