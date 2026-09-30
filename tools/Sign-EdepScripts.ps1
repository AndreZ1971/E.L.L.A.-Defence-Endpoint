<#
.SYNOPSIS
    Signiert alle PowerShell-Dateien eines Ordners per Authenticode mit Zeitstempel.

.DESCRIPTION
    Das Zertifikat (Code Signing, OV oder EV) muss im Zertifikatspeicher liegen, bei
    aktuellen Zertifikaten auf einem Hardware-Token oder in einem Cloud-HSM.
    Der Zeitstempel sorgt dafür, dass die Signatur nach Ablauf des Zertifikats gültig bleibt.

.EXAMPLE
    .\tools\Sign-EdepScripts.ps1 -Path .\out\EDEP -CertificateThumbprint 0123ABCD...
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
    Where-Object Thumbprint -eq $CertificateThumbprint | Select-Object -First 1
if (-not $cert) { throw "Code-Signing-Zertifikat $CertificateThumbprint nicht gefunden." }
if ($cert.NotAfter -lt (Get-Date)) { throw "Zertifikat abgelaufen am $($cert.NotAfter)." }

$files = Get-ChildItem -Path $Path -Include *.ps1, *.psm1, *.psd1 -Recurse
foreach ($f in $files) {
    if ($PSCmdlet.ShouldProcess($f.FullName, 'Signieren')) {
        $sig = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert `
            -TimestampServer $TimestampServer -HashAlgorithm SHA256
        if ($sig.Status -ne 'Valid') { throw "$($f.Name): $($sig.Status) $($sig.StatusMessage)" }
        Write-Host "signiert: $($f.Name)"
    }
}
