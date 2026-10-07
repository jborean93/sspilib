#!/usr/bin/env pwsh
# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

<#
.SYNOPSIS
Runs a command with a Kerberos KDC for the sspilib tests.

.DESCRIPTION
Starts an Obol KDC for the realm SSPILIB.TEST with a user and a service
principal, registers it with the Windows Kerberos SSP and runs the command
given. The realm details are passed to the command as JSON in the
SSPILIB_TEST_KERBEROS environment variable, which the krb_env fixture in
tests/conftest.py reads. The Kerberos tests are skipped when it is not set.

The realm is registered with the Kerberos SSP machine wide, like
ksetup.exe /addkdc, which needs an elevated session.

The Obol module is installed from the PowerShell Gallery if the version this
script uses is not already available.

.EXAMPLE
pwsh build_helpers/run-with-kdc.ps1 python -m pytest tests/test_kerberos.py
#>

$ErrorActionPreference = 'Stop'

if (-not $args) {
    throw 'A command to run with the KDC must be specified, for example: run-with-kdc.ps1 python -m pytest'
}
$command = $args[0]
$commandArgs = @($args | Select-Object -Skip 1)

$obolVersion = '0.1.0'
$baseVersion, $prerelease = $obolVersion -split '-', 2

function Get-ObolModule {
    Get-Module -Name Obol -ListAvailable | Where-Object {
        $_.Version -eq [Version]$baseVersion -and [string]$_.PrivateData.PSData.Prerelease -eq [string]$prerelease
    } | Select-Object -First 1
}

$obolModule = Get-ObolModule
if (-not $obolModule) {
    Write-Host "Installing Obol $obolVersion from the PowerShell Gallery"
    $installParams = @{
        Name = 'Obol'
        Version = $obolVersion
        Prerelease = [bool]$prerelease
        TrustRepository = $true
        Scope = 'CurrentUser'
        Quiet = $true
    }
    Install-PSResource @installParams

    $obolModule = Get-ObolModule
    if (-not $obolModule) {
        throw "Failed to find Obol $obolVersion after installing it"
    }
}
Import-Module -Name $obolModule.Path

function New-RandomPassword {
    [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
}

$realm = 'SSPILIB.TEST'
$hostname = 'host.sspilib.test'
$service = 'host'
$userPrincipal = 'user'
$userPassword = New-RandomPassword

# The tickets for the service are encrypted with the random keys of this
# account, which the acceptor reads from a keytab. The SSPI acceptor does not
# run as SYSTEM so it cannot verify a PAC, the tickets for the service are
# issued without one.
$acceptorPrincipal = 'service'

$kdcParams = @{
    Realm = $realm
    Principal = [ordered]@{
        $userPrincipal = New-ObolPrincipalSetting -Password (
            ConvertTo-SecureString -AsPlainText -Force $userPassword
        )
        $acceptorPrincipal = New-ObolPrincipalSetting -Alias "$service/$hostname" -Flag NoAuthDataRequired
    }
    Port = 88  # Windows Kerberos always contacts a KDC on port 88.
}

$tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "sspilib-kdc-$([Guid]::NewGuid().ToString('N'))"
$null = New-Item -Path $tempPath -ItemType Directory

$exitCode = 1
$kdc = Start-ObolKdc @kdcParams
try {
    $clientKeytab = Join-Path $tempPath 'client.keytab'
    $acceptorKeytab = Join-Path $tempPath 'acceptor.keytab'
    Export-ObolKeytab -Path $clientKeytab -Kdc $kdc -Name $userPrincipal
    Export-ObolKeytab -Path $acceptorKeytab -Kdc $kdc -Name $acceptorPrincipal

    $env:SSPILIB_TEST_KERBEROS = [ordered]@{
        realm = $realm
        initiator_username = "$userPrincipal@$realm"
        initiator_password = $userPassword
        initiator_keytab = $clientKeytab
        acceptor_spn = "$service/$hostname"
        acceptor_keytab = $acceptorKeytab
    } | ConvertTo-Json -Compress

    Write-Host "Running '$command $commandArgs' with the KDC for $realm on $($kdc.Endpoint)"

    # The command runs in another process so the realm must be registered
    # for the whole machine, the per thread scope only applies to this one.
    Use-ObolSspiEnvironment -Kdc $kdc -Scope MitRealm {
        & $command @commandArgs
        $script:exitCode = $LASTEXITCODE
    }
}
finally {
    $kdc | Stop-ObolKdc
    Remove-Item -LiteralPath $tempPath -Recurse -Force -ErrorAction SilentlyContinue
}

exit $exitCode
