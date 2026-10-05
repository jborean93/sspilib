#!/usr/bin/env pwsh
# Copyright: (c) 2026 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

<#
.SYNOPSIS
Runs a command with a Kerberos KDC the sspilib tests can authenticate with.

.DESCRIPTION
Starts an Obol KDC (https://github.com/jborean93/PowerShell-Obol) for the
SSPILIB.TEST realm, registers it with the Windows Kerberos SSP, and runs the
command given with the SSPILIB_KRB_CONFIG environment variable set to a JSON
object that describes the realm. The krb_env fixture in tests/conftest.py reads
it and skips the Kerberos tests when it is not set. The KDC is stopped once the
command finishes.

The KDC is registered for the whole machine through the DC locator, the same
DNS SRV and LDAP ping lookup Windows uses to find an Active Directory domain
controller, so the Python process started here finds it like it would a real
domain. That needs an elevated session.

The service principal is created with the NoAuthDataRequired flag so its
tickets have no PAC. Windows only validates a PAC itself when the acceptor runs
as SYSTEM or holds SeTcbPrivilege, any other process asks a domain controller
of the realm to validate it which fails on a host not joined to it.

This is Windows only. sspi-rs, used on other platforms, cannot accept Kerberos
tokens through SSPI and does not support keytab credentials, so there is
nothing to test against a KDC there.

The command's arguments are passed as is, pwsh -File is used without a param
block so pytest options like -v or -k are not parsed as PowerShell parameters.

SSPILIB_KRB_CONFIG is a JSON object with the keys
    realm               The realm name.
    user                UPN of a user with a password.
    password            The password of that user.
    keytab_user         UPN of a user with random keys.
    keytab_user_keytab  Path to a keytab with that user's keys.
    service             SPN of the service principal.
    service_keytab      Path to a keytab with the service's keys.

.EXAMPLE
pwsh build_helpers/kerberos-env.ps1 python -m pytest -v
#>

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $IsWindows) {
    throw 'The Kerberos tests are only supported on Windows, see the script description.'
}
if ($args.Count -eq 0) {
    throw 'A command to run with the KDC must be specified.'
}

Import-Module -Name Obol

$realm = 'SSPILIB.TEST'
$user = 'user'
$keytabUser = 'keytabuser'
$service = 'HTTP/web.sspilib.test'
$password = "Pass$([Guid]::NewGuid().ToString('N'))!"

$principals = [ordered]@{
    $user = ConvertTo-SecureString -AsPlainText -Force $password
    # Random keys only, the client authenticates with its keytab.
    $keytabUser = $null
    # No PAC in the service tickets, see the description.
    $service = New-ObolPrincipalSetting -Flag NoAuthDataRequired
}

$tempPath = Join-Path ([IO.Path]::GetTempPath()) "sspilib-krb-$([Guid]::NewGuid().ToString('N'))"
$null = New-Item -Path $tempPath -ItemType Directory
$exitCode = 1
$kdc = $null
$traceEvents = @()
try {
    # Windows Kerberos always contacts a KDC on port 88.
    $kdc = Start-ObolKdc -Realm $realm -Address 127.0.0.1 -Port 88 -Principal $principals
    Write-Host "Started Obol KDC for $realm on $($kdc.Endpoint)"

    # The KDC, DNS and LDAP ping events are queued in this runspace while the
    # command runs and written out at the end so a failed test shows what the
    # KDC saw and how Windows found it.
    $traceEvents = foreach ($kdcEvent in ($kdc | Get-Member -MemberType Event)) {
        $sourceIdentifier = "sspilib-kdc-$($kdcEvent.Name)"
        Register-ObjectEvent -InputObject $kdc -EventName $kdcEvent.Name -SourceIdentifier $sourceIdentifier
        $sourceIdentifier
    }

    $serviceKeytab = Join-Path $tempPath 'service.keytab'
    $userKeytab = Join-Path $tempPath 'user.keytab'
    $kdc | Export-ObolKeytab -Path $serviceKeytab -Name $service
    $kdc | Export-ObolKeytab -Path $userKeytab -Name $keytabUser

    # The keys match the KerberosEnvironment dataclass in tests/conftest.py.
    $env:SSPILIB_KRB_CONFIG = [ordered]@{
        realm = $realm
        user = "$user@$realm"
        password = $password
        keytab_user = "$keytabUser@$realm"
        keytab_user_keytab = $userKeytab
        service = $service
        service_keytab = $serviceKeytab
    } | ConvertTo-Json -Compress

    # $args in the scriptblock are the KDCs the Use-Obol* cmdlets pass to it,
    # the command to run is captured from the script's arguments.
    $command = @($args)
    Use-ObolSspiEnvironment -Kdc $kdc -Scope DcLocator -ScriptBlock {
        & $command[0] @($command | Select-Object -Skip 1)
        $script:exitCode = $LASTEXITCODE
    }
}
finally {
    if ($kdc) {
        $kdc | Stop-ObolKdc
    }

    foreach ($sourceIdentifier in $traceEvents) {
        Get-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "[KDC] $($_.SourceEventArgs.Message)"
            Remove-Event -EventIdentifier $_.EventIdentifier
        }
        Unregister-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $tempPath -Recurse -Force -ErrorAction SilentlyContinue
}

exit $exitCode
