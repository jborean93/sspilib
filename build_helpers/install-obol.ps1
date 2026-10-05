#!/usr/bin/env pwsh
# Copyright: (c) 2026 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

<#
.SYNOPSIS
Installs the Obol PowerShell module used to run a KDC for the Kerberos tests.

.DESCRIPTION
Nothing is installed when any version of Obol is already available to the
current session, so a locally built or newer module is used as is.

.PARAMETER Version
The version to install when the module is not present, including any
prerelease label such as 0.1.0-beta1.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'

$existing = Get-Module -Name Obol -ListAvailable | Select-Object -First 1
if ($existing) {
    Write-Host "Using Obol $($existing.Version) from $($existing.ModuleBase)"
    return
}

$installParams = @{
    Name = 'Obol'
    Version = $Version
    Prerelease = $true
    Repository = 'PSGallery'
    TrustRepository = $true
    Scope = 'CurrentUser'
    Quiet = $true
    PassThru = $true
}
$module = Install-PSResource @installParams
Write-Host "Installed Obol $Version to $($module.InstalledLocation)"
