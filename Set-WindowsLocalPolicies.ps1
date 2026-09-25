[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $PolicyPath,

    [Parameter()]
    [string] $BackupPath = (Join-Path $PSScriptRoot ('PolicyBackup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $AppLockerXmlPath,

    [Parameter()]
    [switch] $SkipAuditPolicy,

    [Parameter()]
    [switch] $SkipDefenderPolicy,

    [Parameter()]
    [switch] $SkipEdgePolicy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Invoke-Native {
    param([string] $FilePath, [string[]] $ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $FilePath $($ArgumentList -join ' ')"
    }
}

function Set-PolicyRegistryValue {
    param(
        [string] $Path,
        [string] $Name,
        [object] $Value,
        [Microsoft.Win32.RegistryValueKind] $Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set policy value to $Value")) {
        New-Item -Path $Path -Force | Out-Null
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

function Get-DefaultPolicy {
    return [ordered]@{
        PasswordPolicy = [ordered]@{
            MinimumPasswordAgeDays = 1
            MaximumPasswordAgeDays = 60
            MinimumPasswordLength = 14
            PasswordHistoryCount = 24
            ComplexityEnabled = $true
            ReversibleEncryptionEnabled = $false
        }
        LockoutPolicy = [ordered]@{
            LockoutThreshold = 5
            LockoutDurationMinutes = 15
            ResetLockoutCounterMinutes = 15
        }
        SecurityOptions = [ordered]@{
            DontDisplayLastUserName = $true
            DisableDomainCreds = $true
            RestrictAnonymous = 1
            RestrictAnonymousSam = 1
            EveryoneIncludesAnonymous = 0
        }
        AuditPolicy = [ordered]@{
            'Account Logon' = 'Success and Failure'
            'Account Management' = 'Success and Failure'
            'Detailed Tracking' = 'Success'
            'DS Access' = 'Failure'
            'Logon/Logoff' = 'Success and Failure'
            'Object Access' = 'Failure'
            'Policy Change' = 'Success and Failure'
            'Privilege Use' = 'Failure'
            'System' = 'Success and Failure'
        }
        Defender = [ordered]@{
            DisableAntiSpyware = 0
            DisableRealtimeMonitoring = 0
            PUAProtection = 1
            EnableNetworkProtection = 1
            EnableControlledFolderAccess = 1
        }
        Edge = [ordered]@{
            PasswordManagerEnabled = 0
            AutofillAddressEnabled = 0
            AutofillCreditCardEnabled = 0
            SmartScreenEnabled = 1
            SmartScreenPuaEnabled = 1
        }
    }
}

function Merge-Hashtable {
    param([hashtable] $Base, [hashtable] $Override)
    foreach ($key in $Override.Keys) {
        if ($Base.ContainsKey($key) -and $Base[$key] -is [hashtable] -and $Override[$key] -is [hashtable]) {
            Merge-Hashtable -Base $Base[$key] -Override $Override[$key]
        } else {
            $Base[$key] = $Override[$key]
        }
    }
}

Assert-Administrator

$policy = Get-DefaultPolicy
if ($PolicyPath) {
    $custom = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json -AsHashtable
    Merge-Hashtable -Base $policy -Override $custom
}

if ($PSCmdlet.ShouldProcess($BackupPath, 'Create policy backup directory')) {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\secedit.exe') -ArgumentList @('/export', '/cfg', (Join-Path $BackupPath 'security-policy.inf'), '/quiet')
    & reg.exe export 'HKLM\SOFTWARE\Policies' (Join-Path $BackupPath 'machine-policies.reg') /y | Out-Null
    & reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows Defender' (Join-Path $BackupPath 'defender.reg') /y | Out-Null
}

$tempInf = Join-Path ([IO.Path]::GetTempPath()) ('local-policy-' + [guid]::NewGuid().ToString() + '.inf')
try {
    $p = $policy.PasswordPolicy
    $l = $policy.LockoutPolicy
    $inf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = $($p.MinimumPasswordAgeDays)
MaximumPasswordAge = $($p.MaximumPasswordAgeDays)
MinimumPasswordLength = $($p.MinimumPasswordLength)
PasswordHistorySize = $($p.PasswordHistoryCount)
PasswordComplexity = $([int][bool]$p.ComplexityEnabled)
ClearTextPassword = $([int][bool]$p.ReversibleEncryptionEnabled)
LockoutBadCount = $($l.LockoutThreshold)
ResetLockoutCount = $($l.ResetLockoutCounterMinutes)
LockoutDuration = $($l.LockoutDurationMinutes)

[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    if ($PSCmdlet.ShouldProcess('Local Security Policy', 'Apply password and lockout policy')) {
        Set-Content -LiteralPath $tempInf -Value $inf -Encoding Unicode
        Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\secedit.exe') -ArgumentList @('/configure', '/db', (Join-Path $env:SystemRoot 'security\database\local.sdb'), '/cfg', $tempInf, '/areas', 'SECURITYPOLICY', '/quiet')
    }
} finally {
    Remove-Item -LiteralPath $tempInf -Force -ErrorAction SilentlyContinue
}

$securityPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$so = $policy.SecurityOptions
Set-PolicyRegistryValue -Path $securityPath -Name 'LimitBlankPasswordUse' -Value 1
Set-PolicyRegistryValue -Path $securityPath -Name 'RestrictAnonymous' -Value $so.RestrictAnonymous
Set-PolicyRegistryValue -Path $securityPath -Name 'RestrictAnonymousSAM' -Value $so.RestrictAnonymousSam
Set-PolicyRegistryValue -Path $securityPath -Name 'EveryoneIncludesAnonymous' -Value $so.EveryoneIncludesAnonymous
Set-PolicyRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'dontdisplaylastusername' -Value ([int][bool]$so.DontDisplayLastUserName)
Set-PolicyRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Value ([int][bool]$so.DisableDomainCreds)

if (-not $SkipAuditPolicy) {
    foreach ($entry in $policy.AuditPolicy.GetEnumerator()) {
        if ($PSCmdlet.ShouldProcess($entry.Key, "Set audit policy to $($entry.Value)")) {
            Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\auditpol.exe') -ArgumentList @('/set', '/subcategory:*', "/success:$($entry.Value -match 'Success')", "/failure:$($entry.Value -match 'Failure')")
            break
        }
    }
}

if (-not $SkipDefenderPolicy) {
    $defenderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $d = $policy.Defender
    Set-PolicyRegistryValue -Path $defenderPath -Name 'DisableAntiSpyware' -Value $d.DisableAntiSpyware
    Set-PolicyRegistryValue -Path $defenderPath -Name 'DisableRealtimeMonitoring' -Value $d.DisableRealtimeMonitoring
    Set-PolicyRegistryValue -Path "$defenderPath\MpEngine" -Name 'MpEnablePus' -Value $d.PUAProtection
    Set-PolicyRegistryValue -Path "$defenderPath\Windows Defender Exploit Guard\Network Protection" -Name 'EnableNetworkProtection' -Value $d.EnableNetworkProtection
    Set-PolicyRegistryValue -Path "$defenderPath\Windows Defender Exploit Guard\Controlled Folder Access" -Name 'EnableControlledFolderAccess' -Value $d.EnableControlledFolderAccess
}

if (-not $SkipEdgePolicy) {
    $edgePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    foreach ($entry in $policy.Edge.GetEnumerator()) {
        Set-PolicyRegistryValue -Path $edgePath -Name $entry.Key -Value $entry.Value
    }
}

if ($AppLockerXmlPath) {
    if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
        throw 'The AppLocker cmdlets are unavailable on this Windows edition.'
    }
    if ($PSCmdlet.ShouldProcess($AppLockerXmlPath, 'Replace local AppLocker policy')) {
        Set-AppLockerPolicy -XMLPolicy $AppLockerXmlPath -Merge
    }
}

if ($PSCmdlet.ShouldProcess('Windows policy refresh', 'Refresh local policy')) {
    Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\gpupdate.exe') -ArgumentList @('/target:computer', '/force')
}

Write-Host 'Local policy configuration completed. Review the backup and event logs, then restart if required.' -ForegroundColor Green
