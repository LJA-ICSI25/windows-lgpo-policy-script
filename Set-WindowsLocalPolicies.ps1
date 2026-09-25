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
    [switch] $SkipEdgePolicy,

    [Parameter()]
    [switch] $SkipFirewallPolicy,

    [Parameter()]
    [switch] $SkipUAC,

    [Parameter()]
    [switch] $SkipCryptography,

    [Parameter()]
    [switch] $SkipNetworkSecurity,

    [Parameter()]
    [switch] $SkipEventLog,

    [Parameter()]
    [switch] $SkipRemoteDesktop
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

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
        [Microsoft.Win32.RegistryValueKind] $Type = [Microsoft.Win32.RegistryValueKind]::DWord,
        [string] $Description
    )

    if ($Description) {
        Write-Host "  [Registry] $Description" -ForegroundColor Cyan
    }

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set policy value to $Value")) {
        New-Item -Path $Path -Force | Out-Null
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

function Set-PolicyStringValue {
    param(
        [string] $Path,
        [string] $Name,
        [string] $Value,
        [string] $Description
    )
    Set-PolicyRegistryValue -Path $Path -Name $Name -Value $Value -Type ([Microsoft.Win32.RegistryValueKind]::String) -Description $Description
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
            LimitBlankPasswordUse = 1
            RequireSignOnUsingCtrlAltDel = 1
            DisableNewNetworkConnectionProfiles = $true
        }
        UAC = [ordered]@{
            EnableLUA = 1
            ConsentPromptBehaviorAdmin = 2
            ConsentPromptBehaviorUser = 0
            PromptOnSecureDesktop = 1
            ValidateAdminCodeSignatures = 0
            DetectInstallersAndPromptForElevation = 1
            AllowUIAccessApplicationsToPromptForElevation = 0
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
            'Sensitive Privilege Use' = 'Failure'
            'Account Lockout' = 'Success and Failure'
            'Process Creation' = 'Success'
            'Authentication Policy Change' = 'Success'
        }
        EventLog = [ordered]@{
            ApplicationMaxSize = 20480
            ApplicationRetention = 0
            SecurityMaxSize = 196608
            SecurityRetention = 0
            SystemMaxSize = 20480
            SystemRetention = 0
        }
        Cryptography = [ordered]@{
            TLS10 = 0
            TLS11 = 0
            TLS12 = 1
            TLS13 = 1
            SSL30 = 0
            SSL20 = 0
        }
        NetworkSecurity = [ordered]@{
            'NTLM: Deny all NTLM authentication in this domain if enabled' = 0
            'NTLM: Minimum session security for NTLM SSP based clients' = 537395200
            'NTLM: Minimum session security for NTLM SSP based servers' = 537395200
            'LanManCompatibilityLevel' = 5
            'NoLmHash' = 1
            'RestrictNTLMInDomain' = 7
            'RestrictNTLMOutgoing' = 1
        }
        RemoteDesktop = [ordered]@{
            SecurityLayer = 2
            UserAuthentication = 1
            MinEncryptionLevel = 4
            ClientConnectionEncryptionLevel = 3
            EncryptionLevel = 3
            DisableRemoteDesktop = 0
            NegotiateSecurityLayer = 1
        }
        Defender = [ordered]@{
            DisableAntiSpyware = 0
            DisableRealtimeMonitoring = 0
            PUAProtection = 1
            EnableNetworkProtection = 1
            EnableControlledFolderAccess = 1
            CloudBasedProtectionLevel = 2
            CloudBlockLevelDefault = 4
            SubmitSamplesConsent = 3
            MAPSReporting = 2
            DisableBehaviorMonitoring = 0
            DisableIOAVProtection = 0
            DisableScriptScanning = 0
            DisableArchiveScanning = 0
            DisableCatchupFullScan = 0
            DisableCatchupQuickScan = 0
            AVEngineUpdatesDisabled = 0
            SignatureUpdateInterval = 0
            SignatureScheduleDay = 0
            SignatureScheduleTime = 2
        }
        Firewall = [ordered]@{
            EnableFirewall = 1
            DefaultInboundAction = 1
            DefaultOutboundAction = 0
            EnableStealthModeForIPv4 = 1
            EnableStealthModeForIPv6 = 1
            LogDroppedPackets = 1
            LogSuccessfulConnections = 0
            LogMaxSizeInKB = 16384
        }
        Edge = [ordered]@{
            PasswordManagerEnabled = 0
            AutofillAddressEnabled = 0
            AutofillCreditCardEnabled = 0
            SmartScreenEnabled = 1
            SmartScreenPuaEnabled = 1
            BrowserSignin = 0
            MetricsReportingEnabled = 0
            PreventSmartScreenPromptOverride = 1
            PreventSmartScreenPromptOverrideForFiles = 1
            WarnBeforeOpeningFile = 1
            BlockThirdPartyCookies = 1
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

function Backup-CurrentPolicy {
    param([string] $BackupPath)

    Write-Host "`n[Backup] Creating system policy backup..." -ForegroundColor Magenta

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    }

    try {
        Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\secedit.exe') -ArgumentList @('/export', '/cfg', (Join-Path $BackupPath 'security-policy.inf'), '/quiet')
        Write-Host "  Saved: $(Join-Path $BackupPath 'security-policy.inf')" -ForegroundColor Green
    } catch {
        Write-Host "  Warning: Could not backup secedit policy: $_" -ForegroundColor Yellow
    }

    try {
        & reg.exe export 'HKLM\SOFTWARE\Policies' (Join-Path $BackupPath 'machine-policies.reg') /y | Out-Null
        & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' (Join-Path $BackupPath 'tcpip.reg') /y | Out-Null
        & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' (Join-Path $BackupPath 'lsa.reg') /y | Out-Null
        Write-Host "  Saved: registry exports to $BackupPath" -ForegroundColor Green
    } catch {
        Write-Host "  Warning: Could not backup registry policies: $_" -ForegroundColor Yellow
    }
}

function Apply-PasswordPolicy {
    param([hashtable] $PasswordPolicy, [hashtable] $LockoutPolicy)

    Write-Host "`n[Password Policy] Applying password requirements..." -ForegroundColor Magenta

    $tempInf = Join-Path ([IO.Path]::GetTempPath()) ('policy-' + [guid]::NewGuid().ToString() + '.inf')
    try {
        $p = $PasswordPolicy
        $l = $LockoutPolicy
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
            Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\secedit.exe') -ArgumentList @(
                '/configure', '/db', (Join-Path $env:SystemRoot 'security\database\local.sdb'),
                '/cfg', $tempInf, '/areas', 'SECURITYPOLICY', '/quiet'
            )
            Write-Host "  Applied password and lockout policies" -ForegroundColor Green
        }
    } finally {
        Remove-Item -LiteralPath $tempInf -Force -ErrorAction SilentlyContinue
    }
}

function Apply-SecurityOptions {
    param([hashtable] $SecurityOptions)

    Write-Host "`n[Security Options] Configuring system security options..." -ForegroundColor Magenta

    $securityPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-PolicyRegistryValue -Path $securityPath -Name 'LimitBlankPasswordUse' -Value $SecurityOptions.LimitBlankPasswordUse -Description 'Limit blank password usage'
    Set-PolicyRegistryValue -Path $securityPath -Name 'RestrictAnonymous' -Value $SecurityOptions.RestrictAnonymous -Description 'Restrict anonymous access'
    Set-PolicyRegistryValue -Path $securityPath -Name 'RestrictAnonymousSAM' -Value $SecurityOptions.RestrictAnonymousSam -Description 'Restrict anonymous SAM enumeration'
    Set-PolicyRegistryValue -Path $securityPath -Name 'EveryoneIncludesAnonymous' -Value $SecurityOptions.EveryoneIncludesAnonymous -Description 'Anonymous group membership'
    Set-PolicyRegistryValue -Path $securityPath -Name 'RequireSignOnUsingCtrlAltDel' -Value $SecurityOptions.RequireSignOnUsingCtrlAltDel -Description 'Require Ctrl+Alt+Del for login'
    Set-PolicyRegistryValue -Path $securityPath -Name 'NoLmHash' -Value 1 -Description 'Do not store LM hash of new passwords'
    Set-PolicyRegistryValue -Path $securityPath -Name 'DisableDomainCreds' -Value ([int][bool]$SecurityOptions.DisableDomainCreds) -Description 'Disable domain credentials storage'

    $systemPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-PolicyRegistryValue -Path $systemPath -Name 'dontdisplaylastusername' -Value ([int][bool]$SecurityOptions.DontDisplayLastUserName) -Description 'Do not display last username on login screen'
    Set-PolicyRegistryValue -Path $systemPath -Name 'DisableNewNetworkConnectionProfiles' -Value ([int][bool]$SecurityOptions.DisableNewNetworkConnectionProfiles) -Description 'Disable new network connection profiles'
}

function Apply-UACPolicy {
    param([hashtable] $UAC)

    Write-Host "`n[UAC] Configuring User Account Control..." -ForegroundColor Magenta

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-PolicyRegistryValue -Path $uacPath -Name 'EnableLUA' -Value $UAC.EnableLUA -Description 'Enable User Account Control'
    Set-PolicyRegistryValue -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -Value $UAC.ConsentPromptBehaviorAdmin -Description 'Admin approval mode for built-in admin'
    Set-PolicyRegistryValue -Path $uacPath -Name 'ConsentPromptBehaviorUser' -Value $UAC.ConsentPromptBehaviorUser -Description 'Standard user elevation behavior'
    Set-PolicyRegistryValue -Path $uacPath -Name 'PromptOnSecureDesktop' -Value $UAC.PromptOnSecureDesktop -Description 'Display UAC prompts on secure desktop'
    Set-PolicyRegistryValue -Path $uacPath -Name 'ValidateAdminCodeSignatures' -Value $UAC.ValidateAdminCodeSignatures -Description 'Require digitally signed code for admin'
    Set-PolicyRegistryValue -Path $uacPath -Name 'DetectInstallersAndPromptForElevation' -Value $UAC.DetectInstallersAndPromptForElevation -Description 'Detect installers and prompt for elevation'
    Set-PolicyRegistryValue -Path $uacPath -Name 'AllowUIAccessApplicationsToPromptForElevation' -Value $UAC.AllowUIAccessApplicationsToPromptForElevation -Description 'Allow UIAccess apps to prompt without secure desktop'
}

function Apply-AuditPolicy {
    param([hashtable] $AuditPolicy)

    Write-Host "`n[Audit Policy] Configuring Advanced Audit Policy..." -ForegroundColor Magenta

    foreach ($entry in $AuditPolicy.GetEnumerator()) {
        $category = $entry.Key
        $successFlag = if ($entry.Value -match 'Success') { 'enable' } else { 'disable' }
        $failureFlag = if ($entry.Value -match 'Failure') { 'enable' } else { 'disable' }

        if ($PSCmdlet.ShouldProcess($category, "Set audit policy to $($entry.Value)")) {
            try {
                Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\auditpol.exe') -ArgumentList @(
                    '/set', '/subcategory:*', "/subcategory:$category", "/success:$successFlag", "/failure:$failureFlag"
                )
            } catch {
                Write-Host "  Warning: Could not set audit policy for $category`: $_" -ForegroundColor Yellow
            }
        }
    }
}

function Apply-EventLogPolicy {
    param([hashtable] $EventLog)

    Write-Host "`n[Event Log] Configuring event log retention policies..." -ForegroundColor Magenta

    $logs = @{
        'Application' = @{ MaxSize = 'ApplicationMaxSize'; Retention = 'ApplicationRetention' }
        'Security' = @{ MaxSize = 'SecurityMaxSize'; Retention = 'SecurityRetention' }
        'System' = @{ MaxSize = 'SystemMaxSize'; Retention = 'SystemRetention' }
    }

    foreach ($logEntry in $logs.GetEnumerator()) {
        $logName = $logEntry.Key
        $maxSize = $EventLog[$logEntry.Value.MaxSize]
        $retention = $EventLog[$logEntry.Value.Retention]

        if ($PSCmdlet.ShouldProcess($logName, "Set event log size to $maxSize KB and retention to $retention days")) {
            try {
                $log = Get-EventLog -List | Where-Object { $_.Log -eq $logName }
                if ($log) {
                    Limit-EventLog -LogName $logName -MaximumSize ($maxSize * 1KB) -RetentionDays $retention -ErrorAction Stop
                    Write-Host "  Configured $logName log: MaxSize=$maxSize KB, RetentionDays=$retention" -ForegroundColor Green
                }
            } catch {
                Write-Host "  Warning: Could not configure $logName log: $_" -ForegroundColor Yellow
            }
        }
    }
}

function Apply-CryptographyPolicy {
    param([hashtable] $Cryptography)

    Write-Host "`n[Cryptography] Configuring TLS and SSL settings..." -ForegroundColor Magenta

    $basePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $protocols = @{
        'TLS 1.0' = 'TLS10'
        'TLS 1.1' = 'TLS11'
        'TLS 1.2' = 'TLS12'
        'TLS 1.3' = 'TLS13'
        'SSL 3.0' = 'SSL30'
        'SSL 2.0' = 'SSL20'
    }

    foreach ($protEntry in $protocols.GetEnumerator()) {
        $protName = $protEntry.Key
        $regKey = $protEntry.Value
        $value = $Cryptography[$regKey]

        if ($PSCmdlet.ShouldProcess($protName, "Set protocol enable state to $value")) {
            try {
                $clientPath = "$basePath\$protName\Client"
                Set-PolicyRegistryValue -Path $clientPath -Name 'Enabled' -Value $value -Description "$protName Client: $(if($value -eq 1) {'Enabled'} else {'Disabled'})"
                $serverPath = "$basePath\$protName\Server"
                Set-PolicyRegistryValue -Path $serverPath -Name 'Enabled' -Value $value -Description "$protName Server: $(if($value -eq 1) {'Enabled'} else {'Disabled'})"
            } catch {
                Write-Host "  Warning: Could not configure $protName`: $_" -ForegroundColor Yellow
            }
        }
    }
}

function Apply-NetworkSecurityPolicy {
    param([hashtable] $NetworkSecurity)

    Write-Host "`n[Network Security] Configuring NTLM and LAN Manager policies..." -ForegroundColor Magenta

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $msvPath = "$lsaPath\MSV1_0"

    Set-PolicyRegistryValue -Path $lsaPath -Name 'LmCompatibilityLevel' -Value $NetworkSecurity.LanManCompatibilityLevel -Description 'LAN Manager compatibility level'
    Set-PolicyRegistryValue -Path $lsaPath -Name 'NoLmHash' -Value $NetworkSecurity.NoLmHash -Description 'Do not store LM hash of new passwords'
    Set-PolicyRegistryValue -Path $msvPath -Name 'NTLMMinClientSec' -Value $NetworkSecurity.'NTLM: Minimum session security for NTLM SSP based clients' -Description 'NTLM minimum client session security'
    Set-PolicyRegistryValue -Path $msvPath -Name 'NTLMMinServerSec' -Value $NetworkSecurity.'NTLM: Minimum session security for NTLM SSP based servers' -Description 'NTLM minimum server session security'
    Set-PolicyRegistryValue -Path $msvPath -Name 'RestrictNTLMInDomain' -Value $NetworkSecurity.'RestrictNTLMInDomain' -Description 'Restrict NTLM in domain'
    Set-PolicyRegistryValue -Path $msvPath -Name 'RestrictNTLMOutgoing' -Value $NetworkSecurity.'RestrictNTLMOutgoing' -Description 'Restrict NTLM outgoing authentication'
}

function Apply-RemoteDesktopPolicy {
    param([hashtable] $RemoteDesktop)

    Write-Host "`n[Remote Desktop] Configuring RDP security settings..." -ForegroundColor Magenta

    $rdpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Set-PolicyRegistryValue -Path $rdpPath -Name 'SecurityLayer' -Value $RemoteDesktop.SecurityLayer -Description 'RDP Security Layer (2 = SSL/TLS)'
    Set-PolicyRegistryValue -Path $rdpPath -Name 'UserAuthentication' -Value $RemoteDesktop.UserAuthentication -Description 'Require Network Level Authentication'
    Set-PolicyRegistryValue -Path $rdpPath -Name 'MinEncryptionLevel' -Value $RemoteDesktop.MinEncryptionLevel -Description 'Minimum RDP Encryption Level (4 = High)'

    $rdpPolPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    Set-PolicyRegistryValue -Path $rdpPolPath -Name 'EncryptionLevel' -Value $RemoteDesktop.EncryptionLevel -Description 'RDP Encryption Level'
    Set-PolicyRegistryValue -Path $rdpPolPath -Name 'fDisableRemoteDesktop' -Value $RemoteDesktop.DisableRemoteDesktop -Description 'Disable Remote Desktop (0 = Enabled, 1 = Disabled)'
}

function Apply-DefenderPolicy {
    param([hashtable] $Defender)

    Write-Host "`n[Windows Defender] Configuring Defender and real-time protection..." -ForegroundColor Magenta

    $defenderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $realTimePath = "$defenderPath\Real-Time Protection"
    $scanPath = "$defenderPath\Scan"
    $updatePath = "$defenderPath\Updates"
    $mpeEnginePath = "$defenderPath\MpEngine"
    $exploitGuardPath = "$defenderPath\Windows Defender Exploit Guard"
    $networkProtectionPath = "$exploitGuardPath\Network Protection"
    $controlledFolderPath = "$exploitGuardPath\Controlled Folder Access"

    Set-PolicyRegistryValue -Path $defenderPath -Name 'DisableAntiSpyware' -Value $Defender.DisableAntiSpyware -Description 'Disable Antispyware'
    Set-PolicyRegistryValue -Path $realTimePath -Name 'DisableRealtimeMonitoring' -Value $Defender.DisableRealtimeMonitoring -Description 'Disable Real-time Protection'
    Set-PolicyRegistryValue -Path $realTimePath -Name 'DisableBehaviorMonitoring' -Value $Defender.DisableBehaviorMonitoring -Description 'Disable Behavior Monitoring'
    Set-PolicyRegistryValue -Path $realTimePath -Name 'DisableIOAVProtection' -Value $Defender.DisableIOAVProtection -Description 'Disable I/O on-Access Protection'
    Set-PolicyRegistryValue -Path $realTimePath -Name 'DisableScriptScanning' -Value $Defender.DisableScriptScanning -Description 'Disable Script Scanning'
    Set-PolicyRegistryValue -Path $realTimePath -Name 'DisableArchiveScanning' -Value $Defender.DisableArchiveScanning -Description 'Disable Archive Scanning'
    Set-PolicyRegistryValue -Path $scanPath -Name 'DisableCatchupFullScan' -Value $Defender.DisableCatchupFullScan -Description 'Disable Catch-up Full Scan'
    Set-PolicyRegistryValue -Path $scanPath -Name 'DisableCatchupQuickScan' -Value $Defender.DisableCatchupQuickScan -Description 'Disable Catch-up Quick Scan'
    Set-PolicyRegistryValue -Path $mpeEnginePath -Name 'MpEnablePus' -Value $Defender.PUAProtection -Description 'Enable Potentially Unwanted Application protection'
    Set-PolicyRegistryValue -Path $defenderPath -Name 'SubmitSamplesConsent' -Value $Defender.SubmitSamplesConsent -Description 'Send malware samples automatically'
    Set-PolicyRegistryValue -Path $defenderPath -Name 'MAPSReporting' -Value $Defender.MAPSReporting -Description 'Microsoft Active Protection Service reporting'
    Set-PolicyRegistryValue -Path $defenderPath -Name 'CloudBasedProtectionLevel' -Value $Defender.CloudBasedProtectionLevel -Description 'Cloud-delivered protection level'
    Set-PolicyRegistryValue -Path $defenderPath -Name 'CloudBlockLevelDefault' -Value $Defender.CloudBlockLevelDefault -Description 'Cloud block level'
    Set-PolicyRegistryValue -Path $updatePath -Name 'AVEngineUpdatesDisabled' -Value $Defender.AVEngineUpdatesDisabled -Description 'Disable AV Engine Updates'
    Set-PolicyRegistryValue -Path $updatePath -Name 'SignatureUpdateInterval' -Value $Defender.SignatureUpdateInterval -Description 'Signature update interval'
    Set-PolicyRegistryValue -Path $updatePath -Name 'SignatureScheduleDay' -Value $Defender.SignatureScheduleDay -Description 'Signature update schedule day'
    Set-PolicyRegistryValue -Path $updatePath -Name 'SignatureScheduleTime' -Value $Defender.SignatureScheduleTime -Description 'Signature update time'
    Set-PolicyRegistryValue -Path $networkProtectionPath -Name 'EnableNetworkProtection' -Value $Defender.EnableNetworkProtection -Description 'Enable Network Protection'
    Set-PolicyRegistryValue -Path $controlledFolderPath -Name 'EnableControlledFolderAccess' -Value $Defender.EnableControlledFolderAccess -Description 'Enable Controlled Folder Access'
}

function Apply-FirewallPolicy {
    param([hashtable] $Firewall)

    Write-Host "`n[Windows Firewall] Configuring firewall policies..." -ForegroundColor Magenta

    $fwPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
    Set-PolicyRegistryValue -Path $fwPath -Name 'EnableFirewall' -Value $Firewall.EnableFirewall -Description 'Enable Windows Firewall'
    Set-PolicyRegistryValue -Path $fwPath -Name 'DefaultInboundAction' -Value $Firewall.DefaultInboundAction -Description 'Default Inbound Action (1 = Block)'
    Set-PolicyRegistryValue -Path $fwPath -Name 'DefaultOutboundAction' -Value $Firewall.DefaultOutboundAction -Description 'Default Outbound Action (0 = Allow)'

    $logPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging'
    Set-PolicyRegistryValue -Path $logPath -Name 'LogDroppedPackets' -Value $Firewall.LogDroppedPackets -Description 'Log dropped packets'
    Set-PolicyRegistryValue -Path $logPath -Name 'LogSuccessfulConnections' -Value $Firewall.LogSuccessfulConnections -Description 'Log successful connections'
    Set-PolicyRegistryValue -Path $logPath -Name 'LogFileSize' -Value $Firewall.LogMaxSizeInKB -Description 'Log file maximum size (KB)'
}

function Apply-EdgePolicy {
    param([hashtable] $Edge)

    Write-Host "`n[Microsoft Edge] Configuring browser security policies..." -ForegroundColor Magenta

    $edgePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    Set-PolicyRegistryValue -Path $edgePath -Name 'PasswordManagerEnabled' -Value $Edge.PasswordManagerEnabled -Description 'Enable Password Manager'
    Set-PolicyRegistryValue -Path $edgePath -Name 'AutofillAddressEnabled' -Value $Edge.AutofillAddressEnabled -Description 'Enable Autofill for addresses'
    Set-PolicyRegistryValue -Path $edgePath -Name 'AutofillCreditCardEnabled' -Value $Edge.AutofillCreditCardEnabled -Description 'Enable Autofill for credit cards'
    Set-PolicyRegistryValue -Path $edgePath -Name 'SmartScreenEnabled' -Value $Edge.SmartScreenEnabled -Description 'Enable SmartScreen'
    Set-PolicyRegistryValue -Path $edgePath -Name 'SmartScreenPuaEnabled' -Value $Edge.SmartScreenPuaEnabled -Description 'Enable SmartScreen for PUA'
    Set-PolicyRegistryValue -Path $edgePath -Name 'BrowserSignin' -Value $Edge.BrowserSignin -Description 'Browser Sign-in Policy'
    Set-PolicyRegistryValue -Path $edgePath -Name 'MetricsReportingEnabled' -Value $Edge.MetricsReportingEnabled -Description 'Send diagnostic data'
    Set-PolicyRegistryValue -Path $edgePath -Name 'PreventSmartScreenPromptOverride' -Value $Edge.PreventSmartScreenPromptOverride -Description 'Prevent bypassing SmartScreen'
    Set-PolicyRegistryValue -Path $edgePath -Name 'PreventSmartScreenPromptOverrideForFiles' -Value $Edge.PreventSmartScreenPromptOverrideForFiles -Description 'Prevent bypassing SmartScreen for files'
    Set-PolicyRegistryValue -Path $edgePath -Name 'WarnBeforeOpeningFile' -Value $Edge.WarnBeforeOpeningFile -Description 'Warn before opening potentially dangerous files'
    Set-PolicyRegistryValue -Path $edgePath -Name 'BlockThirdPartyCookies' -Value $Edge.BlockThirdPartyCookies -Description 'Block third-party cookies'
}

function Apply-AppLockerPolicy {
    param([string] $AppLockerXmlPath)

    Write-Host "`n[AppLocker] Deploying AppLocker rules..." -ForegroundColor Magenta

    if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
        Write-Host "  Warning: AppLocker cmdlets unavailable on this Windows edition" -ForegroundColor Yellow
        return
    }

    if ($PSCmdlet.ShouldProcess($AppLockerXmlPath, 'Replace local AppLocker policy')) {
        Set-AppLockerPolicy -XMLPolicy $AppLockerXmlPath -Merge
        Write-Host '  AppLocker rules deployed successfully' -ForegroundColor Green
    }
}

Assert-Administrator

Write-Host "`nWindows Local Policy Configuration Script (LGPO Emulator)`n" -ForegroundColor Cyan

$policy = Get-DefaultPolicy
if ($PolicyPath) {
    Write-Host "Loading custom policy from: $PolicyPath" -ForegroundColor Yellow
    try {
        $custom = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json -AsHashtable
        Merge-Hashtable -Base $policy -Override $custom
        Write-Host 'Custom policy merged successfully' -ForegroundColor Green
    } catch {
        Write-Host "Warning: Could not load custom policy: $_" -ForegroundColor Yellow
    }
}

Backup-CurrentPolicy -BackupPath $BackupPath

Apply-PasswordPolicy -PasswordPolicy $policy.PasswordPolicy -LockoutPolicy $policy.LockoutPolicy
Apply-SecurityOptions -SecurityOptions $policy.SecurityOptions

if (-not $SkipUAC) {
    Apply-UACPolicy -UAC $policy.UAC
}
if (-not $SkipAuditPolicy) {
    Apply-AuditPolicy -AuditPolicy $policy.AuditPolicy
}
if (-not $SkipEventLog) {
    Apply-EventLogPolicy -EventLog $policy.EventLog
}
if (-not $SkipCryptography) {
    Apply-CryptographyPolicy -Cryptography $policy.Cryptography
}
if (-not $SkipNetworkSecurity) {
    Apply-NetworkSecurityPolicy -NetworkSecurity $policy.NetworkSecurity
}
if (-not $SkipRemoteDesktop) {
    Apply-RemoteDesktopPolicy -RemoteDesktop $policy.RemoteDesktop
}
if (-not $SkipDefenderPolicy) {
    Apply-DefenderPolicy -Defender $policy.Defender
}
if (-not $SkipFirewallPolicy) {
    Apply-FirewallPolicy -Firewall $policy.Firewall
}
if (-not $SkipEdgePolicy) {
    Apply-EdgePolicy -Edge $policy.Edge
}
if ($AppLockerXmlPath) {
    Apply-AppLockerPolicy -AppLockerXmlPath $AppLockerXmlPath
}

if ($PSCmdlet.ShouldProcess('Windows policy refresh', 'Refresh local policy')) {
    try {
        Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\gpupdate.exe') -ArgumentList @('/target:computer', '/force')
        Write-Host '  Group policy refreshed' -ForegroundColor Green
    } catch {
        Write-Host "  Warning: gpupdate failed: $_" -ForegroundColor Yellow
    }
}

Write-Host "`nLocal policy configuration completed. Review the backup and event logs, then restart if required.`nBackup Location: $BackupPath`n" -ForegroundColor Green
