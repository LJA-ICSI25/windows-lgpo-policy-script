# Windows Local Policy Configuration

This repository contains `Set-WindowsLocalPolicies.ps1`, an administrator-run PowerShell script for applying common local security and application policies without the LGPO.exe utility.

> **Important:** Test in a disposable VM first. Local security policy changes can lock out accounts or affect applications. Run from an elevated 64-bit PowerShell session and keep a recovery path available.

## What it configures

- Password policy: minimum length, complexity, age, history, reversible encryption
- Account lockout policy
- Security options such as anonymous enumeration and administrator-name behavior
- Advanced audit policy categories
- Windows Defender and Microsoft Defender Firewall registry policies
- Optional Microsoft Edge policy registry settings
- Optional AppLocker rule deployment from an XML file
- Backup and restore of the local security database and registry policy keys

## Usage

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\\Set-WindowsLocalPolicies.ps1 -BackupPath C:\\PolicyBackup
```

Preview changes first:

```powershell
.\\Set-WindowsLocalPolicies.ps1 -WhatIf
```

Apply a custom policy file:

```powershell
.\\Set-WindowsLocalPolicies.ps1 -PolicyPath .\\policy.json -BackupPath C:\\PolicyBackup
```

Deploy AppLocker rules separately:

```powershell
.\\Set-WindowsLocalPolicies.ps1 -AppLockerXmlPath .\\AppLocker.xml
```

The script is intentionally explicit rather than pretending to implement every LGPO feature. Domain Group Policy, MDM policy, and policy areas not represented by the supplied configuration remain outside its scope.
