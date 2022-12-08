# windows-configs

Various configuration files for Microsoft Windows operating systems

### Licenses

Unless a different license is included with a file as `<filename>.copyright-notice` all files are released under the MIT license.

Examples in this README taken and adapted from the Microsoft documents:

- Microsoft Docs Examples: 
	* [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)
	* <https://github.com/MicrosoftDocs/PowerShell-Docs/blob/staging/LICENSE>
	* <https://github.com/MicrosoftDocs/windows-powershell-docs/LICENSE>
	* <https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/LICENSE>
	* <https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/LICENSE>
	* <https://github.com/MicrosoftDocs/sysinternals/blob/main/LICENSE>
	* <https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE>
- Win32-OpenSSH Wiki Examples:
	* <https://github.com/PowerShell/Win32-OpenSSH/wiki>
- Stack Overflow Licensing:
	* <https://stackoverflow.com/legal/terms-of-service#licensing>
	* [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/)

## To do:

- [x] Create table of contents
- [x] Write overview and summary of files
- [ ] Steps to resolve issues encountered when baselining systems
	* Event Logs
	* Debugging with Sysinternals
	* Backup / restore the registry

## Contents

- [Enable-BasicDefense.ps1](/Enable-BasicDefense.ps1)
	* Enables / sets many of the default settings in Windows Defender
	* Checks for SecureBoot
	* Controlled Folder Access
	* BitLocker Full Disk Encryption
	* Checks for Local Admin, provides commands to create a non-administrative user
- [Get-SecurityTools.ps1](/Get-SecurityTools.ps1)
	* This script will need updated and should only be used for reference
- [Manage-Sysinternals.ps1](/Manage-Sysinternals.ps1)
	* Installs and updates Sysmon
	* Installs Process Explorer, with the option to replace Task Manager
	* Option to download the latest Sysinternals Suite
	* Option to download just the following tools instead:
		- accesschk64
		- Autoruns64
		- tcpview64
		- strings64
		- vmmap64
		- whois64
	* Creates a`C:\Tools` folder that's world readable, only writable by admin or SYSTEM
- [Set-EdgePolicy.ps1](/Set-EdgePolicy.ps1)
	* Sets a secuity-focused system-wide policy for Microsoft Edge via the registry
	* Tries to follow the guidance of both, Microsoft Recommended Baselines and DISA STIG's Chromium guide:
		- https://www.microsoft.com/en-us/download/details.aspx?id=55319
		- https://static.open-scap.org/ssg-guides/ssg-chromium-guide-stig.html
- [Set-WinPrefsAdmin.ps1](/Set-WinPrefsAdmin.ps1)
	* A modified fork of version 3.10, 2020-07-15, <https://github.com/Disassembler0/Win10-Initial-Setup-Script>
	* Enables / sets many privacy and security focused settings via the registry and PowerShell
	* [Set-WinPrefsUser.ps1](/Set-WinPrefsUser.ps1) exists to also apply some settings to `HKCU`
	* The version in this repo currently has no 'undo' function, see the source linked above instead for additional options
- [Tail-EventLogs.ps1](/Tail-EventLogs.ps1)
	* The `sudo tail -f /var/log/audit.log | grep ...` of PowerShell
	* Run with `.\Tail-EventLogs.ps1`

# Windows Baselining

Creating a security baseline for Windows.

## Backup the Registry

Before making changes, it's useful to create a backup of the registry in a default or working state.

- [Enable-ComputerRestore](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/enable-computerrestore?view=powershell-5.1)
- [CheckPoint-Computer](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer?view=powershell-5.1)
- [Restore-Computer](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/restore-computer?view=powershell-5.1)

To create a system restore point:
```powershell
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "First restore point"
```

There are multiple restore point types:

- `APPLICATION_INSTALL`
- `APPLICATION_UNINSTALL`
- `DEVICE_DRIVER_INSTALL`
- `MODIFY_SETTINGS`
- `CANCELLED_OPERATION`

For registry changes specifically, `APPLICATION_INSTALL` is the type to use. It's also the default type, so it's not necessary to specify it on the commandline.

List all system restore points:
```powershell
Get-ComputerRestorePoint
```

After making changes, revert to a specific restore point:
```powershell
Restore-Computer -RestorePoint 1
```

The restore process can take several minutes, even when reverting a single change to the registry. Generally it takes about 3-4 minutes for local test VM's.

## Applying a Baseline

See the tools available in the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

Choose what tools and policies to download that you'd like to apply to your environment.

The idea with the `.PolicyRules` files is they are configurations that are pre-made by Microsoft and ready to be installed using `LGPO.exe`

You can do all of this manually with PowerShell, and you will ultimately want to familiarize yourself with the descriptions of each setting should you run into any issues, but this will save a ton of time in getting things up and running.

Use `PolicyAnalyzer.exe` to view the `*.PolicyRules` files, compare them to other `*.PolicyRules` files or even your current system settings.

Use `LGPO.exe` to apply the configurations found in the `*.PolicyRules` files to your system.

For example the you might apply the [Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) for both Windows 11 Pro and the latest available version of Microsoft Edge.

Deploy and test these configurations in a temporary or virtual environment first, either a VM (local or cloud) or enabled the [Windows Sandbox](https://techcommunity.microsoft.com/t5/windows-kernel-internals-blog/windows-sandbox/ba-p/301849) feature.

Windows Sandbox is a temporary, and (depending on your `.wsb` configuration) fully isolated environment that can be started very quickly from either launching the application as you would any other, or by running a `.wsb` [configuration file](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file.md).

# Managing Active Directory

Get all online AD computers:

```powershell
Get-ADComputer –filter *
```

Update Group Policy to sync with the Domain Controller via `cmd.exe`:

```cmd
gpupdate.exe
```

Push updates to Group Policy to sync with the Domain Controller via PowerShell:

- [Invoke-GPUpdate](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/invoke-gpupdate?view=windowsserver2022-ps)
- [Force a Remote Group Policy Refresh (GPUpdate)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj134201(v=ws.11))

```powershell
Invoke-GPUpdate -Computer "DOMAIN\COMPUTER-01" -Target "User" -RandomDelayInMinutes 0 -Force
```

*NOTE: some GPO's do not appear configured in the gpedit.msc snap in on endpoints, but will appear if you check their registry.* 

One example of this is Disabling Link-Local Multicast Name Resolution (LLMNR) protocol.

Setting Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution to Enabled on the Domain Controller and pushing the update with `Invoke-GPUpdate` or similar will not display this policy as Enabled on the endpoints, however it will show as set in their registry. This can be tested by changing the policy on the DC and refreshing each endpoint before checking again with `Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"`.


# Managing Windows Security

<https://docs.microsoft.com/en-us/powershell/module/defender/?view=windowsserver2022-ps>

| Cmdlet                  | Description
| ----------------------- | -------------------------------------------------------------------- |
| `Add-MpPreference`      | Modifies settings for Windows Defender.                              |
| `Get-MpComputerStatus`  | Gets the status of antimalware software on the computer.             |
| `Get-MpPreference`      | Gets preferences for the Windows Defender scans and updates.         |
| `Get-MpThreat`          | Gets the history of threats detected on the computer.                |
| `Get-MpThreatCatalog`   | Gets known threats from the definitions catalog.                     |
| `Get-MpThreatDetection` | Gets active and past malware threats that Windows Defender detected. |
| `Remove-MpPreference`   | Removes exclusions or default actions.                               |
| `Remove-MpThreat`       | Removes active threats from a computer.                              |
| `Set-MpPreference`      | Configures preferences for Windows Defender scans and updates.       |
| `Start-MpScan`          | Starts a scan on a computer.                                         |
| `Start-MpWDOScan`       | Starts a Windows Defender offline scan.                              |
| `Update-MpSignature`    | Updates the antimalware definitions on a computer.                   |

## Controlled Folder Access

> Protect your data from malicious apps such as ransomware

Write access must be granted to applications before modifications can be made to files within folders you define as protected. This is often the home directories under `C:\Users`, but can also be filesystems on external drives.

### Enable Controlled Folders

<https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-controlled-folders?view=o365-worldwide>

```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableControlledFolderAccess AuditMode # Enable the audit feature only
Set-MpPreference -EnableControlledFolderAccess Disabled  # Turn off Controlled Folder Access
```

### Customize Controlled Folder Access

<https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/customize-controlled-folders?view=o365-worldwide>

> **IMPORTANT**: Use `Add-MpPreference` to append or add apps to the list and not `Set-MpPreference`. Using the `Set-MpPreference` cmdlet will overwrite the existing list.

Add/remove protection for a folder:
```powershell
Add-MpPreference -ControlledFolderAccessProtectedFolders "c:\path\to\folder"
Remove-MpPreference -ControlledFolderAccessProtectedFolders "c:\path\to\folder"
```

Add/remove an application's access to protected folders:
```powershell
Add-MpPreference -ControlledFolderAccessAllowedApplications "c:\apps\test.exe"
Remove-MpPreference -ControlledFolderAccessAllowedApplications "c:\apps\test.exe"
```

## ASR (Attack Surface Reduction)

- [ASR Overview](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-deployment?view=o365-worldwide)
- [Rule List Reference](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide)
- [Rule GUIDs](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix)
- [Manage ASR Rules with PowerShell](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#powershell)

> | Rule Name | Rule GUID |
> |:-----|:-----|
> | Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5 |
> | Block Adobe Reader from creating child processes | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c |
> | Block all Office applications from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a |
> | Block credential stealing from the Windows local security authority subsystem (lsass.exe) | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 |
> | Block executable content from email client and webmail | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 |
> | Block executable files from running unless they meet a prevalence, age, or trusted list criterion | 01443614-cd74-433a-b99e-2ecdc07bfc25 |
> | Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc |
> | Block JavaScript or VBScript from launching downloaded executable content | d3e037e1-3eb8-44c8-a917-57927947596d |
> | Block Office applications from creating executable content | 3b576869-a4ec-4529-8536-b80a7769e899 |
> | Block Office applications from injecting code into other processes | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 |
> | Block Office communication application from creating child processes | 26190899-1602-49e8-8b27-eb1d0a1ce869 |
> | Block persistence through WMI event subscription (File and folder exclusions not supported). | e6db77e5-3df2-4cf1-b95a-636979351e5b |
> | Block process creations originating from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c |
> | Block untrusted and unsigned processes that run from USB | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 |
> | Block Win32 API calls from Office macros | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b |
> | Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 |

[ASR rules can be set in multiple modes](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-modes):

- `0` = Not configured / Disabled
- `1` = Block
- `2` = Audit
- `6` = Warn

Set a rule by it's GUID with PowerShell:

```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions <mode>
```

To enable all rules at once:

```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions 1
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions 1
```

[Confilcting Policy](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#policy-conflict)

> If a conflicting policy is applied via MDM and GP, the setting applied from MDM will take precedence.

[Exclude files and folders from ASR rules](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#exclude-files-and-folders-from-asr-rules)

> You can specify individual files or folders (using folder paths or fully qualified resource names), but you can't specify which rules the exclusions apply to.

[Excluding files and folders from ASR rules with PowerShell](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-deployment-implement?view=o365-worldwide#use-powershell-to-exclude-files-and-folders)

> ```powershell
> Add-MpPreference -AttackSurfaceReductionOnlyExclusions "<fully qualified path or resource>"
> ```

## Windows Sandbox

This documenation from Microsoft walks through every option for creating a Windows Sandbox Configuration (.wsb) file.

<https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file>

[Example 1](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file#example-1) provides a great base configuration for a malware analysis setup, where GPU and Networking are disabled, and a single folder from the host is available as read-only.

[Example 2](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file#example-2) demonstrates mapping different host folders to the sandbox as read-only or writable, and also reading from a cmd script on the host to execute on startup, which downloads and installs VSCode automatically.

The document also notes exposing the following features to the sandbox potentially affects the attack surface:

- vGPU (Enabled by default)
- Network (Enabled by default)
- Mapped folders and files that are writable
- Audio input (Enabled by default)
- Video input (Disabled by default)

There's also an option called `Protected Client` mode:

> "Applies more security settings to the sandbox Remote Desktop client, decreasing its attack surface."

This repo contains a `.wsb` configuration file geared towards malware analysis that follows Example 1, and disables / enables a few additional features. Without networking in the sandbox, you should plan to have installers for all of the required tools within a mapped folder (C:\Tools -> C:\Users\WDAGUtilityAccount\Documents\Tools). What you can do then is save a `.cmd` script within the mapped Tools directory to launch with as many install commands as you're able to automate:

So if the script is named `install.cmd`, the `.wsb` file contains these lines:

```wsb
  <LogonCommand>
    <Command>C:\Users\WDAGUtilityAccount\Documents\Tools\install.cmd</Command>
  </LogonCommand>
```

And `install.cmd` itself could look something like this:

```cmd
C:\Users\WDAGUtilityAccount\Documents\Tools\tool1.exe /install
C:\Users\WDAGUtilityAccount\Documents\Tools\tool2.exe /arg 1 /arg 2 /install
C:\Users\WDAGUtilityAccount\Documents\Tools\tool3.exe /install
```

# User Accounts

<https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1>

1. Create a local user
```powershell
$Password = Read-Host -AsSecureString
New-LocalUser "User2" -Password $Password -FullName "Second User" -Description "Description of this account."
Name    Enabled  Description
----    -------  -----------
User2  True     Description of this account.
```

<https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember?view=powershell-5.1>

2. Add the local user to a group; add them to "Users" so they may login

Add a local user to the Users group
```powershell
Add-LocalGroupMember -Group "Users" -Member User2
```

Add a local user to the Administrators group (only do this if [UAC](#uac-prompt) is configured correctly and the account will only be used for administration)
```powershell
Add-LocalGroupMember -Group "Administrators" -Member User2
```

You can run commands as another user, you'll be prompted for a password similar to `sudo`:
```powershell
runas /user:User2 cmd.exe
runas /user:Hostname\DomainUser2 powershell.exe -ep bypass -nop -w hidden iex <payload>
runas /user:Domain\DomainUser2 powershell.exe -ep bypass -nop -w hidden iex <payload>
```

See [HackTricks - Credential User Impersonation](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-local-privilege-escalation/access-tokens.md#credentials-user-impersonation) for more on this.

## UAC Prompt

What the UAC prompt is and how / why it works:

<https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users#best-practices>

> Countermeasure
> Configure the User Account Control: Behavior of the elevation prompt for standard users to Automatically deny elevation requests. This setting requires the user to log on with an administrative account to run programs that require elevation of privilege. As a security best practice, standard users should not have knowledge of administrative passwords. However, if your users have both standard and administrator-level accounts, we recommend setting Prompt for credentials so that the users do not choose to always log on with their administrator accounts, and they shift their behavior to use the standard user account.

What the Secure Desktop is and how / why it works:

<https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation#best-practices>

> Enable the User Account Control: Switch to the secure desktop when prompting for elevation setting. The secure desktop helps protect against input and output spoofing by presenting the credentials dialog box in a protected section of memory that is accessible only by trusted system processes.

The secure desktop will obscure the entire desktop behind the prompt, where instead the 'insecure' prompt will leave all of the desktop windows visible.

You can see the difference by changing this value (0x1=enabled, 0x0=disabled) here:

```powershell
# Enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "PromptOnSecureDesktop" -Type DWord -Value "0x1"
# Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "PromptOnSecureDesktop" -Type DWord -Value "0x0"
```

You can easily test if UAC is enabled for administrative actions by running the following:

```powershell
# https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs.md#uac-disabled
Start-Process powershell -Verb runAs "notepad.exe"
```

If you are not prompted to allow `notepad` to run, then UAC is not enabled.

### Configuring the UAC Prompt for local users

See the following documentation for guidance:

- [Microsoft Docs, Open Specifications on all UAC settings](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/12867da0-2e4e-4a4f-9dc4-84a7f354c8d9)
- [Microsoft Docs, UAC Best Practices](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users#best-practices)
- [DevBlogs, UAC Settings](https://devblogs.microsoft.com/oldnewthing/20160816-00/?p=94105)
- [HackTricks, UAC Bypass](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs.md#uac)
- [FuzzySecurity, UAC Attacks](https://www.fuzzysecurity.com/tutorials/27.html)

**Summary** 

If these are not set, you are potentially vulnerable to UAC bypass:

```powershell
# Check if UAC is active in Admin Approval Mode (value of 1) or inactive (value of 0), you will always want this active
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/958053ae-5397-4f96-977f-b7700ee461ec
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "EnableLUA"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "EnableLUA" -Type DWord -Value "0x1"

# Ensure all UAC prompts happen via the secure desktop prompt
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/9ad50fd3-4d8d-4870-9f5b-978ce292b9d8
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "PromptOnSecureDesktop -Type DWord -Value "0x1"

# Require credentials when running as Admin
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4
Set-ItemProptery -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value "0x1"

# Deny all elevation for standard users
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/15f4f7b3-d966-4ff4-8393-cb22ea1c3a63
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value "0x0"
# Require credentials for standard users
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value "0x1"
```

The recommended setting is to automatically deny elevation of privileges to standard users.

If a user regularly requires administrative access, it's recommended to instead prompt for admin credentials. This way administrative tasks are performed only when needed, and the account is otherwise running in the context of a standard user.

- `0x0` = Automatically deny (all UAC actions require logging in as admin, best)
- `0x1` = Prompt for credentials on the secure desktop (recommended if not 0x0)
- `0x2` = Prompt for credentials (Default)

This setting prevents standard users from performing administrative actions:

```powershell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value "0x0"
```

Alternatively, this allows the user to elevate privileges temporarily using the separate administrative account's credentials:

```powershell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value "0x1"
```

### UAC Prompt for local admins

- `0x0` = Elevate without prompting (perform admin actions automatically, dangerous)
- `0x1` = Prompt for credentials (username / password) on the secure desktop
- `0x2` = Prompt for interaction (y/n dialogue) on the secure desktop

This will prompt the administrator account for any valid administrator credentials via the secure desktop to take actions:

```powershell
Set-ItemProptery -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value "0x1"
```

When logged in as an admin, this will prompt the user with a yes/no dialogue instead of credentials before performing actions:

```powershell
Set-ItemProptery -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value "0x2"
```

# Network

Display general network information
```
ipconfig
ipconfig /all
ipconfig /flushdns
```

Show all active protocols and connections
```cmd
netstat -ano
```

Show the executable involved in creating all active protocols and connections
```cmd
netstat -abno    # Requires Administrative privileges
```

Display the arp table
```
arp -a
```

Display the routing table
```cmd
route print
```

Additional tools for network visibility:

- <https://www.wireshark.org/>
- <https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview>

## Firewall Rules

Example baseline policy executed in `cmd.exe`:

```cmd
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles settings inboundusernotification enable
netsh advfirewall set allprofiles settings remotemanagement disable
netsh advfirewall set allprofiles logging maxfilesize 8000
netsh advfirewall set allprofiles logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log

netsh advfirewall show currentprofile
```

Example baseline policy executed in `PowerShell`:

```powershell
# https://docs.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2022-ps
Set-NetFirewallProfile -All -Enabled True
Set-NetFirewallProfile -All -DefaultInboundAction Block
Set-NetFirewallProfile -All -AllowInboundRules True
Set-NetFirewallProfile -All -AllowUnicastResponseToMulticast False
Set-NetFirewallProfile -All -NotifyOnListen True # Windows displays a notification when blocking an application
Set-NetFirewallProfile -All -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -All -LogMaxSizeKilobytes 8000
Set-NetFirewallProfile -All -LogAllowed False
Set-NetFirewallProfile -All -LogBlocked True
Set-NetConnectionProfile -NetworkCategory Public
```

There are three different network profiles in Windows: 

| Profile     | Description
| ----------- | -------------------------------------------------------------------------- |
| **Public**  | Considered untrusted, similar to being publicly accessible on the internet |
| **Domain**  | Considered trusted, typically a managed corporate network                  |
| **Private** | Considered trusted, a 'home' network                                       |

Get information about a specific network profile:

```powershell
Get-NetFirewallProfile -Name Domain
Get-NetFirewallProfile -Name Private
Get-NetFirewallProfile -Name Public
```

Sometimes you need to change your network profile, here's how with PowerShell:
```powershell
Set-NetConnectionProfile -NetworkCategory Public
```

Get general information about the firewall rules:
```powershell
Get-NetFirewallProfile -All
Get-NetFirewallRule -All
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow
Get-NetFirewallPortFilter -All | Where-Object -Property LocalPort -eq 22
```

Look for rules with specific ports:
```powershell
Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq 20 -or $_.LocalPort -eq 445 }
```

Look for rules within a range of ports:
```powershell
Get-NetFirewallPortFilter -All | where { $_.LocalPort -ge 20 -and $_.LocalPort -le 445 }
```

Load all active / allowed inbound port rules into the variable '$inboundrules':
```powershell
$inboundrules = Get-NetFirewallRule * | where { ($_.Direction -like "Inbound" -and $_.Action -like "Allow" -and $_.Enabled -like "True") }
```

List firewall rule name + display name for all active / allowed inbound ports:
```powershell
$inboundrules | Select-Object -Property Name,DisplayName
```

List all unique active / allowed  inbound ports:
```powershell
$inboundrules | Get-NetFirewallPortFilter | Select-Object -Property LocalPort -Unique
```

List DisplayName + port information for all inbound rules currently enabled and allowed:

```powershell
Get-NetFirewallRule -Direction "Inbound" -Enabled "true" -Action "Allow" | ForEach-Object {
    echo ""
    ($_ | Select-Object -Property DisplayName | fl | Out-String).trim()
    ($_ | Select-Object -Property Profile | fl | Out-String).trim()
    ($_ | Get-NetFirewallPortFilter | Select-Object -Property Protocol,LocalPort | fl | Out-String).trim()
}
```

Example result of the previous command:

```
...
DisplayName : Microsoft Edge (mDNS-In)
Profile : Any
Protocol  : UDP
LocalPort : 5353

DisplayName : Cortana
Profile : Domain, Private, Public
Protocol  : Any
LocalPort : Any
...
```

### blockinboundalways / -AllowInboundRules False

Likely the most useful setting(s) available:

```powershell
#cmd.exe
netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound

#powershell
Set-NetFirewallProfile -AllowInboundRules False
```
...which drops all inbound connections even if Windows has a default allow rule for the service.

On domain joined workstations, this will not disrupt connections to server file shares and stops lateral movement between workstations.

Workstation typically should not need to talk to each other, with the server being the central point of authentication.

**Keep in mind on cloud instances of Windows in Azure / AWS / GCP this will likely lock you out of the machine**

On personal, non domain joined workstations this should be the default setting, and an absolute must for travel / using untrusted LAN and WiFi networks.

To enable this setting from within the GUI:

- `Network & Internet Settings > Status > Windows Firewall`
- For all three, `Domain`, `Public`, `Private`:
- Set to `On`
- Check `Blocks all incoming connections, including those on the list of allowed apps.`

To turn off this setting via the GUI: 
- Uncheck `Blocks all incoming connections, including those on the list of allowed apps.`

## LLMNR

<https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/>

Disable via GPO:

- Group Policy Management
- Forest: `<DOMAIN>.local` > Domains > `<DOMAIN>.local` > `Right-Click`
- Create a GPO in this domain, and Link it here...
- Name it "LLMNR" or something meaningful, click OK
- Computer Configuration > Administrative Templates > Network > DNS Client
- Turn Off Multicast Name Resolution > Enabled
- `Right-Click` the policy name under `<DOMAIN>.local` and choose `Enforced`

*You'll need to restart the endpoints, or refresh the group policy on each endpoint manually to ensure these changes take effect immediately*

Update Group Policy via PowerShell:

```powershell
Get-ADComputer -filter * | foreach{ Invoke-GPUpdate -computer $_.name -RandomDelayInMinutes 0 -force}
```

Update Group Policy via cmd.exe:

```cmd
gpupdate
```

Disable LLMNR via PowerShell:

```powershell
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
```

Disable LLMNR via cmd.exe:

```cmd
REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient”
REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ” EnableMulticast” /t REG_DWORD /d “0” /f
```

## Mitigate IPv6 MitM Attacks

<https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course>

<https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/>

<https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/>

There are three predefined firewall rules to change from allow to block.

This walks through setting these rules as a GPO on a Domain Controller, but you can create the same rules manually on endpoints via Windows Defender Firewall.

Test these rules in an environment with ADCS configured by enabling them, updating Group Policy on each machine, then rebooting endpoints and signing in as a Domain Admin on any of them with mitm6 running. The attack(s) will no longer fire when these rules are in place.

Here are the commands to run on the attacker machine:

```bash
# In one terminal window:
sudo /home/kali/.local/bin/mitm6 -i eth0 -v -d TESTDOMAIN.local
# In another:
impacket-ntlmrelayx -6 -t ldaps://<dc-ip> -wh fakewpad.testdomain.local -l loot
```

- Group Policy Management
- Forest: `<DOMAIN>.local` > Domains > `<DOMAIN>.local` > `Right-Click`
- Create a GPO in this domain, and Link it here...
- Name it "IPv6" or something meaningful, click OK
Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall with Advanced Security > [Inbound|Outbound] Rules
- Create new custom rules for all three, there are usually none defined in Group Policy Management on the DC when defining a new GPO.

- (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-IN)
	* Name: Block - (DHCPV6-In)
	* Protocol type: UDP
	* Protocol number: 17
	* Local Port: Specific Ports, 546
	* Remote Port: Specific Ports, 547
	* This program: %SystemRoot%\system32\svchost.exe

- (Inbound) Core Networking - Router Advertisement (ICMPv6-IN)
	* Name: Block - Router Advertisement (ICMPv6-In)
	* Protocol type: ICMPv6
	* Protocol number: 58
	* Local port: All Ports
	* Remote port: All Ports
	* Specific ICMP types: [x] Router Advertisement
		- ICMP Type: 0
		- ICMP Code: Any
	* This program: System

- (Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-Out)
	* Name: Block - (DHCPV6-Out)
	* Protocol type: UDP
	* Protocol number: 17
	* Local Port: Specific Ports, 546
	* Remote Port: Specific Ports, 547
	* This program: %SystemRoot%\system32\svchost.exe

- `Right-Click` the policy name under `<DOMAIN>.local` and choose `Enforced`

*You'll need to restart the endpoints or refresh the group policy on each endpoint manually to ensure these changes take effect immediately*

Update Group Policy via PowerShell:

```powershell
Get-ADComputer -filter * | foreach{ Invoke-GPUpdate -computer $_.name -RandomDelayInMinutes 0 -force}
```

Update Group Policy via cmd.exe:

```cmd
gpupdate
```

## Enable SMB Signing

<https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing>

Default for Workstations = 0
Default for Server = 1

Enable SMB Signing via PowerShell:

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1
```

Enable SMB Signing on a Domain Controller via a GPO:

- Group Policy Management
- Forest: `<DOMAIN>.local` > Domains > `<DOMAIN>.local` > `Right-Click`
- Create a GPO in this domain, and Link it here...
- Name it "SMB Signing" or something meaningful, click OK
- Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
- Microsoft network server: Digitally sign communications (always) > Enable
- Microsoft network client:  Digitally sign communications (always) > Enable
- `Right-Click` the policy name under `<DOMAIN>.local` and choose `Enforced`

*You'll need to restart the endpoints or refresh the group policy on each endpoint manually to ensure these changes take effect immediately*

Update Group Policy via PowerShell:

```powershell
Get-ADComputer -filter * | foreach{ Invoke-GPUpdate -computer $_.name -RandomDelayInMinutes 0 -force}
```

Update Group Policy via cmd.exe:

```cmd
gpupdate
```

# Filesystem Permissions

How to do the equivalent of `chmod` operations in Windows.

## icacls.exe

Change ownership recursively of a file(s) or folder(s) to Administrator:

```powershell
takeown.exe /F .\ExampleDir\ /A /R
```

Change ownership back to a standard user (system is either local pc name or domain name, and user is a local or domain user):

```powershell
takeown.exe /S $SYSTEM /U $USER /F .\ExampleDir\
```

Reset to default permissions:

```powershell
icacls.exe .\ExampleDir\ /reset
```

Permit read-only access to a **folder** for everyone (removes any inherit or current write or modify permissions with /inheritance:r):

**NOTE**: sid `*S-1-1-0` means `everyone`

**NOTE**: similar to `chmod a=rX -R ./ExampleFolder` in Linux

```powershell
icacls.exe .\ExampleDir\ /inheritance:r /grant *S-1-1-0:"(CI)(OI)RX"
```

The purpose of `CI` and `OI` is to allow the "synchronize" permission, which allows directory traversal and if missing, denies it even if RX permission is granted

Do that same, but to a single file; this does not require `(CI)(OI)`:

```powershell
icacle.exe .\example.md /inheritance:r /grant *S-1-1-0:"RX"
```

Grant specific users full access to a single file, here only SYSTEM and the bultin Administrators accounts may access the specified file:

```powershell
icacls.exe .\administrators_authorized_keys /inheritance:r
icacls.exe .\administrators_authorized_keys /grant SYSTEM:"(F)"
icacls.exe .\administrators_authorized_keys /grant BUILTIN\Administrators:"(F)"
```

To create a directory with read-only / execute access for everyone, and full / write access only for Administrators:

```powershell
icacls.exe .\ExmapleFolder /inheritance:r
icacls.exe .\ExmapleFolder /grant SYSTEM:"(F)"
icacls.exe .\ExmapleFolder /grant BUILTIN\Administrators:"(F)"
icacls.exe .\ExmapleFolder /grant *S-1-1-0:"RX"
```

The above is similar to `chmod a=rX -R ./ExampleFolder; chmod o=rwX -R ./ExampleFolder; chown root:root ./ExmapleFolder` on Linux

## SysInternals

Overview:

<https://docs.microsoft.com/en-us/sysinternals/>

Download individual tools directly:

<https://live.sysinternals.com/>

Download the entire suite as a zip archive:

<https://download.sysinternals.com/files/SysinternalsSuite.zip>


### AccessChk

- <https://live.sysinternals.com/accesschk64.exe>
- <https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk>

See the following blog for additional uses of AccessChk:
- <https://sirensecurity.io/blog/windows-privilege-escalation-resources/>

Evaluate what access to C:\$PATH is available to $USER:

```powershell
accesschk64.exe "$USER" c:\$PATH
```

### Sysmon

- <https://live.sysinternals.com/Sysmon64.exe>
- <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

**Installing Sysmon**

Open an administrative PowerShell session.

Create the tools directory with the correct permissions:

```powershell
mkdir C:\Tools
icacls.exe C:\Tools /inheritance:r
icacls.exe C:\Tools /grant SYSTEM:"(F)"
icacls.exe C:\Tools /grant BUILTIN\Administrators:"(F)"
icacls.exe C:\Tools /grant *S-1-1-0:"(CI)(OI)RX"
```

Download and install Sysmon and the starter configuration file (if you did not write your own).

```powershell
cd C:\Tools

iex "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml', 'C:\Tools\sysmon-config.xml')"

iex "(New-Object Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon64.exe', 'C:\Tools\Sysmon64.exe')"

# Alternatively download the entire Sysinternals Suite
iex "(New-Object Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SysinternalsSuite.zip', 'C:\Tools\SysinternalsSuite.zip')"

# Optionally extract sigcheck (from the Sysinternals Suite) to run a signature check
C:\Tools\sigcheck64.exe -a -h -nobanner C:\Tools\Sysmon64.exe

# Uninstall the currently running Sysmon components with the newest binary if you already have an older version running (does not require reboot)
C:\Tools\Sysmon64.exe -accepteula -u

# Install the newest Sysmon components (does not require reboot)
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml
```

**NOTE**: This does not erase or remove current log files, and they can all still be read again after installing the new binary.

**Cleanup**

- Option 1: Make the config file readable only by SYSTEM and BUILTIN\Administrator
	```powershell
	icacls.exe C:\Tools\sysmon-config.xml /inheritance:r
	icacls.exe C:\Tools\sysmon-config.xml /grant SYSTEM:"(F)"
	icacls.exe C:\Tools\sysmon-config.xml /grant BUILTIN\Administrators:"(F)"
	```
- Option 2: Delete the config file from the local machine
- Both: Monitor and log for execution of `Sysmon64.exe -c` which dumps the entire configuration whether it's still on disk or not. If you find this in your logs and did not run this, you may have been broken into.

### Reading Logs

This is a quick start on how to read your Sysmon logs.
- <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.2>

These will help in building statements to parse logs conditionally with more granularity:
- <https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-if?view=powershell-7.2>
- <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-string?view=powershell-7.2>

Note that if you do not use `Sort-Object -Unique` or similar, logs will be displayed from oldest (top) to newest (bottom).

This webcast is an excellent resource, not just for rule creation but various ways to script and parse logs, and essentially a quick start to Sysmon threat hunting via the CLI and GUI:

- [Security Weekly Webcast - Sysmon: Gaining Visibility Into Your Enterprise](https://securityweekly.com/webcasts/sysmon-gaining-visibility-into-your-enterprise/)
- [Slide Deck](https://securityweekly.com/wp-content/uploads/2022/04/alan-stacilauskas-unlock-sysmon-slide-demov4.pdf)

Huge thanks to the presentors:

- [Alan Stacilauskas](https://www.alstacilauskas.com/)
- [Amanda Berlin](https://twitter.com/@infosystir)
- [Tyler Robinson](https://twitter.com/tyler_robinson)

Additional resources from the presentation and discord:

- [Poshim - Automated Windows Log Collection](https://www.blumira.com/integration/poshim-automate-windows-log-collection/)
- [Chainsaw](https://github.com/countercept/chainsaw)
- [Sysmon Modular - Olaf Hartong](https://github.com/olafhartong/sysmon-modular)
- [Sysmon Config - SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)

The technique of using `ForEach-Object { Out-String -InputObject $_.properties[x,y,z].value }` was highlighted during the webcast.

---

Set a starting time for logs to be queried. 

Doing this also speeds up the time to parse the log file.

```powershell
$Date = (Get-Date).AddMinutes(-30)
$Date = (Get-Date).AddHours(-1)
$Date = (Get-Date).AddDays(-2)
```

**Network**

Show all unique DNS queries (ID 22):
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='22' } | ForEach-Object { Out-String -InputObject $_.properties[4].value } | Sort-Object -Unique
```

Show all DNS queries (ID 22) and when they were made:
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='22' } | Format-List | Out-String -Stream | Select-String "^\s+(UtcTime:|QueryName:)"
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='22' } | ForEach-Object { Out-String -InputObject $_.properties[1,4].value }
```

Show all network connections (ID 3), what executable made them, their timestamp, and destination:
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='3' } | Format-List | Out-String -Stream | Select-String "^\s+(UtcTime:|ProcessId:|Image:|DestinationIp:|DestinationHostname:)"

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='3' } | ForEach-Object { Out-String -InputObject $_.properties[1,4,14,15].value }
```

**ProcessCreation**

List all processes created by timestamp, PID, executable, commandline, executable hashes, and PPID:
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='1' } | Format-List | Out-String -Stream | Select-String "^\s+(UtcTime:|ProcessId:|Image:|CommandLine:|Hashes:|ParentProcessId:)"

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='1' } | ForEach-Object { Out-String -InputObject $_.properties[1,3,4,10,17,19].value }
```

List all details of all processes created:
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='1' } | Format-List | Out-String -Stream

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Date; Id='1' } | ForEach-Object { Out-String -InputObject $_.properties[0..20].value }
```

## OpenSSH

| Directory              | Description
| ---------------------- | ------------------------------------------------- |
| `C:\ProgramData\ssh\`  | Main configuration folder, `/etc/ssh/` equivalent |
| `C:\Users\$USER\.ssh\` | User folder, `~/.ssh` equivalent                  |

Steps to setup OpenSSH Server (The OpenSSH Client is typically installed by default).

1. Update Windows

2. Install OpenSSH Server Optional Feature

See the following Microsoft documentation of OpenSSH for additional context:

<https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse>

> ```powershell
> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
> 
> # Install the OpenSSH Client
> Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
> 
> # Install the OpenSSH Server
> Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
> 
> # Start the sshd service
> Start-Service sshd
> ```

3. Configure:

> ```powershell
> # OPTIONAL but recommended:
> Set-Service -Name sshd -StartupType 'Automatic'
> 
> # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
> if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
>     Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
>     New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
> } else {
>     Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
> }
> ```

Change the following in `C:\ProgramData\ssh\sshd_config`:
```
#PasswordAuthentication Yes
```
To:
```
PasswordAuthentication no
```

Place public key data into:
```
C:\Users\$USER\.ssh\authorized_keys
C:\ProgramData\ssh\administrators_authorized_keys
```

Like on Unix systems, the permissions must be correct on the authorized_key files. See the following page on the Win32-OpenSSH Wiki for detailed descriptions:

<https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-Win32-OpenSSH>

Then, if the user you'll be logging in as IS NOT an administrator:
```powershell
takeown.exe /F .\authorized_keys /S $HOSTNAME /U $USER
icacls.exe .\authorized_keys /reset
icacls.exe .\authorized_keys /inheritance:r
icacls.exe .\authorized_keys /grant $USER:"(F)"
```

or if the user you'll be logging in as IS an administrator:
```powershell
icacls.exe .\authorized_keys /reset
icacls.exe .\administrators_authorized_keys /inheritance:r
icacls.exe .\administrators_authorized_keys /grant SYSTEM:"(F)"
icacls.exe .\administrators_authorized_keys /grant BUILTIN\Administrators:"(F)"
```

---

## Scheduled Tasks

List all scheduled tasks by creation date:

```powershell
Get-ScheduledTask -TaskName * | Select -Property Date,Author,Taskname | Sort-Object -Property Date
```

View scheduled tasks' creation date in the GUI:

Task Scheduler > Task Scheduler (Local) > Task Scheduler Library > [TaskName] > Created

Autoruns will also quickly identify any scheduled tasks in the `Scheduled Tasks` tab.

- Hide: Windows Entries
- Hide: Microsoft Entries

<https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns>

#### Log and audit when a new scheduled task is created:

<https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698#security-monitoring-recommendations>

Using the GUI:

Run `gpedit.msc`

`Local Computer Policy > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > Audit Other Object Access Events`

Choose `Configure the following audit events`

Choose `Success`, then `Apply` and `OK`

Now you can query the event logs for occurances of scheduled task creation:

```powershell
Get-WinEvent -LogName "Security" | Where Id -eq "4698"
Get-WinEvent -LogName "Security" | Where Id -eq "4698" | Select -Property *
```

**TO DO**: Configure scheduled task creation auditing using only PowerShell

You can locate registry items just like searching the filesystem.

We know the policy for scheduled task logging is related to "Object Access":

```powershell
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\*object*access*" -Recurse -ErrorAction SilentlyContinue
```

After a possible delay while it searches, you should find it at this path, and be able to check it's values:

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Audit\ObjectAccess_AuditOtherObjectAccessEvents"
```

---

## WMI

- [PayloadsAllTheThings - WMI Event Subscription](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md#windows-management-instrumentation-event-subscription)

---

# Disk Management

This SuperUser answer by user VainMan is an excellent walkthrough of managing disks with just built in Windows tools:

- [SuperUser: How to Move the Recovery Partition on Windows 10](https://web.archive.org/web/20220612105334/https://superuser.com/questions/1453790/how-to-move-the-recovery-partition-on-windows-10)
	* <https://stackoverflow.com/legal/terms-of-service#licensing>
	* This section is released under the same [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/) license as the original post.

Additional documentation for this section:

- [Microsoft Docs: Capture and Apply the System and Recovery Partitions](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/capture-and-apply-windows-system-and-recovery-partitions?view=windows-11)
- [`diskpart.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskpart)
- [`dism.exe`](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/what-is-dism?view=windows-11)
- [`reagentc.exe`](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11)

This entire example essentially mirrors the SuperUser answer linked above, with only small additions or changes to focus on backing up the recovery partition, deleting it so that the `C:` partition can be extended, then appending the backup recovery partition image to the new end of the `C:` partition.

Mount the recovery partition
```cmd
diskpart
list disk
select disk <disk>
list partition
select partition <partition>
assign letter=R
exit
```
Create an image file with the `dd`-like `dism.exe` utility:
```cmd
dism /Capture-Image /ImageFile:C\recovery-partition.wim /CaptureDir:R:\ /Name:"Recovery"
```

Delete the current recovery partition:
```cmd
diskpart
select volume R
delete partition override
exit
```

- Extend the `C:\` drive in Disk Management
- Create a new volume (+ new drive letter)
- Apply the recovery image to the new volume using the new drive letter

```cmd
dism /Apply-Image /ImageFile:C:\recovery-partition.wim /Index:1 /ApplyDir:R:\
```

Register the new recovery location
```cmd
reagentc /disable
reagentc /setreimage /path R:\Recovery\WindowsRE
reagentc /enable
```

Unmount that drive letter to return the recovery partition to a 'hidden' state
```cmd
diskpart
select volume R
remove
exit
```

* You'll be able to see in Disk Management the Recovery (or whatever you named it) partition loses it's new drive letter

Optionally:
- Confirm the recovery partition is working with `reagentc /info`
- Boot into recovery `reagentc /boottore /logfile C:\Temp\Reagent.log`
- Delete the recovery image file `del C:\recovery-image.wim`

---

# Device Management

Restricting device and driver installation.

- [Manage Device Installation with Group Policy](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy)
- [System Defined Device Setup Classes Available to Vendors](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors)
- [System Defined Device Setup Classes Reserved for System Use](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use)
- [USB Device Descriptors](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-descriptors)

### Determine Device ID Strings

<https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy#determine-device-identification-strings>

The `Class GUID` is the type of device, for example a printer or a tablet.

The `Instance ID`, `Hardware IDs`, and `Compatible IDs` are identifiers for the device. The most specific is the `Instance ID`. This relates to that one device, and individual devices may have multiple `Instance ID`s. You'll need these ID's to 'allow' or 'deny' devices.

### Enum Device ID Strings with cmd.exe

You can start like this from a command prompt with [`pnputil`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil):

```cmd
pnputil /enum-devices /connected
```

If you were trying to find a single device, scroll through the list to determine the possible `Class GUID` of the device you're looking for.

Next you'd query connected devices of that class. This should narrow down the results enough for you to identify the exact device.

```cmd
pnputil /enum-devices /connected /class '{<guid>}'
```

In this case, the `Device Description` fields most closely matching and describing your device are usually the right ones.

Finally, query the device directly using the `Instance ID` (there may be multiple `Instand ID`s for the same device, query each one you find) and this time also print the `Hardware IDs` and `Compatible IDs` for each instance:

```cmd
pnputil /enum-devices /instanceid '<instance-id>' /ids
```

### Enum Device ID Strings with PowerShell

All the credit for this one goes to the [PowerShell Team](https://devblogs.microsoft.com/powershell/) over on the Microsoft DevBlogs:

- [Displaying USB Devices Using WMI](https://web.archive.org/web/20220903134605/https://devblogs.microsoft.com/powershell/displaying-usb-devices-using-wmi/)

This will gather all of your connected USB devices in a single line:

> ```powershell
> Get-WmiObject Win32_USBControllerDevice | %{[wmi]($_.Dependent)} | Sort-Object Description,DeviceID | ft Description,DeviceID -auto
> ```

We can append `ClassGuid`, `HardwareID`, and or `CompatibleID` onto an `fl` instead of an `ft` command to obtain the other IDs as well:

```powershell
Get-WmiObject Win32_USBControllerDevice | %{[wmi]($_.Dependent)} | Sort-Object Description,DeviceID | fl Description,DeviceID,ClassGuid,HardwareID,CompatibleID
```

In any case, you'll want to note the `Instance ID`, `Hardware IDs`, and `Compatible IDs` for use with policy configuration.

As mentioned in #3 of [Scenario steps - preventing installation of prohibited devices](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy#scenario-steps--preventing-installation-of-prohibited-devices), be sure you know exactly what will be blocked by the policy before deploying it. It's recommended to test all of this in a VM, as you can quickly recover from a policy that's too broad (which could block all external devices preventing you from using or recovering the machine).

Devices are evaluated by the `Apply layered order of evaluation for Allow and Prevent device installation policies across all device match criteria` policy in the following order:

- Device Instance IDs
- Device IDs (hardware / compatible)
- Device Setup Class
- Removeable Devices

`Device Instance IDs` are the most specific and always take precedence.

To allow only trusted devices while defaulting to blocking all others:

- Enter the ID's of devices you wish to allow under `Allow installation of devices that match any of these device instance IDs` and enable this policy
- Set `Apply layered order of evaluation for Allow and Prevent device installation policies across all device match criteria` policy to enable
- Enabled the `Prevent installation of removable devices` policy

Alternatively, and as a test, if you wish to block specific devices while allowing all by default:

- Enable the `Prevent installation of devices that match any of these device instance IDs` policy to block specific Instance IDs (precise)
- Enable the `Prevent installation of devices that match any of these device IDs` policy to block based on Hardware or Compatible IDs (broad)
- Click `Show` and add the IDs to this list
- Check `Also apply to matching devices that are already installed`

What the last point will do is disconnect any currently connected device(s) matching the policy and remove their drivers. In Windows 11 this will happen immediately after applying the policy.

*Remember you may need to specify multiple `Instance IDs` even for one device.*

You can confirm the devices are no longer visible with:

```cmd
pnputil.exe /enum-devices /connected /class '{<guid>}'
```

Disabling or setting that policy to Not Configured will reconnect the devices.

## Use Case: Blocking ISO Mounting

Taken directly from [Mubix](https://twitter.com/mubix)'s blog post:

- <https://malicious.link/post/2022/blocking-iso-mounting/>

What this does:

- Block ISO mounting from double clicking
- Block ISO mounting via the context menu
- Block programmatic ISO mounting via PowerShell

In the following GPO path:

```
Local Computer Policy > Administrative Templates > System > Device Installation > Device Installation Restrictions
```

Enable this policy:

```
Prevent installation of devices that match any of these device IDs
```

Check the "Also apply to matching devices that are already installed" option.

And set this as a value:

```
SCSI\CdRomMsft____Virtual_DVD-ROM_
```

Try to mount an ISO to validate this is working. All ISO files should fail to mount to the filesystem once this policy is in place.

#### Creating an ISO for Testing

On Ubuntu the `genisoimage` command can quickly create an ISO of any folder or file:

```bash
genisoimage -o <outfile>.iso <input-folder>
genisoimage -o my-docs.iso ./Documents
```

You can verify the ISO and contents with:

```bash
file ./my-docs.iso

sudo mkdir /mnt/my-iso
sudo mount my-docs.iso /mnt/my-iso

ls -l /mnt/my-iso

sudo umount /mnt/my-iso
sudo rm -rf /mnt/my-iso
```

Now move the `.iso` file over to your Windows machine (or if you did this in WSL it's already there) to confirm your policy configurations are working.

### Additional Use Case Microsoft Documentation

- [Allow only authorized USB device(s), block all other USB devices](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy#scenario-steps--preventing-installation-of-all-usb-devices-while-allowing-only-an-authorized-usb-thumb-drive)

- [Block a specific device from being installed](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy#scenario-2-prevent-installation-of-a-specific-printer-1)

**TO DO**: how to configure these policies with just PowerShell

---
