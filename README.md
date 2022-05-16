# windows-configs

Various configuration files for Microsoft Windows operating systems

### Licenses

Unless a different license is included with a file as `<filename>.copyright-notice` all files are released under the MIT license.

Examples in this README taken and adapted from the Microsoft documents:

- Microsoft Docs Examples: 
	* CC-BY-4.0
	* <https://github.com/MicrosoftDocs/PowerShell-Docs/blob/staging/LICENSE>
	* <https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/LICENSE>
	* <https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/LICENSE>
	* <https://github.com/MicrosoftDocs/sysinternals/blob/main/LICENSE>
- Win32-OpenSSH Wiki Examples:
	* <https://github.com/PowerShell/Win32-OpenSSH/wiki>

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
	* Fetches an array of popular security tools and utilities, mainly for malware and network analysis
	* Sysinternals Suite
	* Python3
	* PEStudio / CFF Explorer
	* IDA / Ghidra
	* Cutter
	* Wireshark
- [Manage-Sysinternals.ps1](/Manage-Sysinternals.ps1)
	* Currently focuses on installing and updating Sysmon
	* Optionally downloads the latest Sysinternals Suite
	* Creates the a `C:\Tools` folder with the correct permissions
- [Set-EdgePolicy.ps1](/Set-EdgePolicy.ps1)
	* Sets a secuity-focused system-wide policy for Microsoft Edge via the registry
	* Tries to follow the guidance of both, Microsoft Recommended Baselines and DISA STIG's Chromium guide:
		- https://www.microsoft.com/en-us/download/details.aspx?id=55319
		- https://static.open-scap.org/ssg-guides/ssg-chromium-guide-stig.html
- [Set-WinPrefs.ps1](/Set-WinPrefs.ps1)
	* A modified fork of version 3.10, 2020-07-15, <https://github.com/Disassembler0/Win10-Initial-Setup-Script>
	* Enables / sets many privacy and security focused settings via the registry and PowerShell
	* The version in this repo currently has no 'undo' function, see the source linked above instead for additional options
- [Tail-EventLogs.ps1](/Tail-EventLogs.ps1)
	* The `sudo tail -f /var/log/audit.log | grep ...` of PowerShell
	* Run with `.\Tail-EventLogs.ps1`

# Windows Baselining

See the tools available in the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

Choose what tools and policies to download that you'd like to apply to your environment.

The idea with the `.PolicyRules` files is they are configurations that are pre-made by Microsoft and ready to be installed using `LGPO.exe`

You can do all of this manually with PowerShell, and you will ultimately want to familiarize yourself with the descriptions of each setting should you run into any issues, but this will save a ton of time in getting things up and running.

Use `PolicyAnalyzer.exe` to view the `*.PolicyRules` files, compare them to other `*.PolicyRules` files or even your current system settings.

Use `LGPO.exe` to apply the configurations found in the `*.PolicyRules` files to your system.

For example the you might apply the [Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) for both Windows 11 Pro and the latest available version of Microsoft Edge.

Deploy and test these configurations in a temporary or virtual environment first, either a VM (local or cloud) or enabled the [Windows Sandbox](https://techcommunity.microsoft.com/t5/windows-kernel-internals-blog/windows-sandbox/ba-p/301849) feature.

Windows Sandbox is a temporary, and (depending on your `.wsb` configuration) fully isolated environment that can be started very quickly from either launching the application as you would any other, or by running a `.wsb` [configuration file](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file.md).

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

Add a local user to the Administrators group
```powershell
Add-LocalGroupMember -Group "Administrators" -Member User2
```

## UAC Prompt

What the prompt is and how / why it works:

<https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation#best-practices>

The secure desktop will obscure the entire desktop behind the prompt, where instead the insecure prompt will leave all of the desktop windows visible.

You can see the difference by changing this value (0x1=enabled, 0x0=disabled) here:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "PromptOnSecureDesktop -Type DWord -Value "0x1"
```

### UAC Prompt for local users

See the following documentation for guidance:

<https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users#best-practices>

The recommended setting is to automatically deny elevation of privileges to standard users.

If a user regularly requires administrative access, it's recommended to instead prompt for admin credentials. This way administrative tasks are performed only when needed, and the account is otherwise running in the context of a standard user.

- `0x0` = Automatically deny (all UAC actions require logging in as admin, best)
- `0x1` = Prompt for credentials on the secure desktop (recommended if not 0x0)
- `0x2` = Prompt for credentials (Default)

This setting prevents standard users from performing administrative actions:

```powershell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value "0x0"
```

### UAC Prompt for local admins

- `0x0` = Elevate without prompting (perform admin actions automatically, dangerous)
- `0x1` = Prompt for credentials (username / password)
- `0x2` = Prompt for interaction (y/n dialogue)
- `0x3` = Prompt for credentials when (custom defined action)

When logged in as an admin, this will prompt the user with a yes/no dialogue instead of credentials before performing actions:

```powershell
Set-ItemProptery -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value "0x2"
```

# Firewall Rules

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

## blockinboundalways

Likely the most useful setting here is `blockinboundalways`, which drops all inbound connections even if Windows has a default allow rule for the service.

On domain joined workstations, this will not disrupt connections to server file shares, and stops lateral movement between workstations.

Workstations typically should not need to talk to each other, with the server being the central point of authentication.

If you do need workstation to workstation communication, find the best way to monitor these connecitons for your environment and limit their scope with firewall rules if possible.

On personal, non domain joined devices this should be the default setting for travel and using untrusted LAN and WiFi networks. 

This way if the Public network profile is either not set, or the active profile has any inbound allowances that may have been unknowingly added by applications or processes, this will prevent inbound connections.

To enable `blockinboundalways` on all profiles with cmd.exe:
```cmd
netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound
```

To enable `blockinboundalways` on all profiles with powershell.exe: 
```powershell
cmd.exe /C netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound
```

To return inbound blocking rules for all profiles back to `blockinbound` which will drop all connections without a defined rule by default:
```powershell
cmd.exe /C netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

To enable `blockinboundalways` from within the GUI:

- `Network & Internet Settings > Status > Windows Firewall`
- For all three, `Domain`, `Public`, `Private`; Set to `On` if it isn't already
- Check `Blocks all incoming connections, including those on the list of allowed apps.`

To turn off this setting, uncheck the box via the GUI, or using PowerShell set the profile(s) back to `blockinbound`.


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

### AccessChk

<https://sirensecurity.io/blog/windows-privilege-escalation-resources/>

<https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk>

Evaluate what access to C:\$PATH is available to $USER:

```powershell
accesschk64.exe "$USER" c:\$PATH
```

### Sysmon

Installing Sysmon:

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

Cleanup:

- Option 1: Make the config file readable only by SYSTEM and BUILTIN\Administrator
	```powershell
	icacls.exe C:\Tools\sysmon-config.xml /inheritance:r
	icacls.exe C:\Tools\sysmon-config.xml /grant SYSTEM:"(F)"
	icacls.exe C:\Tools\sysmon-config.xml /grant BUILTIN\Administrators:"(F)"
	```
- Option 2: Delete the config file from the local machine
- Both: Monitor and log for execution of `Sysmon64.exe -c` which dumps the entire configuration whether it's still on disk or not. If you find this in your logs and did not run this, you may have been broken into.


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

```powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install the OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Install the OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the sshd service
Start-Service sshd
```

3. Configure:

```powershell
# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
```

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
icacls.exe .\authorized_keys /inheritance:r
icacls.exe .\authorized_keys /remove $OTHERUSERS
icacls.exe .\authorized_keys /remove bob
icacls.exe .\authorized_keys /remove alice
```

or if the user you'll be logging in as IS an administrator:
```powershell
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

**TO DO**

---
