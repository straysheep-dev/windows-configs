# Windows 10 Defense Essentials Script
# Based on: https://github.com/Disassembler0/Win10-Initial-Setup-Script

# Usage:
# 	Open an Administrative powershell.exe prompt
# 	Temporarily set execution policy to bypass `powershell.exe -ep bypass`
# 	Dot source to load the functions `. .\windows-defense-essentials.ps1`
# 	Apply the settings with: `Enable-BasicDefense -Action Apply`
# 	Remove the settings with: `Enable-BasicDefense -Action Undo`

# To do:
# 	Check Core Isolation?
# 	Check Reputation-base protection settings?
# 	Disable automounting of external media?
# 	Check for, or setup and configure, Sysmon?
# 	echo "0.0.0.0 wpad." >> 'C:\Windows\System32\drivers\etc\hosts'?


# Colors
$Reset = $host.ui.RawUI.ForegroundColor      # Make current color a variable
$host.ui.RawUI.ForegroundColor = "Green"     # Change color using this line
# <Print information to terminal>
$host.ui.RawUI.ForegroundColor = $Reset      # Reset color to original color via $Reset variable using this line


function Set-SecurityBaseline {

	[CmdletBinding()]
	Param(
		[Parameter(Position = 0)]
		[string]$Action
	)

	if ("$Action" -like "Apply") 
	{
		# Apply settings


		
		# [ Network ]


		# Set current network profile to public (deny file sharing, device discovery, etc.)

		Write-Output ""
		Write-Output "Setting current network profile to public..."
		Set-NetConnectionProfile -NetworkCategory Public


		# Disable NetBIOS over TCP/IP on all currently installed network interfaces
		# https://attack.mitre.org/mitigations/M1042

		Write-Output "Disabling NetBIOS over TCP/IP..."
		Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2


		# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
		# https://attack.mitre.org/mitigations/M1042

		Write-Output "Disabling Link-Local Multicast Name Resolution (LLMNR)..."
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0


		# Enable SMB signing
		# https://attack.mitre.org/mitigations/M1037
		# https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing

		Write-Output "Enabling SMB signing..."
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1
		#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1


		# Disable SMBv1 Protocol
		# https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

		Write-Output "Disabling SMBv1 protocol..."
		Write-Host -ForegroundColor Cyan "[i]If prompted for Restart, choose No and restart after this script is done executing."
		Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol


		# Disable Remote Desktop
		# https://attack.mitre.org/mitigations/M1035/
		# https://attack.mitre.org/mitigations/M1042/

		Write-Output "Disabling Remote Desktop..."
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1


		# Shields Up -> Drop all inbound connections, disable (inbound) remote management, log all inbound connection attempts, increase logfile size
		# https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/best-practices-configuring#know-how-to-use-shields-up-mode-for-active-attacks

		Write-Output "Configuring Windows Defender Firewall Rules -> allprofiles state on..."
		netsh advfirewall set allprofiles state on
		Write-Host -ForegroundColor Cyan "[i]Set firewall to 'blockinboundalways'?"
		Write-Host "This will prevent inbound connections even if an allow rule exists."
		Write-Host -BackgroundColor Yellow -ForegroundColor DarkRed "WARNING: This setting will likely lock you out if this is a cloud instance."
		$BlockInboundChoice = ""
		while ($BlockInboundChoice -ne "y" -or "n") {
		    if ($BlockInboundChoice -eq "y") {
			Write-Host "Configuring Windows Defender Firewall Rules -> blockinboundalways,allowoutbound..."
			netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound
			break
		    }
		    elseif ($BlockInboundChoice -eq "n") {
			Write-Host "Configuring Windows Defender Firewall Rules -> blockinbound,allowoutbound..."
			netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
			break
		    }
		    else {
			$BlockInboundChoice = Read-Host "[y/n]"
		    }
		}
		Write-Output "Configuring Windows Defender Firewall Rules -> remotemanagement disabled..."
		netsh advfirewall set allprofiles settings remotemanagement disable
		Write-Output "Configuring Windows Defender Firewall Rules -> inboundusernotification enabled..."
		netsh advfirewall set allprofiles settings inboundusernotification enable
		Write-Output "Configuring Windows Defender Firewall Rules -> logging droppedconnections enabled..."
		netsh advfirewall set allprofiles logging droppedconnections enable
		Write-Output "Configuring Windows Defender Firewall Rules -> logging maxfilesize 16384 (~16MB)..."
		netsh advfirewall set allprofiles logging maxfilesize 16384
		Write-Output "Configuring Windows Defender Firewall Rules -> logging to %systemroot%\system32\LogFiles\Firewall\pfirewall.log..."
		netsh advfirewall set allprofiles logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log


		# Disable outbound mDNS, LLMNR connections, and Windows Search

		Write-Output "Configuring Windows Defender Firewall Rules -> block outbound mDNS..."
		Set-NetFirewallRule -DisplayName "mDNS*" -Direction Outbound -Action Block -Enabled True
		Write-Output "Configuring Windows Defender Firewall Rules -> block outbound LLMNR..."
		Set-NetFirewallRule -DisplayName "*LLMNR*" -Direction Outbound -Action Block -Enabled True



		# [ System UI ]


		# Disable Autoplay (automatically running executables when connecting external media / devices)
		# https://attack.mitre.org/mitigations/M1042

		Write-Output "Disabling Autoplay..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1


		# Hide network options from Lock Screen

		Write-Output "Hiding network options from Lock Screen..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1


		# Hide shutdown options from Lock Screen

		Write-Output "Hiding shutdown options from Lock Screen..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0


		# Show known file extensions

		Write-Output "Showing known file extensions..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0


		# Show hidden files

		Write-Output "Showing hidden files..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1



		# [ Security ]


		# Enable Controlled Folder Access (will need configured for your environment, this can be done on the fly through prompts in the GUI when an issue arises)
		# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/controlled-folders?view=o365-worldwide

		Write-Output "Enabling Controlled Folder Access..."
		Set-MpPreference -EnableControlledFolderAccess Enabled


		# Enable Mandatory ASLR
		# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide

		Write-Output "Enabling Mandatory ASLR..."
		Set-ProcessMitigation -System -Enable ForceRelocateImages


		# Validate SecureBoot
		# https://docs.microsoft.com/en-us/powershell/module/secureboot/?view=windowsserver2019-ps
		# https://attack.mitre.org/mitigations/M1046/

		Write-Output "Validating SecureBoot..."
		if (!(Test-Path -Path "HKLM:\SYSTEM\ControlSet001\Control\SecureBoot\State"))
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]SecureBoot Not enabled!"
			echo ""
		}
		else
		{
			Confirm-SecureBootUEFI
		}


		# Validate BitLocker full disk encryption is enabled
		# https://docs.microsoft.com/en-us/powershell/module/bitlocker/?view=windowsserver2019-ps

		Write-Output "Validating BitLocker..."
		if (Get-BitLockerVolume | Select-Object -Property ProtectionStatus | Select-String "Off")
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]BitLocker not enabled on one or more volumes, consider enabling it with:"
			Write-Host -ForegroundColor Green "Start > Windows System > Control Panel > System and Security > BitLocker Drive Encryption > Manage BitLocker > Turn on BitLocker"
			echo ""
		}
		elseif (Get-BitLockerVolume | Select-Object -Property ProtectionStatus | Select-String "On")
		{
			echo ""
			Write-Host -ForegroundColor Green "BitLocker is enabled..."
			echo ""
		}
		else
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]Cannot determine BitLocker status, make sure Windows is up to date..."
			echo ""
		}

		sleep 2


		# Check for Application Guard
		# https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/install-md-app-guard
		# https://attack.mitre.org/mitigations/M1048
		# https://attack.mitre.org/mitigations/M1050

		Write-Output "Checking for Application Guard..."
		if (Get-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard | Select-Object -Property State | Select-String "Disabled")
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]Application Guard is disabled, consider enabling it with:"
			Write-Host -ForegroundColor Green "Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard"
			echo ""
		}
		else
		{
			echo "[i]Application Guard is installed..."
		}

		sleep 2


		# Check if current user is a local Administrator
		# https://attack.mitre.org/mitigations/M1026
		# https://devblogs.microsoft.com/powershell-community/is-a-user-a-local-administrator/

		$CurrentUser = C:\Windows\System32\whoami.exe
		$Admins = Get-LocalGroupMember -Name Administrators | Select-Object -ExpandProperty Name

		if ($Admins -contains $CurrentUser)
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]You are running as a local Administrator."
			Write-Host -ForegroundColor Green "Create a separate user for daily use with:"
			echo ""
			Write-Host -ForegroundColor Cyan '$Password = Read-Host -AsSecureString'
			Write-Host -ForegroundColor Cyan 'New-LocalUser "NewUserNameHere" -Password $Password -FullName "Your Full Name" -Description "Description of this account.'
			Write-Host -ForegroundColor Cyan 'Add-LocalGroupMember -Group "Users" -Member "NewUserNameHere"'
			echo ""
			Write-Host -ForegroundColor Magenta 'See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/?view=powershell-5.1'
			echo ""
		}

		sleep 2



		# [ Software ]


		# Uninstall Internet Explorer

		Write-Output "Uninstalling Internet Explorer..."
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null
		Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null

		Write-Output "Done."
	}
	elseif ("$Action" -like "Undo") 
	{
		# Undo all settings; return to defaults



		# [ Network ]


		# Set current network profile to public (deny file sharing, device discovery, etc.)

		Write-Output ""
		Write-Output "Setting current network profile to public..."
		Set-NetConnectionProfile -NetworkCategory Public


		# Reset NetBIOS over TCP/IP options back to default value of 0

		Write-Output "Enabling NetBIOS over TCP/IP..."
		Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0


		# Remove Link-Local Multicast Name Resolution (LLMNR) protocol registry entry

		Write-Output "Enabling Link-Local Multicast Name Resolution (LLMNR)..."
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
		If ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
			Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
		}


		# Don't enforce SMB signing, default is 0 for Workstations, Servers ship with SMB signing enabled by default

		Write-Output "Disabling SMB signing (Only for clients)..."
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 0
		#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1


		# SMBv1 Protocol should no longer be used, not enabling it here.

		#Write-Output "Enabling SMBv1 protocol..."
		#Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol


		# Remote Desktop default value is already 0

		Write-Output "Reseting Remote Desktop policy..."
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1


		# Reset firewall back to allow all outbound, deny inbound, permit inbound that have explicit rules enabled.

		Write-Output "Reseting Windows Defender Firewall Rules..."
		netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
		netsh advfirewall set allprofiles settings remotemanagement disable
		netsh advfirewall set allprofiles settings inboundusernotification enable
		netsh advfirewall set allprofiles logging droppedconnections disable
		netsh advfirewall set allprofiles logging maxfilesize 4096


		# Reset outbound mDNS, LLMNR connections, and Windows Search to `Allow`

		Set-NetFirewallRule -DisplayName "mDNS*" -Direction Outbound -Action Allow -Enabled True
		Set-NetFirewallRule -DisplayName "*LLMNR*" -Direction Outbound -Action Allow -Enabled True



		# [ System UI ]


		# Enable Autoplay

		Write-Output "Enabling Autoplay..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0


		# Unhide network options from Lock Screen

		Write-Output "Unhiding network options from Lock Screen..."
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI"


		# Unhide shutdown options from Lock Screen

		Write-Output "Unhiding shutdown options from Lock Screen..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1


		# Hide file extensions

		Write-Output "Hiding file extensions..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1


		# Hide hidden files

		Write-Output "Hiding hidden files..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2



		# [ Security ]


		# Disable Controlled Folder Access

		Write-Output "Disabling Controlled Folder Access..."
		Set-MpPreference -EnableControlledFolderAccess Disabled


		# Disable Mandatory ASLR

		Write-Output "Disabling Mandatory ASLR..."
		Set-ProcessMitigation -System -Disable ForceRelocateImages


		# Validate SecureBoot
		# https://docs.microsoft.com/en-us/powershell/module/secureboot/?view=windowsserver2019-ps

		Write-Output "Validating SecureBoot..."
		if (!(Test-Path -Path "HKLM:\SYSTEM\ControlSet001\Control\SecureBoot\State"))
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]SecureBoot Not enabled!"
			echo ""
		}
		else
		{
			Confirm-SecureBootUEFI
		}


		# Validate BitLocker full disk encryption is enabled
		# https://docs.microsoft.com/en-us/powershell/module/bitlocker/?view=windowsserver2019-ps

		Write-Output "Validating BitLocker..."
		if (Get-BitLockerVolume | Select-Object -Property ProtectionStatus | Select-String "Off")
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]BitLocker not enabled on one or more volumes, consider enabling it with:"
			Write-Host -ForegroundColor Green "Start > Windows System > Control Panel > System and Security > BitLocker Drive Encryption > Manage BitLocker > Turn on BitLocker"
			echo ""
		}
		elseif (Get-BitLockerVolume | Select-Object -Property ProtectionStatus | Select-String "On")
		{
			echo ""
			Write-Host -ForegroundColor Green "BitLocker is enabled..."
			echo ""
		}
		else
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]Cannot determine BitLocker status, make sure Windows is up to date..."
			echo ""
		}

		sleep 2


		# Check for Application Guard
		# https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/install-md-app-guard

		Write-Output "Checking for Application Guard..."
		if (Get-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard | Select-Object -Property State | Select-String "Disabled")
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]Application Guard is disabled, consider enabling it with:"
			Write-Host -ForegroundColor Green "Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard"
			echo ""
		}
		else
		{
			echo "[i]Application Guard is installed..."
		}

		sleep 2


		# Check if current user is a local Administrator
		#
		# https://devblogs.microsoft.com/powershell-community/is-a-user-a-local-administrator/

		$CurrentUser = C:\Windows\System32\whoami.exe
		$Admins = Get-LocalGroupMember -Name Administrators | Select-Object -ExpandProperty Name

		if ($Admins -contains $CurrentUser)
		{
			echo ""
			Write-Host -ForegroundColor Yellow "[i]You are running as a local Administrator."
			Write-Host -ForegroundColor Green "Create a separate user for daily use with:"
			echo ""
			Write-Host -ForegroundColor Cyan '$Password = Read-Host -AsSecureString'
			Write-Host -ForegroundColor Cyan 'New-LocalUser "NewUserNameHere" -Password $Password -FullName "Your Full Name" -Description "Description of this account.'
			Write-Host -ForegroundColor Cyan 'Add-LocalGroupMember -Group "Users" -Member "NewUserNameHere"'
			echo ""
			Write-Host -ForegroundColor Magenta 'See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/?view=powershell-5.1'
			echo ""
		}

		sleep 2



		# [ Software ]


		# Enable Internet Explorer (there should be no reason to do this anymore, keeping commands here in case)

		#Write-Output "Re-enabling Internet Explorer..."
		#Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null
		#Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Enable-WindowsCapability -Online | Out-Null


		Write-Output "Done."
	}
	else 
	{
		Write-Output "Usage: Enable-BasicDefense [Apply|Undo]"
	}
}
