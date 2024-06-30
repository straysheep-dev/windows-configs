<#
.SYNOPSIS

Cmdlet to manage OpenSSH Server for Windows

.DESCRIPTION

Often remote access on non-domain joined machines is difficult and insecure using WinRM. RDP is not always the best option either.

This cmdlet was created to help deploy and manage OpenSSH server on Windows endpoints. It automates a lot of the configuration process.

- Denies password auth, requires public key auth by default
- authorized_keys files are written with the correct permissions and encoding
- Adds utilties from the PowerShell/openssh-portable repo to C:\Tools\Scripts for reviewing permissions should anything go wrong
- Obtains and installs public keys from the GitHub API via username
- Automates changing the listening port for inbound SSH connections and the related firewall rule

The goal was to have an easy and ready-to-go way to prepare a Windows endpoint to be provisioned by Ansible, or simply for remote access by the user.

.PARAMETER InstallOpenSSHServer

Installs all of the OpenSSH server components from either winget or Windows Optional Features.

.PARAMETER ManagePublicKeys

Obtains additional public keys from the GitHub API based on username and appends them to the specified authorized_keys files for either the administrators or a regular user.

.PARAMETER UpdateSSHPort

Changes the accepted port and updates the firewall rule for SSH connections.

.PARAMETER UninstallOpenSSHServer

Uninstalls all of the OpenSSH server components. You can choose to keep or remove you host and authorized key files.

.EXAMPLE

PS> Manage-OpenSSHServer InstallOpenSSHServer

.EXAMPLE

PS> Manage-OpenSSHServer UpdateSSHPort

.LINK

https://github.com/PowerShell/Win32-OpenSSH
https://github.com/PowerShell/openssh-portable
https://github.com/straysheep-dev/windows-configs

#>

function UpdateSSHPort {

	# Change current SSH port
	$ChangeSSHPortChoice = ""
	$NewSSHPort = ""
	while ( $ChangeSSHPortChoice -ne "y" -or "n" ) {
		if ( $ChangeSSHPortChoice -eq "y" ) {

			do { $NewSSHPort = Read-Host "Enter new port number" } until (
				# Need more precise regex for 1-65535
				$NewSSHPort -match "^\d{1,5}$"
			)
			# Encoding must be ASCII plain-text, Tee-Object will make the configuration file unreadable by sshd.exe
			# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.2#replacement-operator
			# https://stackoverflow.com/questions/53867147/grep-and-sed-equivalent-in-powershell
			(Get-Content C:\ProgramData\ssh\sshd_config) -replace "^#?Port \d{1,5}","Port $NewSSHPort" | Out-File -Encoding ASCII -FilePath C:\ProgramData\ssh\sshd_config > $null
			Write-Host -BackgroundColor Blue "Setting sshd_config listening port to $NewSSHPort"
			break
		}
		elseif ( $ChangeSSHPortChoice -eq "n" ) {
			break
		}
		else {
			Write-Host ""
			$ChangeSSHPortChoice = Read-Host "Change the port for SSH to listen on? [y/n]"
		}
	}

	# The rest of the function always runs, so that even if the default port of 22 is kept, that firewall rule is still added during install
	Restart-Service sshd

	# https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse#start-and-configure-openssh-server
	$SSHPort = ((Get-Content 'C:\ProgramData\ssh\sshd_config' | Select-String "^#?Port\s\d{1,5}$" | Out-String).split(" ")[1]).trim()

	if (!(Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort })) {
		# Remove previous rule if it already exists
		Write-Host -BackgroundColor Blue -ForegroundColor Yellow "Removing previous rule..."
		Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule > $null
		# Add rule for inbound connections to $SSHPort
		Write-Host -BackgroundColor Blue "Creating 'OpenSSH-Server-In-TCP'..."
		New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort "$SSHPort" > $null
		# Print the rule details to terminal for review
		Start-Sleep 1
		(Get-NetFirewallPortFilter | Where-Object -Property LocalPort -eq "$SSHPort" | Get-NetFirewallRule | select Name | fl | Out-String).trim()
		(Get-NetFirewallPortFilter | Where-Object -Property LocalPort -eq "$SSHPort" | fl | Out-String).trim()
		Write-Host -BackgroundColor Blue "Done."
	}
	else {
		Write-Host "Firewall rule for OpenSSH Server found."
	}

}

function ManagePublicKeys {

	# IMPORTANT: If your authorized_keys text file has CRLF line endings, public key auth will fail.
	# https://github.com/PowerShell/Win32-OpenSSH/issues/2070
	# You must ensure the authorized_keys has Unix/Linux LF line endigs.
	# Using Out-File ... -Encoding ASCII solves this problem
	# You can also use (Get-Content .\file.txt).Replace("\r?\n","\n")
	# https://github.com/PowerShell/TextUtility/issues/31

	# Prompt to download public keys from GitHub

	# Authorized key file locations:
	#   C:\Users\$env:USERNAME\.ssh\authorized_keys
	#   C:\ProgramData\ssh\administrators_authorized_keys

	# IMPORTANT: Permissions must be specific for sshd to accept an authorized_keys file.
	# Three scripts exist in the project repo you can use if you still have issues:
	# https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/openssh/OpenSSHUtils.psm1
	# https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/openssh/FixHostFilePermissions.ps1
	# https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/openssh/FixUserFilePermissions.ps1

	if (!(Test-Path "C:\Tools\Scripts")) {
		Write-Host -BackgroundColor Blue "Creating C:\Tools\Scripts..."
		New-Item -Path C:\Tools -ItemType Directory 2>$nul | Out-Null
		# First, create the root folder with Everyone:RX Admin:RWX
		$FilePath = "C:\Tools"
		$UserName = "BUILTIN\Administrators"
		# Reset the ACL
		$EmptyAcl = New-Object -TypeName System.Security.AccessControl.FileSecurity -ArgumentList $null
		Set-Acl -Path $FilePath -AclObject $EmptyAcl
		foreach ($item in (gci -Recurse -Force $FilePath)) {
			Set-Acl -Path $FilePath -AclObject $EmptyAcl
		}
		# Construct the new ACL
		$NewAcl = Get-Acl -Path $FilePath
		$AccessRule1 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserName,"FullControl","ContainerInherit,ObjectInherit","None","Allow"
		$AccessRule2 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow"
		$AccessRule3 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "Everyone","ReadAndExecute,Synchronize","ContainerInherit,ObjectInherit","None","Allow"
		$NewOwner = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "$UserName"
		$NewAcl.SetAccessRule($AccessRule1)
		$NewAcl.SetAccessRule($AccessRule2)
		$NewAcl.SetAccessRule($AccessRule3)
		$NewAcl.SetAccessRuleProtection($true, $false)
		$NewAcl.SetOwner($NewOwner)
		Set-Acl -Path $FilePath -AclObject $EmptyAcl
		foreach ($item in (gci -Recurse -Force $FilePath)) {
			Set-Acl -Path $FilePath -AclObject $NewAcl
		}
		Get-Acl -Path $FilePath | fl
		New-Item -Path C:\Tools\Scripts -ItemType Directory 2>$nul | Out-Null
	}

	if (!(Test-Path "C:\Tools\Scripts\OpenSSHUtils.psm1")) {
		$url_list = @(
			"https://github.com/straysheep-dev/openssh-portable/raw/latestw_all/contrib/win32/openssh/FixHostFilePermissions.ps1",
			"https://github.com/straysheep-dev/openssh-portable/raw/latestw_all/contrib/win32/openssh/FixUserFilePermissions.ps1",
			"https://github.com/straysheep-dev/openssh-portable/raw/latestw_all/contrib/win32/openssh/OpenSSHUtils.psm1"
			)

		$sha256_list = @(
			"C9AEC7447482D76D81AA1E03C1C0C990DDB25A8C0C457B4FC35429AAFD00FB7C",
			"7A4503AC69DBC94191083D2DE7E3A4EF11705183A2129DEC7E99E106FF337C47",
			"83B4C9B2141A072FE2B1E72DA156AAB778467D3EA4D6026143F7542608B7F28E"
		)

		foreach ($url in $url_list) {
			# Split-Path works with URLs
			# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/split-path?view=powershell-7.4#-leaf
			$basename = echo $url | Split-Path -leaf
			Write-Host -BackgroundColor Blue "Downloading $basename..."
			iwr -Uri $url -OutFile C:\Tools\Scripts\$basename
			if (!(Get-FileHash C:\Tools\Scripts\$basename | sls $sha256_list)) {
				Write-Host -BackgroundColor Blue -ForegroundColor Red "[WARNING]SHA256: $basename"
			}
			else {
				Write-Host -BackgroundColor Blue -ForegroundColor Green "[OK]SHA256: $basename"
			}
		}
	}

	if (!(Test-Path "C:\ProgramData\ssh\administrators_authorized_keys")) {
		Write-Host -BackgroundColor Blue "Creating C:\ProgramData\ssh\administrators_authorized_keys..."
		New-Item -Path "C:\ProgramData\ssh\administrators_authorized_keys" > $null
	}

		# You can use the NTAccount constructor to specify "$Domain","$Account" with "$Domain" being optional.
		# With this you can change ownership without takeown.exe.
		# $EmptyAcl uses the first constructor example in the File Security class to create an empty FileSecurity object, and apply it to the `$FilePath`.
		# This is effective at undoing any misconfigured changes, and "resetting" the file back to its default permissions.
		# Default permissions are determined by inheritance.
		# Empty Constructor example: https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesecurity.-ctor?view=net-8.0#system-security-accesscontrol-filesecurity-ctor
		# File Security class: https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesecurity?view=net-8.0#constructors
		# takeown.exe example: https://superuser.com/questions/1819564/whats-the-difference-between-takeown-and-set-acl-for-changing-ownership
		# NTAccount() constructor: https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.ntaccount.-ctor?view=net-8.0
		$FilePath = "C:\ProgramData\ssh\administrators_authorized_keys"
		# Reset the ACL
		$EmptyAcl = New-Object -TypeName System.Security.AccessControl.FileSecurity -ArgumentList $null
		Set-Acl -Path $FilePath -AclObject $EmptyAcl
		# Construct the new ACL
		$NewAcl = Get-Acl -Path $FilePath
		$AccessRule1 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "NT AUTHORITY\SYSTEM","FullControl","Allow"
		$AccessRule2 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "BUILTIN\Administrators","FullControl","Allow"
		$NewOwner = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "BUILTIN\Administrators"
		$NewAcl.SetAccessRule($AccessRule1)
		$NewAcl.SetAccessRule($AccessRule2)
		$NewAcl.SetAccessRuleProtection($true, $false)
		$NewAcl.SetOwner($NewOwner)
		Set-Acl -Path $FilePath -AclObject $NewAcl
		Get-Acl -Path $FilePath | fl

	while ( $DownloadAdminKey -ne "y" -or "n" ) {
		if ( $DownloadAdminKey -eq "y" ) {

			# Changed from URL regex to GitHub public key API
			while ( $gh_username -notlike "[A-Za-z_-]+" ) {
				if ( $gh_username -match "[A-Za-z_-]+" ) {

					Write-Host -BackgroundColor Blue "Appending public key for user:$gh_username to administrators_authorized_keys..."
					# Invoke-RestMethod converts, or deserializes, JSON / XML content into [PSCustomObject] objects.
					# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-7.4#description
					Invoke-RestMethod -Uri https://github.com/$gh_username.keys | Out-File -FilePath "C:\ProgramData\ssh\administrators_authorized_keys" -Encoding ASCII -Append
					Write-Host -BackgroundColor Blue "administrators_authorized_keys content:"
					Get-Content "C:\ProgramData\ssh\administrators_authorized_keys"
					Write-Host -BackgroundColor Blue "Done."
					break
				}
				else {
					$gh_username = Read-Host "Enter the GitHub username"
				}
			}
			break
		}
		elseif ( $DownloadAdminKey -eq "n" ) {
			break
		}
		else {
			Write-Host ""
			$DownloadAdminKey = Read-Host "Add a public key from GitHub to administrators_authorized_keys? [y/n]"
		}
	}

	$UserList = (Get-ChildItem C:\Users\ -ErrorAction SilentlyContinue | Select -Property Name | Where { $_.Name -notlike "Public" } | Out-String).trim()
	# Variables need to always reset to an empty string, in case this function is called multiple times from the same shell
	$UserName = ""
	$gh_username = ""

	while ( $DownloadUserKey -ne "y" -or "n" ) {
		if ( $DownloadUserKey -eq "y" ) {

			while ( $UserList -notcontains $UserName ) {
				if (($UserList -match $UserName) -and ($Username -match "[A-Za-z_-]+")) {

					# Create the .ssh folder and authorized_keys file
					if (!(Test-Path "C:\Users\$UserName\.ssh")) {
						New-Item -ItemType Directory -Path "C:\Users\$UserName\.ssh" > $null
					}
					if (!(Test-Path "C:\Users\$UserName\.ssh\authorized_keys")) {
						Write-Host -BackgroundColor Blue "Creating C:\Users\$UserName\.ssh\authorized_keys..."
						New-Item -ItemType File -Path "C:\Users\$UserName\.ssh\authorized_keys" > $null
					}

					$FilePath = "C:\Users\$UserName\.ssh\authorized_keys"
					# Reset the ACL
					$EmptyAcl = New-Object -TypeName System.Security.AccessControl.FileSecurity -ArgumentList $null
					Set-Acl -Path $FilePath -AclObject $EmptyAcl
					# Construct the new ACL
					$NewAcl = Get-Acl -Path $FilePath
					$AccessRule1 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserName,"FullControl","Allow"
					$AccessRule2 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "NT AUTHORITY\SYSTEM","FullControl","Allow"
					$AccessRule3 = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "BUILTIN\Administrators","FullControl","Allow"
					$NewOwner = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "$UserName"
					$NewAcl.SetAccessRule($AccessRule1)
					$NewAcl.SetAccessRule($AccessRule2)
					$NewAcl.SetAccessRule($AccessRule3)
					$NewAcl.SetAccessRuleProtection($true, $false)
					$NewAcl.SetOwner($NewOwner)
					Set-Acl -Path $FilePath -AclObject $NewAcl
					Get-Acl -Path $FilePath | fl

					# Need more precise regex for GitHub usernames
					while ( $gh_username -notlike "[A-Za-z_-]+" ) {
						if ( $gh_username -match "[A-Za-z_-]+" ) {

							Write-Host -BackgroundColor Blue "Appending public key for user:$gh_username to authorized_keys..."
							Invoke-RestMethod -Uri https://github.com/$gh_username.keys | Out-File -FilePath  "C:\Users\$UserName\.ssh\authorized_keys" -Encoding ASCII -Append
							Write-Host -BackgroundColor Blue "authorized_keys content:"
							Get-Content "C:\Users\$UserName\.ssh\authorized_keys"
							Write-Host -BackgroundColor Blue "Done."
							break
						}
						else {
							$gh_username = Read-Host "Enter the GitHub username"
						}
					}
					break
				}
				else {
					Write-Host ""
					$UserList
					Write-Host ""
					$UserName = Read-Host "Which user?"
				}
			}
			break
		}
		elseif ( $DownloadUserKey -eq "n" ) {
			break
		}
		else {
			Write-Host ""
			$DownloadUserKey = Read-Host "Add a public key from GitHub to authorized_keys for a user? [y/n]"
		}
	}
}

function InstallOpenSSHServer {

	if (!((Test-Path "C:\Program Files (x86)\OpenSSH\sshd.exe") -or (Test-Path "C:\Windows\System32\OpenSSH\sshd.exe"))) {

		while ( $InstallChoice -ne "y" -or "n" ) {
			if ( $InstallChoice -eq "y" ) {

				while ( $SourceChoice -ne "1" -or "2" ) {
					if ( $SourceChoice -eq "1" ) {

						# Previous / current stable release pulling from Windows Optional Features
						Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Add-WindowsCapability -Online

						break
					}
					elseif ( $SourceChoice -eq "2" ) {

						# Winget obtains the latest release, using the project's unique winget ID
						# The winget package is recommended by the project
						# https://github.com/PowerShell/Win32-OpenSSH
						# |_https://github.com/PowerShell/openssh-portable
						winget install --id Microsoft.OpenSSH.Beta -e --source winget

						break
					}
					else {
						Write-Host ""
						Write-Host "1: Windows Optional Feature (built in)"
						Write-Host "2: winget (latest features)"
						$SourceChoice = Read-Host "Choose an installation source [1/2]"
					}
				}

				# Start the service, this generates the C:\ProgramData\ssh folder and configuration files
				Start-Service sshd

				# Set public key authentication only
				(Get-Content C:\ProgramData\ssh\sshd_config) -replace "^#?PasswordAuthentication.*$","PasswordAuthentication no" | Out-File -Encoding ASCII -FilePath C:\ProgramData\ssh\sshd_config
				Restart-Service sshd

				UpdateSSHPort

				# OPTIONAL but recommended:
				Set-Service -Name sshd -StartupType 'Automatic'

				ManagePublicKeys

				Get-Service sshd

				break

			}
			elseif ( $InstallChoice -eq "n" ) {
				Write-Host "Exiting."
				break
			}
			else {
				Write-Host ""
				$InstallChoice = Read-Host "Install OpenSSH Server? [y/n]"
			}
		}
		break
	}
	else {
		Write-Host "OpenSSH Server already installed."
		Write-Host ""
		Get-Service sshd
	}
}

function UninstallOpenSSHServer {
	if (Get-Service sshd -ErrorAction SilentlyContinue) {

		while ( $UninstallChoice -ne "y" -or "n" ) {

			if ( $UninstallChoice -eq "n" ) {
				break
			}
			elseif ( $UninstallChoice -eq "y" ) {

				Write-Host -BackgroundColor Blue "Stopping and disabling sshd service..."
				Stop-Service sshd
				Set-Service -ServiceName sshd -StartupType Disabled

				Start-Sleep 3

				# Interestingly, both uninstall paths can leave an empty sshd service and the firewall rule running on the system.
				# For now, just disable the service and delete the firewall rule. The sshd.exe binaries are always removed correctly.
				$SSHPort = ((Get-Content 'C:\ProgramData\ssh\sshd_config' | Select-String "^#?Port\s\d{1,5}$" | Out-String).split(" ")[1]).trim()
				Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort } | Remove-NetFirewallRule > $null
				Write-Host -BackgroundColor Blue "Firewall rule for sshd removed"

				Start-Sleep 1

				# Check the installation path for the winget version
				if (Test-Path -Path 'C:\Program Files (x86)\OpenSSH\sshd.exe') {
					winget uninstall --id Microsoft.OpenSSH.Beta
				}

				# Check the installation path for the Windows Optional Feature version
				if (Test-Path -Path 'C:\Windows\System32\OpenSSH\sshd.exe') {
					Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Remove-WindowsCapability -Online > $null
				}
				Write-Host -BackgroundColor Blue "OpenSSH Server Successfully Removed."

				while ( $RemoveAllSSHData -ne "y" -or "n" ) {
					if ( $RemoveAllSSHData -eq "y" ) {
						Write-Host "Removing C:\ProgramData\ssh..."
						Remove-Item -Recurse -Path "C:\ProgramData\ssh" -Force -ErrorAction SilentlyContinue
						Write-Host "Removing C:\Users\*\.ssh..."
						Remove-Item -Recurse -Path "C:\Users\*\.ssh" -Force -ErrorAction SilentlyContinue
						Write-Host -BackgroundColor Blue "All SSH data removed."
						break
					}
					elseif ( $RemoveAllSSHData -eq "n" ) {
						break
					}
					else {
						Write-Host ""
						$RemoveAllSSHData = Read-Host "Remove all SSH data (WARNING: includes all user data)? [y/n]"
					}
				}
				break
			}
			else {
				Write-Host ""
				$UninstallChoice = Read-Host "Uninstall OpenSSH Server? [y/n]"
			}
		}
	}
	else {
		Write-Host "OpenSSH Server not installed."
	}
}


function Get-OpenSSHServerStatus {
	if (Get-Service sshd -ErrorAction SilentlyContinue) {
		Get-Service sshd -ErrorAction SilentlyContinue
		$SSHPort = ((Get-Content 'C:\ProgramData\ssh\sshd_config' | Select-String "^#?Port\s\d{1,5}$" | Out-String).split(" ")[1]).trim()
		$StatusEnabled = (Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort } | Get-NetFirewallRule | Select Enabled | fl | Out-String).trim()
		$RuleName = (Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort } | Get-NetFirewallRule | Select Name | fl | Out-String).trim()
		Write-Host ""
		Write-Host "Firewall Rule Status"
		Write-Host "--------------------"
		if (Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort }) {
			Write-Host "$RuleName"
			Write-Host "Port : $SSHPort"
			Write-Host "$StatusEnabled"
		}
		else {
			Write-Host "Absent"
		}
	}
}

# Cmdlet to manage all functions
function Manage-OpenSSHServer {


	[CmdletBinding()]
	Param(
		[Parameter(Position = 0)]
		[string]$Action
	)

	if ("$Action" -like "InstallOpenSSHServer")
	{
		InstallOpenSSHServer
	}
	elseif ("$Action" -like "ManagePublicKeys")
	{
		if (Get-Service sshd -ErrorAction SilentlyContinue) {
			ManagePublicKeys
		}
		else {
			Write-Host "OpenSSH Server not installed."
		}
	}
	elseif ("$Action" -like "UpdateSSHPort")
	{
		if (Get-Service sshd -ErrorAction SilentlyContinue) {
			UpdateSSHPort
		}
		else {
			Write-Host "OpenSSH Server not installed."
		}
	}
	elseif ("$Action" -like "UninstallOpenSSHServer")
	{
		UninstallOpenSSHServer
	}
	else
	{
		Write-Host "Usage: Manage-OpenSSHServer <option>"
		Write-Host ""
		Write-Host "Options:"
		Write-Host "  InstallOpenSSHServer"
		Write-Host "  UninstallOpenSSHServer"
		Write-Host "  UpdateSSHPort"
		Write-Host "  ManagePublicKeys"
		Write-Host ""
		Get-OpenSSHServerStatus
	}
}