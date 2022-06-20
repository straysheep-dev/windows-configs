# Install and manage OpenSSH server

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
			Write-Host -BackgroundColor Blue "Setting sshd listening port to $NewSSHPort"
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

	# This needs a more precise check to know if 'OpenSSH-Server-In-TCP' is the rule connected to $SSHPort
	# This way if another rule already exists using the same port as $SSHPort, and it isn't related to SSH, we can alert the user to choose a different port

	if (!(Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort })) {
		Write-Host -BackgroundColor Blue "Creating 'OpenSSH-Server-In-TCP'..."

		# Remove previous rule if it already exists
		Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule > $null
		# Add rule for inbound connections to $SSHPort
		New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $SSHPort
		# Print the rule details to terminal for review
		Get-NetFirewallPortFilter | Where-Object -Property LocalPort -eq "$SSHPort"
		Write-Host -BackgroundColor Blue "Done."
	} 
	else {
		Write-Host "Firewall rule 'OpenSSH-Server-In-TCP' found."
	}

}

function GetPublicKeys {

	# Prompt to download public keys from a URL

	# Authorized key file locations:
	#   C:\Users\$USER\.ssh\authorized_keys
	#   C:\ProgramData\ssh\administrators_authorized_keys

	if (!(Test-Path "C:\ProgramData\ssh\administrators_authorized_keys")) {
		Write-Host -BackgroundColor Blue "Creating C:\ProgramData\ssh\administrators_authorized_keys..."
		New-Item -Path "C:\ProgramData\ssh\administrators_authorized_keys" > $null
		icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r > $null
		icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /grant SYSTEM:"(F)" > $null
		icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /grant BUILTIN\Administrators:"(F)" > $null
	}

	while ( $DownloadAdminKey -ne "y" -or "n" ) {
		if ( $DownloadAdminKey -eq "y" ) {

			# Need more precise regex for URL's
			while ( $AdminKeyURL -notlike "https?://(\w+\.){1,4}?\w+(/.*+\.*+)?" ) {
				if ( $AdminKeyURL -match "https?://(\w+\.){1,4}?\w+(/\w+)?" ) {

					Write-Host -BackgroundColor Blue "Downloading $AdminKeyURL..."
					Add-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value (New-Object Net.WebClient).DownloadString($AdminKeyUrl)
					Write-Host -BackgroundColor Blue "administrators_authorized_keys content:"
					Get-Content "C:\ProgramData\ssh\administrators_authorized_keys"
					Write-Host -BackgroundColor Blue "Done."
					break
				}
				else {
					$AdminKeyURL = Read-Host "Type the full URL to the public key [url]"
				}
			}
			break
		}
		elseif ( $DownloadAdminKey -eq "n" ) {
			break
		}
		else {
			Write-Host ""
			$DownloadAdminKey = Read-Host "Add a public key to administrators_authorized_keys? [y/n]"
		}
	}

	$UserList = (Get-ChildItem C:\Users\ -ErrorAction SilentlyContinue | Select -Property Name | Where { $_.Name -notlike "Public" } | Out-String).trim()
	# $UserName needs to always reset to an empty string, in case this function is called multiple times from the same shell
	$UserName = ""

	while ( $DownloadUserKey -ne "y" -or "n" ) {
		if ( $DownloadUserKey -eq "y" ) {

			while ( $UserList -notcontains $UserName ) {
				if (($UserList -match $UserName) -and ($Username -match "\w+")) {

					# Create the .ssh folder and authorized_keys file
					if (!(Test-Path "C:\Users\$UserName\.ssh")) {
						New-Item -ItemType Directory -Path "C:\Users\$UserName\.ssh" > $null
					}
					if (!(Test-Path "C:\Users\$UserName\.ssh\authorized_keys")) {
						Write-Host -BackgroundColor Blue "Creating C:\Users\$UserName\.ssh\authorized_keys..."
						New-Item -ItemType File -Path "C:\Users\$UserName\.ssh\authorized_keys" > $null

						# This will need a more precise solution, so that $UserName is the owner, and is the only user with access to the file
						# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-7.2#example-5-grant-administrators-full-control-of-the-file
						$NewAcl = Get-Acl -Path C:\Users\$UserName\.ssh\authorized_keys
						$NewAcl.SetAccessRule.(New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "$UserName","FullControl","Allow")
						Set-Acl -Path C:\Users\$UserName\.ssh\authorized_keys -AclObject $NewAcl
					}

					# Need more precise regex for URL's
					while ( $UserKeyURL -notlike "https?://(\w+\.){1,4}?\w+(/.*+\.*+)?" ) {
						if ( $UserKeyURL -match "https?://(\w+\.){1,4}?\w+(/\w+)?" ) {

							Write-Host -BackgroundColor Blue "Downloading $UserKeyURL..."
							Add-Content -Path "C:\Users\$UserName\.ssh\authorized_keys" -Value (New-Object Net.WebClient).DownloadString($UserKeyUrl)
							Write-Host -BackgroundColor Blue "authorized_keys content:"
							Get-Content "C:\Users\$UserName\.ssh\authorized_keys"
							Write-Host -BackgroundColor Blue "Done."
							break
						}
						else {
							$UserKeyURL = Read-Host "Type the full URL to the public key [url]"
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
			$DownloadUserKey = Read-Host "Add a public key to authorized_keys for a user? [y/n]"
		}
	}
}

function InstallOpenSSHServer {

	if (!(Get-Service sshd -ErrorAction SilentlyContinue)) {

		while ( $InstallChoice -ne "y" -or "n" ) {
			if ( $InstallChoice -eq "y" ) {

				Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Add-WindowsCapability -Online

				# Start the service, this generates the C:\ProgramData\ssh folder and configuration files
				Start-Service sshd

				# Public key authentication only
				(Get-Content C:\ProgramData\ssh\sshd_config) -replace "^#?PasswordAuthentication.*$","PasswordAuthentication no" | Out-File -Encoding ASCII -FilePath C:\ProgramData\ssh\sshd_config
				Restart-Service sshd

				UpdateSSHPort

				# OPTIONAL but recommended:
				Set-Service -Name sshd -StartupType 'Automatic'

				GetPublicKeys
				
				break

			}
			elseif ( $InstallChoice -eq "n" ) {
				Write-Host "Exiting."
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

				Stop-Service sshd

				Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Remove-WindowsCapability -Online > $null
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
						$RemoveAllSSHData = Read-Host "Remove all SSH data (includes all users)? [y/n]"
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
		Write-Host ""
		Write-Host "Port: $SSHPort"
		if (Get-NetFirewallPortFilter -All | where { $_.LocalPort -eq $SSHPort }) {
			Write-Host "Firewall rule exists."
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
	elseif ("$Action" -like "GetPublicKeys")
	{
		if (Get-Service sshd -ErrorAction SilentlyContinue) {
			GetPublicKeys
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
		Write-Host "  GetPublicKeys"
		Write-Host ""
		Get-OpenSSHServerStatus
	}
}
