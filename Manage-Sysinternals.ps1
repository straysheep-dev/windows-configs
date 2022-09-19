# Update Sysmon, and get latest Sysinternals tools

# This script currently contains no functions and can be run directly:
# PS :\> .\Manage-Sysinternals.ps1

# Create the Tools folder if it does not exist
If(!(Test-Path -LiteralPath "C:\Tools")) {
	Write-Host -BackgroundColor Blue "Creating C:\Tools..."
	New-Item -ItemType Directory -Path "C:\Tools" > $null
	icacls.exe C:\Tools /reset > $null
	icacls.exe C:\Tools /inheritance:r > $null
	icacls.exe C:\Tools /grant SYSTEM:"(CI)(OI)(F)" > $null
	icacls.exe C:\Tools /grant BUILTIN\Administrators:"(CI)(OI)(F)" > $null
	icacls.exe C:\Tools /grant *S-1-1-0:"(CI)(OI)RX" > $null
}

# Prompt to download entire Sysinternals Suite or skip
while ( $DownloadSysinternalsSuite -ne "y" -or "n" ) {
	if ( $DownloadSysinternalsSuite -eq "y" ) {
		Write-Host -BackgroundColor Blue "Downloading Sysinternals Suite..."
		iex "(New-Object Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SysinternalsSuite.zip', 'C:\Tools\SysinternalsSuite.zip')"
		break
	}
	elseif ( $DownloadSysinternalsSuite -eq "n" ) {
		break
	}
	else {
		$DownloadSysinternalsSuite = Read-Host "Download the latest Sysinternals Suite? [y/n]"
	}
}

# sigcheck
If(!(Test-Path -LiteralPath "C:\Tools\sigcheck64.exe")) {
	Write-Host -BackgroundColor Blue "Downloading SigCheck..."
	iex "(New-Object Net.WebClient).DownloadFile('https://live.sysinternals.com/sigcheck64.exe', 'C:\Tools\sigcheck64.exe')"
}

# procexp
If(!(Test-Path -LiteralPath "C:\Tools\procexp64.exe")) {
	Write-Host -BackgroundColor Blue "Downloading Process Explorer..."
	iex "(New-Object Net.WebClient).DownloadFile('https://live.sysinternals.com/procexp64.exe', 'C:\Tools\procexp64.exe')"

	# Check signature
	Write-Host -BackgroundColor Blue "Checking procexp64.exe file signature..."
	Start-Sleep 1
	C:\Tools\sigcheck64.exe -accepteula -a -h -i -nobanner C:\Tools\procexp64.exe

	Write-Host ""

	while ( $ProcExpSignatureCheckOk -ne "y" -or "n" ) {
		if ( $ProcExpSignatureCheckOk -eq "y" ) {
			break
		}
		elseif ( $ProcExpSignatureCheckOk -eq "n" ) {
			Write-Host "Quitting."
			exit
		}
		else {
			$ProcExpSignatureCheckOk = Read-Host "Is the signature valid? [y/n]"
		}
	}

	# Replace taskmgr
	Write-Host ""

	while ( $ReplaceTaskMgr -ne "y" -or "n" ) {
		if ( $ReplaceTaskMgr -eq "y" ) {
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe\" -Name Debugger -Type String -Value "C:\TOOLS\PROCEXP64.EXE"
			break
		}
		elseif ( $ReplaceTaskMgr -eq "n" ) {
			break
		}
		else {
			$ReplaceTaskMgr = Read-Host "Replace taskmgr.exe with procexp64.exe? [y/n]"
		}
	}
}

Write-Host -BackgroundColor Blue "Updating Sysmon..."
Write-Host -BackgroundColor Blue "Downloading latest Sysmon binary..."
iex "(New-Object Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon64.exe', 'C:\Tools\Sysmon64.exe')"

while ( $ExistingConfig -ne "y" -or "n" ) {
	if ( $ExistingConfig -eq "y" ) {
		break
	}
	elseif ( $ExistingConfig -eq "n" ) {
		Write-Host -BackgroundColor Blue "Obtaining SwiftOnSecurity/sysmon-config v74..."
		iex "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml', 'C:\Tools\sysmon-config.xml')"

		If(!(Get-FileHash "C:\Tools\sysmon-config.xml" | Select-String '055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162')) {
			Write-Host -BackgroundColor Red "sysmon-config.xml hash verification failed. Quitting."
			Start-Sleep 3
			exit
		}
		else {
			Write-Host -BackgroundColor Green "sha256sum OK"
		}
		break
	}
	else {
		Write-Host "    If you have an existing Sysmon configuration file, copy it to C:\Tools\sysmon-config.xml and then enter 'y'"
		Write-Host "    Otherwise this script will download version 74 of https://github.com/SwiftOnSecurity/sysmon-config"
		Write-Host ""
		$ExistingConfig = Read-Host "Do you have an existing configuration file? [y/n]"
	}
}

Write-Host -BackgroundColor Blue "Checking Sysmon64.exe file signature..."
Start-Sleep 1
C:\Tools\sigcheck64.exe -accepteula -a -h -i -nobanner C:\Tools\Sysmon64.exe

Write-Host ""

while ( $SysmonSignatureCheckOk -ne "y" -or "n" ) {
	if ( $SysmonSignatureCheckOk -eq "y" ) {
		break
	}
	elseif ( $SysmonSignatureCheckOk -eq "n" ) {
		Write-Host "Quitting."
		exit
	}
	else {
		$SysmonSignatureCheckOk = Read-Host "Is the signature valid? [y/n]"
	}
}

If (Get-Process -Name "Sysmon64" -ErrorAction SilentlyContinue) {
	Write-Host -BackgroundColor Blue "Uninstalling current Sysmon services..."
	C:\Tools\Sysmon64.exe -accepteula -u
}

Start-Sleep 1

Write-Host -BackgroundColor Blue "Installing latest Sysmon binary..."
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml

Write-Host ""
Write-Host -BackgroundColor Blue "Done."
