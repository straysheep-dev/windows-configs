<#
  PowerStig-Setup.ps1
#>

Install-Module PowerSTIG -Scope CurrentUser

(Get-Module PowerStig -ListAvailable).RequiredModules | % {
   $PSItem | Install-Module -Force
}

# List all unique policies
$PowerStigVersion = (Get-Module PowerStig -ListAvailable).Version.ToString()
$StigDataPath = "C:\Users\Administrator\Documents\WindowsPowerShell\Modules\PowerSTIG\$PowerStigVersion\StigData\Processed\"
#(gci -Path $StigDataPath | Split-Path -Leaf).Replace(".xml","").Replace(".org.default","") | sort -Unique

# Create folders for each policy listed here (change these to fit your requirements)
$PolicyFileList = @("WindowsServer-2022-MS-1.5","WindowsDefender-All-2.4","WindowsFirewall-All-2.2","MS-Edge-1.8")
foreach ($PolicyFile in $PolicyFileList) {
	$DevPath = "C:\Tools\PowerSTIGDev\$PolicyFile"
	New-Item -Type Directory -Path $DevPath 2>$nul
	Copy-Item $StigDataPath$PolicyFile.org.default.xml -Destination $DevPath
}

# Set basic winrm settings
winrm quickconfig

# Get the name of the public profile
$interface_alias = (Get-NetConnectionProfile).InterfaceAlias

# Update the InterfaceAlias parameter with the name of the profile from above
Set-NetConnectionProfile -InterfaceAlias $interface_alias -NetworkCategory Private

# Update the WSMAN MaxEnvelopeSizekb
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192