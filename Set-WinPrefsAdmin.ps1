##########
# Win 10 / Server 2016 / Server 2019 Initial Setup Script - Tweak library
# Author: Disassembler <disassembler@dasm.cz>
# Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
# Forked from version: v3.10, 2020-07-15
##########

##########
#region Privacy Tweaks
##########


# Disable Telemetry

Write-Output "Disabling Telemetry..."
# Settings > Privacy > Diagnostics & feedback > Diagnostic data
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0


# Application Telemetry, see GPO '\Windows Components\Application Compatibility\Turn off Application Telemetry'
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0

#Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
#Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null


# Disable Cortana

Write-Output "Disabling Cortana..."

If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0

If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

# Taskbar > Right click Cortana Icon (Show|Hide)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0

# Based on GPOs under "Administrative Templates\Windows Components\Search"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaInAADPathOOBE" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchPrivacy" -Type DWord -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1


# Disable Application suggestions and automatic installation

Write-Output "Disabling Application suggestions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0


# Disable Activity History feed in Task View
# Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled

Write-Output "Disabling Activity History..."
# Based on GPOs under "Administrative Templates\System\OS Policies"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 0


# Disable location feature and scripting for the location feature

Write-Output "Disabling location services..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1


# Disable automatic Maps updates

Write-Output "Disabling automatic Maps updates..."
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0


# Disable Feedback

Write-Output "Disabling Feedback..."
# Based on GPOs under "Administrative Templates\Windows Components\Data Collection & Preview Builds"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
#Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction Continue | Out-Null
#Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction Continue | Out-Null


# Disable Tailored Experiences

Write-Output "Disabling Tailored Experiences..."
If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1


# Disable Advertising ID

Write-Output "Disabling Advertising ID..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1


# Disable setting 'Let websites provide locally relevant content by accessing my language list'

Write-Output "Disabling Website Access to Language List..."
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1


# Disable access to camera
# Note: This disables access using standard Windows API. Direct access to device will still be allowed.

#Write-Output "Disabling access to camera..."
#If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
#	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
#}
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2


# Disable access to microphone
# Note: This disables access using standard Windows API. Direct access to device will still be allowed.

#Write-Output "Disabling access to microphone..."
#If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
#	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
#}
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2


# Disable Error reporting

Write-Output "Disabling Error reporting..."
# Control Panel > System and Security > Security and Maintenance > Report problems (On|Off)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null


# Stop and disable the service Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)

Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service..."
Stop-Service "DiagTrack" -WarningAction Continue
Set-Service "DiagTrack" -StartupType Disabled


# Disable recent files lists
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.

#Write-Output "Disabling recent files lists..."
#If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
#	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
#}
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1


##########
#region UWP Privacy Tweaks
##########


# Universal Windows Platform (UWP) is an API for common application and device controls unified for all devices capable of running Windows 10.
# UWP applications are running sandboxed and the user can control devices and capabilities available to them.


# Disable access to voice activation from UWP apps

Write-Output "Disabling access to voice activation from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2


# Disable access to notifications from UWP apps

Write-Output "Disabling access to notifications from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2


# Disable access to account info from UWP apps

Write-Output "Disabling access to account info from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2


# Disable access to contacts from UWP apps

Write-Output "Disabling access to contacts from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2


# Disable access to calendar from UWP apps

Write-Output "Disabling access to calendar from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2


# Disable access to phone calls from UWP apps

Write-Output "Disabling access to phone calls from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2


# Disable access to call history from UWP apps

Write-Output "Disabling access to call history from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2


# Disable access to email from UWP apps

Write-Output "Disabling access to email from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2


# Disable access to tasks from UWP apps

Write-Output "Disabling access to tasks from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2


# Disable access to messaging (SMS, MMS) from UWP apps

Write-Output "Disabling access to messaging from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2


# Disable access to radios (e.g. Bluetooth) from UWP apps

Write-Output "Disabling access to radios from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2


# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps

Write-Output "Disabling access to other devices from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2


# Disable access to diagnostic information from UWP apps

Write-Output "Disabling access to diagnostic information from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2


# Disable access to libraries and file system from UWP apps

Write-Output "Disabling access to libraries and file system from UWP apps..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny"


##########
#endregion UWP Privacy Tweaks
##########




##########
#region Security Tweaks
##########


# UAC (User Account Control)

Write-Output "Configuring UAC..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value "0x1"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value "0x1"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value "0x1"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value "0x1"


# Enable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled

Write-Output "Enabling Controlled Folder Access..."
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Continue


# Enabled ASR (Attack Surface Reduction Rules)

Write-Output "Enabling Attack Surface Reduction..."
# Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions 1
# Block Adobe Reader from creating child processes | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions 1
# Block all Office applications from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions 1
# Block credential stealing from the Windows local security authority subsystem (lsass.exe) | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions 1
# Block executable content from email client and webmail | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions 1
# Block executable files from running unless they meet a prevalence, age, or trusted list criterion | 01443614-cd74-433a-b99e-2ecdc07bfc25
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions 1
# Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc
Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions 1
# Block JavaScript or VBScript from launching downloaded executable content | d3e037e1-3eb8-44c8-a917-57927947596d
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions 1
# Block Office applications from creating executable content | 3b576869-a4ec-4529-8536-b80a7769e899
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions 1
# Block Office applications from injecting code into other processes | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions 1
# Block Office communication application from creating child processes | 26190899-1602-49e8-8b27-eb1d0a1ce869
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions 1
# Block persistence through WMI event subscription (File and folder exclusions not supported). | e6db77e5-3df2-4cf1-b95a-636979351e5b
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions 1
# Block process creations originating from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions 1
# Block untrusted and unsigned processes that run from USB | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions 1
# Block Win32 API calls from Office macros | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b
Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions 1
# Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions 1


# Disable Autorun

Write-Output "Disabling Autorun..."
# https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg#using-the-registry-to-disable-autorun
# https://www.sans.org/blog/digital-forensics-how-to-configure-windows-investigative-workstations/
# 255 = 0xFF
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveAutoRun" -Type DWord -Value 255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveAutoRun" -Type DWord -Value 255
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255


# Disable Autoplay

Write-Output "Disabling Autoplay..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1


# Prevent Automatic Mounting of External Drives

Write-Output "Disabling automatic mounting of external drives..."
# https://www.sans.org/blog/digital-forensics-how-to-configure-windows-investigative-workstations/
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MountMgr\" -Name "NoAutoMount" -Type Dword -Value 1


# Prvent Automatic Search Indexing of Removable Drives

Write-Output "Disabling automatic search indexing of removable drives..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableRemovableDriveIndexing" -Type DWord -Value 1


##########
#endregion Security Tweaks
##########



##########
#region Network Tweaks
##########


# Set current network profile to public (deny file sharing, device discovery, etc.)

#Write-Output "Setting current network profile to public..."
#Set-NetConnectionProfile -NetworkCategory Public


# Disable NetBIOS over TCP/IP on all currently installed network interfaces

Write-Output "Disabling NetBIOS over TCP/IP..."
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2


# Disable Link-Local Multicast Name Resolution (LLMNR) protocol

Write-Output "Disabling Link-Local Multicast Name Resolution (LLMNR)..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0


# Disable Remote Desktop

Write-Output "Disabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1


# Shields Up

Write-Output "Configuring Windows Defender Firewall Rules..."

Write-Host -ForegroundColor Cyan "[i]Set firewall to 'blockinboundalways'?"
Write-Host "This will prevent inbound connections even if an allow rule exists."
Write-Host -BackgroundColor Yellow -ForegroundColor DarkRed "WARNING: This setting will likely lock you out if this is a cloud instance."
$BlockInboundChoice = ""
while ($BlockInboundChoice -ne "y" -or "n") {
    if ($BlockInboundChoice -eq "y") {
	Write-Host "Setting Windows Defender Firewall to 'blockinboundalways'..."
	netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound
	break
    }
    elseif ($BlockInboundChoice -eq "n") {
	Write-Host "Setting Windows Defender Firewall to 'blockinbound'..."
	netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
	break
    }
    else {
	$BlockInboundChoice = Read-Host "[y/n]"
    }
}

netsh advfirewall set allprofiles settings remotemanagement disable
netsh advfirewall set allprofiles settings inboundusernotification enable
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging maxfilesize 16384

Set-NetFirewallRule -DisplayName "mDNS*" -Direction Outbound -Action Block -Enabled True
Set-NetFirewallRule -DisplayName "*LLMNR*" -Direction Outbound -Action Block -Enabled True
Set-NetFirewallRule -DisplayName "*search*" -Direction Outbound -Action Block -Enabled True


##########
#endregion Network Tweaks
##########



##########
#region Service Tweaks
##########


# Disable Fast Startup

Write-Output "Disabling Fast Startup..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0


##########
#endregion Service Tweaks
##########



##########
#region UI Tweaks
##########


# Require authentication after resuming from sleep (this should be on by default)

Write-Output "Requiring authentication when resuming from sleep..."
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\Power")) {
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\Power" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\Power" -Name "PromptPasswordOnResume" -Type DWord -Value "1"


# Require authentication (immediately) after screen turns off

Write-Output "Requiring authentication immediately after screen turns off..."
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DelayLockInterval" -Type DWord -Value "0"


# Hide network options from Lock Screen

Write-Output "Hiding network options from Lock Screen..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1


# Hide shutdown options from Lock Screen

Write-Output "Hiding shutdown options from Lock Screen..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0


# Disable Aero Shake (minimizing other windows when one is dragged by mouse and shaken)

#Write-Output "Disabling Aero Shake..."
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1


# Disable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)

Write-Output "Disabling accessibility keys prompts..."
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122"


# Set Dark Mode for Applications

Write-Output "Setting Dark Mode for Applications..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0


# Set Dark Mode for System - Applicable since 1903

Write-Output "Setting Dark Mode for System..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

##########
#endregion UI Tweaks
##########



##########
#region Explorer UI Tweaks
##########


# Show known file extensions

Write-Output "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0


# Show hidden files

Write-Output "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1


##########
#endregion Explorer UI Tweaks
##########





##########
#region Application Tweaks
##########


# Uninstall OneDrive - Not applicable to Server

Write-Output "Uninstalling OneDrive..."
If ((Get-Process "OneDrive" -ErrorAction Continue)) {
	Stop-Process -Name "OneDrive"
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall"
	Start-Sleep -s 5
	Stop-Process -Name "explorer"
	Start-Sleep -s 5
}


# Uninstall default Microsoft applications

Write-Output "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Start-Sleep -s 2
#Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Start-Sleep -s 2
#Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
#Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.Windows.NarratorQuickStart" | Remove-AppxPackage
#Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage

# This needs to be at the bottom, other packages need removed first
Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage
Start-Sleep -s 2


# Disable Xbox features - Not applicable to Server

Write-Output "Disabling Xbox features..."
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction Continue
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
#Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0


# Disable Print Spooler

Stop-Service -Name "Spooler"
Set-Service -Name "Spooler" -StartupType "Disabled"


# Uninstall Windows Media Player

Write-Output "Uninstalling Windows Media Player..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null


# Uninstall Internet Explorer

Write-Output "Uninstalling Internet Explorer..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null


# Uninstall Work Folders Client - Not applicable to Server
Write-Output "Uninstalling Work Folders Client..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null


# Install Linux Subsystem - Applicable since Win10 1607 and Server 1709
# Note: 1607 requires also EnableDevelopmentMode for WSL to work
# For automated Linux distribution installation, see https://docs.microsoft.com/en-us/windows/wsl/install-on-server

#Write-Output "Installing Linux Subsystem..."
#Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null


# Uninstall Telnet Client

Write-Output "Uninstalling Telnet Client..."
If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "TelnetClient" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null
} Else {
	Uninstall-WindowsFeature -Name "Telnet-Client" -WarningAction Continue | Out-Null
}


# Uninstall Microsoft Print to PDF

Write-Output "Uninstalling Microsoft Print to PDF..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null


# Uninstall Microsoft XPS Document Writer

Write-Output "Uninstalling Microsoft XPS Document Writer..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null


# Uninstall Windows Fax and Scan Services - Not applicable to Server

Write-Output "Uninstalling Windows Fax and Scan Services..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null


# Remove PowerShell v2.0

Write-Output "Uninstalling PowerShell v2.0..."
Get-WindowsOptionalFeature -Online | where FeatureName -Like MicrosoftWindowsPowerShellV2* | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction Continue | Out-Null


##########
#endregion Application Tweaks
##########





##########
#region Logging
##########

# Enable PowerShell ScriptBlock Logging

Write-Host "Enabling PowerShell Script Block Logging..."
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1#using-the-registry
$basePath = @(
    'HKLM:\Software\Policies\Microsoft\Windows'
    'PowerShell\ScriptBlockLogging'
) -join '\'

if (-not (Test-Path $basePath)) {
    $null = New-Item $basePath -Force
}

Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"
Set-ItemProperty $basePath -Name EnableScriptBlockInvocationLogging -Value "0"

##########
#endregion Logging
##########
