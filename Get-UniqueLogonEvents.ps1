# MIT License
#
# Print unique logon information for a Windows system using built in event logs, in a clear way.
# This returns every user login by default, but you can swap around variables below to suit your needs
# As is, this will also catch shells like "runas /user:username cmd.exe"
#
# This script is meant to return data in a similar format as ".\Seatbelt.exe ExplicitLogonEvents" would:
# [GhostPack/Seatbelt - ExplicitLogonEvents](https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Windows/EventLogs/ExplicitLogonEvents/ExplicitLogonEventsCommand.cs)
#
# Parsing logs like this was learned from:
# [Security Weekly Webcast - Sysmon: Gaining Visibility Into Your Enterprise](https://securityweekly.com/webcasts/sysmon-gaining-visibility-into-your-enterprise/)
# [Slide Deck](https://securityweekly.com/wp-content/uploads/2022/04/alan-stacilauskas-unlock-sysmon-slide-demov4.pdf)
#
# Huge thanks to the presentors:
#
# [Alan Stacilauskas](https://www.alstacilauskas.com/)
# [Amanda Berlin](https://twitter.com/@infosystir)
# [Tyler Robinson](https://twitter.com/tyler_robinson)

# Set a range of time to search in the logs
# AddMinutes / AddHours / AddDays / AddMonths
$startTime = (Get-Date).AddDays(-1)

# This line will get you the relevant event log data to begin parsing
Get-WinEvent -FilterHashtable @{LogName='Security'} | where TimeCreated -gt $startTime | where Id -eq '4648' | foreach {
    # Variable names were kept the same as they are in Seatbelt's ExplicitLogonEventsCommand.cs
    # Variable properties can be extracted from the Windows Event ID 4648 $_.Message object:
    $creationTime = $_.TimeCreated
    $subjectUserSid = $_.properties[0].value
    $subjectUserName = $_.properties[1].value
    $subjectDomainName = $_.properties[2].value
    $subjectLogonId = $_.properties[3].value
    $logonGuid = $_.properties[4].value
    $targetUserName = $_.properties[5].value
    $targetDomainName = $_.properties[6].value
    $targetLogonGuid = $_.properties[7].value
    $targetServerName = $_.properties[8].value
    $targetServerInfo = $_.properties[9].value
    $processId = $_.properties[10].value
    $processName = $_.properties[11].value
    $ipAddress = $_.properties[12].value
    $ipPort = $_.properties[13].value

    # You can change this pattern variable and the if statement itself below if you'd like to search for different data
    # Basically the "user logging in" part of the login sequence captured by event logs is made by svchost.exe and not winlogon.exe
    $patternToMatch = 'winlogon.exe'

    # Another approach is filtering for a blank username:
    # if ($targetUserName -ne $nul) { ...
    #
    # Alternatively you could filter for:
    # if ($targetUserName -inotmatch "(UMFD-\d|DWM-\d)") { ...
    # DWM-\d matches patterns of the Desktop Window Manager user
    # UMFD-\d matches patterns of the Font Driver Host user

    # Lastly, you could filter based on the source IP Address:
    # if ($ipAddress -match $patternToMatch) {

    if ($processName -inotmatch $patternToMatch) {
        Write-Host "$creationTime, $targetUserName, $targetDomainName, $targetServerName, $processName, $ipAddress"
    }
}