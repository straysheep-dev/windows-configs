<#
.SYNOPSIS

Tail any Event Log on a live system.

.DESCRIPTION

Similar to Unix's `tail -f /var/log/LogName`.
The default path for Event Logs is: C:\Windows\System32\winevt\Logs\*.evtx

To see all available logs on a (Windows) system:
Get-WinEvent -ListLog * | Select -Property LogName

To see the available properties for a log, use:
Get-WinEvent -MaxEvents 1 -LogName '<log>' | select -Property *

This script was adapted from user1756588's example:
https://stackoverflow.com/questions/15262196/powershell-tail-windows-event-log-is-it-possible

Essential logs you'd want to tail:

* Security
* Microsoft-Windows-Sysmon/Operational
* Microsoft-Windows-PowerShell/Operational

.PARAMETER LogName

Specifies the name of the Event Log to tail.

.PARAMETER EventId

Only return logs matching a specific Event Id.

.EXAMPLE

PS> Tail-EventLog -LogName "Security"

.EXAMPLE

PS> Tail-EventLog -LogName "Security" -EventId "4648"

.EXAMPLE

PS> Tail-EventLog -LogName "Microsoft-Windows-Sysmon/Operational" | Tee-Object -FilePath C:\tail.log [-Encoding ASCII]

.LINK

https://github.com/straysheep-dev/windows-configs
https://stackoverflow.com/questions/15262196/powershell-tail-windows-event-log-is-it-possible
https://stackoverflow.com/legal/terms-of-service#licensing
https://creativecommons.org/licenses/by-sa/4.0/

#>

function Tail-EventLog {

	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $True)]
		[string]$LogName,

		[Parameter(Position = 1, Mandatory = $False)]
		[string]$EventId
	)

	if ("$LogName" -ne "") {

        # Use this variable to customize what properties are printed to terminal, see the Format-Table example below
        $format_property = @{ expression={$_.TimeCreated}; label="TimeCreated"}, 
                           @{ expression={$_.Id}; label="SysmonId"},
                           @{ expression={$_.ProcessId}; label="PPId"},
                           @{ expression={$_.Message}; label="Message"; width=100}

        # We use two variables to create a comparison of the current log entry
        # If the RecordId increments, we print the newest log entry to the terminal
        $id_1 = (Get-WinEvent -LogName "$LogName" -Max 1 -ErrorAction SilentlyContinue).RecordId

        while ($true) {

            # This prevents the endless printing of errors stating there's no difference between the RecordId's yet (difference is 0)
            # Once a new log entry is written, the difference is no longer 0 for that iteration, and a new log is printed.
            $id_2 = (Get-WinEvent -LogName "$LogName" -Max 1 -ErrorAction SilentlyContinue).RecordId
            if(($id_2 - $id_1) -eq 0) {
                start-sleep 1
            }
            else {
                $id_2 = (Get-WinEvent -LogName "$LogName" -Max 1 -ErrorAction SilentlyContinue).RecordId

                # This section writes the log entries to the terminal

                # Example 1: Format-List
                # Get-WinEvent -LogName "$LogName" -Max ($id_2 - $id_1) | sort RecordId | Format-List
                # Example 2: Format-Table, using the $format_property variable values - this will produce similar results to Format-List with some different properties available to parse
                # Get-WinEvent -LogName "$LogName" -Max ($id_2 - $id_1) | sort RecordId | Format-Table -Property $format_property -Wrap

		if ("$EventId" -ne "") { Get-WinEvent -LogName "$LogName" -Max ($id_2 - $id_1) | sort RecordId | where Id -eq "$EventId" | Format-List }
		else { Get-WinEvent -LogName "$LogName" -Max ($id_2 - $id_1) | sort RecordId | Format-List }

                $id_1 = $id_2
            }
        }
    }
}
