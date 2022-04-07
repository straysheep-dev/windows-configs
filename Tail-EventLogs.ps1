# Adapted from user1756588's example: <https://stackoverflow.com/questions/15262196/powershell-tail-windows-event-log-is-it-possible>
# https://stackoverflow.com/legal/terms-of-service#licensing
# https://creativecommons.org/licenses/by-sa/4.0/


# To see the available properties for a log, use:
# Get-WinEvent -MaxEvents 1 -LogName '<log>' | select -Property *

# Use this variable to customize what properties are printed to terminal, see the Format-Table example below
$format_property = @{ expression={$_.TimeCreated}; label="TimeCreated"}, 
                   @{ expression={$_.Id}; label="SysmonId"},
                   @{ expression={$_.ProcessId}; label="PPId"},
                   @{ expression={$_.Message}; label="Message"; width=100}

# To see all available logs on a (Windows) system:
# Get-WinEvent -ListLog * | Select -Property LogName

# Replace this with the name of the log you'd like to follow
$logname = "Microsoft-Windows-Sysmon/Operational"

# We use two variables to create a comparison of the current log entry
# If the RecordId increments, we print the newest log entry to the terminal
$id_1 = (Get-WinEvent -LogName "$logname" -Max 1 -ErrorAction SilentlyContinue).RecordId

while ($true) {

  # This prevents the endless printing of errors stating there's no difference between the RecordId's yet (difference is 0)
  # Once a new log entry is written, the difference is no longer 0 for that iteration, and a new log is printed.
  $id_2 = (Get-WinEvent -LogName "$logname" -Max 1 -ErrorAction SilentlyContinue).RecordId
  if(($id_2 - $id_1) -eq 0) {
    start-sleep 1
  }
  else {
  $id_2 = (Get-WinEvent -LogName "$logname" -Max 1 -ErrorAction SilentlyContinue).RecordId

  # This line writes the log entries to the terminal
  # Example 1: Format-List while also writing the data to C:\Windows\Temp\tail.log
  Get-WinEvent -LogName "$logname" -Max ($id_2 - $id_1) | sort RecordId | Format-List | Tee-Object -FilePath C:\Windows\Temp\tail.log
  # Example 2: Format-Table, using the $format_property variable values - this will produce similar results to Format-List with some different properties available to parse
  #Get-WinEvent -LogName "$logname" -Max ($id_2 - $id_1) | sort RecordId | Format-Table -Property $format_property -Wrap

  $id_1 = $id_2

  }
}
