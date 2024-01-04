<#
.SYNOPSIS

Convenience script to open a reverse ssh tunnel to the Windows host from WSL, giving WSL access to usbipd devices on localhost tcp/3240 without any inbound firewall rules active on the host.

.DESCRIPTION

The following requirements must be met for this to work:

- WSL is up to date with /usr/bin/usbip installed (this is automatic on the latest Ubuntu version)
- The Windows host has an ssh key that the target WSL instance will accept
- The ssh identity is loaded into Windows ssh-agent
- WSL accepts incoming ssh connections
- You can execute commands as admin (this script can run as a normal user but you need to know an admin's credentials)
- You have sudo privileges within WSL

This function was created to avoid allowing any inbound rules on a Windows host. This means you can use usbipd with BlockInboundAlways enabled. This is also referred to as "Shields Up" mode, as it drops all incoming connections even if there's an allow rule for it. This is the ideal scenario for a "locked down" machine that may run in untrusted environments.

It's still possible to achieve this with Windows Firewall by only allowing connections to the virtual interfaces, but the firewall rule needs refreshed on each reboot as the interface's unique indentifiers are "regenerated" making this difficult to maintain without a Scheduled Task running regularly and careful testing.

The "Start-Process -Verb RunAs" is effectively working as "sudo" on Windows, calling usbipd.exe as admin to bind a device while executing the rest of the script in a normal user's context.
A new terminal Window is opened making the ssh reverse connection to WSL, giving you an active shell in that environment while Windows' localhost tcp/3240 is accessible. This is done so the function can finally call usbip from within wsl.exe to attach the bound device before it's done executing.

To disconnect everything, exit the ssh tunnel session, then unbind the device from the host with:

PS> Start-Process PowerShell -Verb RunAs -ArgumentList "usbipd.exe unbind -b $DeviceBUSID"

.PARAMETER DeviceBUSID

The BUSID of the device, obtain using usbipd.exe list

.EXAMPLE

PS> Connect-UsbipSSHTunnel -DeviceBUSID 1-4

.LINK

https://github.com/straysheep-dev/windows-configs
https://github.com/dorssel/usbipd-win/discussions/613#discussioncomment-6039964
https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/tools#shields-up-mode-for-active-attacks

#>

function Connect-UsbipSSHTunnel {

        [CmdletBinding()]
        Param(
                [Parameter(Position = 0, Mandatory = $True)]
                [string]$DeviceBUSID
         )

        # Finds any valid IPv4 address on a WSL network interface within 172.16.0.0/12, the random IPv4 address Windows assigns WSL instances are known to be in this range
        $wsl_ipv4 = wsl.exe ip a | sls "172\.(?:(?:1[6-9]|2[0-9]|3[0-1]?)\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | ForEach-Object { $_.Matches.Value }
        # Obtain the username of the WSL session
        $wsl_user = wsl.exe whoami

        # "sudo" for Windows using -Verb RunAs, prompts for admin credentials
        Start-Process PowerShell -Verb RunAs -ArgumentList "usbipd.exe bind -b $DeviceBUSID"
        # Opens the ssh session in a new window
        Start-Process PowerShell -ArgumentList "ssh -R 127.0.0.1:3240:127.0.0.1:3240 $wsl_user@$wsl_ipv4"
        # Connects from WSL's localhost to Windows' localhost tcp/3240 to reach the shared devices available from usbipd.exe internally
        wsl.exe sudo usbip attach --remote=127.0.0.1 -b $DeviceBUSID
}
