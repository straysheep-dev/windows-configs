# Enforce-FirewallRules.ps1

# Deploy as a scheduled task to prevent unkown inbound rules from activating, for example after updates to Windows workstations.
# This is a last resort, where your machine is not domain-joined and you cannot run with AllowInboundRules: False, because you
# require SSH, RDP, or WinRM.

# Shields Up Mode
# Check if you have it enabled with:
# PS> Get-NetFirewallProfile -All | Select AllowInboundRules  # False
# C:\> netsh advfirewall show allprofiles firewallpolicy      # blockinboundalways
# Enable Shields Up mode with:
# PS> Set-NetFirewallProfile -All -AllowInboundRules False
# C:\> netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound
# https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/tools#shields-up-mode-for-active-attacks
# What "Shields Up" mode does is prevents ALL inbound connections, even if a rule exists.
# This is a good setting to have on workstations, where there should rarely be inbound connections. Options exist to use SSH reverse forwarding to
# work around firewall rules for necessary management, however this script is written with provisioning over Ansible in mind, in cases where a
# machine isn't domain-joined and managed by a DC. You can't set Shields Up per interface, it's only per profile (Public,Private,Domain).

# List of inbound ports to allow
$PortList = @("22","5986")

# Allow connections on this list of network interfaces
$Interfaces = @("Tailscale", "Ethernet 2")
$ExistingInterfaces = Get-NetAdapter -IncludeHidden | Select-Object -ExpandProperty Name

# Without blockinboundalways, ensure only the minimum inbound rules are enabled
Write-Host "[*]Turning off all inbound rules..."
Get-NetFirewallRule -Direction Inbound | Set-NetFirewallRule -Enabled False

# Apply the rule if the adapter exists
foreach ($Interface in $Interfaces) {
		if ($ExistingInterfaces -contains $Interface) {
				foreach ($Port in $PortList) {
					Write-Host "[*]Allow in on $Interface to TCP/$Port"
					# There may be a way to make this more strict and precise with something like `-Program "C:\Program Files\usbipd-win\usbipd.exe"`
					# But there would need to be a way to identify each binary and iterate through them
					New-NetFirewallRule -DisplayName "Allow in on $Interface to TCP/$Port" -Profile Any -Direction Inbound -Protocol TCP -LocalPort $Port -InterfaceAlias $Interface -Action Allow | Out-Null
				}
		}
}