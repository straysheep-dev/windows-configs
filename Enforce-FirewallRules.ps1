# Enforce-FirewallRules.ps1

# Deploy as a scheduled task to prevent unkown inbound rules from activating, for example after updates to Windows workstations.
# This is a last resort, where your machine is not domain-joined and you cannot run with AllowInboundRules: False, because you
# require SSH, RDP, or WinRM.

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