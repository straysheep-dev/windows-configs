#
# Windows PowerShell script for AD DS Deployment
#

# Install the necessary features if they're missing
Install-WindowsFeature -Name "RSAT","AD-Domain-Services" -IncludeManagementTools

Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "domain.internal" `
-DomainNetbiosName "DOMAIN" `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true

# When connecting endpoints to the domain, point the primary DNS server to the DC, secondary DNS can be DoH
# Next enter the domain name, sign in as the administrator, THEN add standard user access or skip until reboot