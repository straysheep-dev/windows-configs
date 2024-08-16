<#
  Applies STIG states to domain-joined endpoints.
  Can be configured to run via a logon script with a GPO or similar.
#>


if ((Get-ComputerInfo).OsProductType -eq "Workstation") {

	Start-DscConfiguration -ComputerName localhost -Path \\dc01.domain.internal\PowerSTIGDev\WindowsClient-11-1.6\

} elseif ((Get-ComputerInfo).OsProductType -eq "DomainController") {

	Start-DscConfiguration -ComputerName localhost -Path \\dc01.domain.internal\PowerSTIGDev\WindowsServer-2022-DC-1.5

}