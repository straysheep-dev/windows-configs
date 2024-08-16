<#
  Default configuration cmdlet for WindowsDefender.
  Applies version 2.4.
#>

Configuration Example
{
    param
    (
        [parameter()]
        [string]
        $NodeName = 'localhost'
    )

    Import-DscResource -ModuleName PowerStig

    Node $NodeName
    {
        WindowsDefender DefenderSettings
        {
            StigVersion = "2.4"
            OrgSettings = "C:\Tools\PowerSTIGDev\WindowsDefender-All-2.4\WindowsDefender-All-2.4.org.default.xml"
        }
    }
}

Example -OutputPath C:\Tools\PowerSTIGDev\WindowsDefender-All-2.4
