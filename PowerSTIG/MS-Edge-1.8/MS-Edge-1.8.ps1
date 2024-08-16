
<#
  Based on the template used for Chrome and Firefox
  Defaults to policy verison 1.8
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
        Edge EdgeSettings
        {
            StigVersion = '1.8'
            OrgSettings = "C:\Tools\PowerSTIGDev\MS-Edge-1.8\MS-Edge-1.8.org.default.xml"
        }
    }
}

Example -OutputPath C:\Tools\PowerSTIGDev\MS-Edge-1.8
