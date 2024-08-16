<#
    Use embedded STIG data while skipping rules and inject exception data.
    Example for baselining WindowsServer 2022 that isn't a DC.
#>

configuration Example
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
        WindowsServer BaseLine
        {
            OsVersion   = '2022'
            OsRole      = 'MS'
            StigVersion = '1.5'
            # Domain and Forest don't need specified if you're already domain joined, unless you're scanning cross-forest
            #DomainName  = 'example.internal'
            #ForestName  = 'example.internal'
            #Exception   = @{'V-1075'= @{'ValueData'='1'} }
            # Rules '254442-4' Involve DoD certificates which we won't have access to
            # Rule 'V-254254.c' breaks on WindowsServer 2022: https://github.com/microsoft/PowerStig/issues/1360#issuecomment-2176146847
            # Rule 'V-254439' denies interactive logon for Enterprise Admins,Domain Admins,Local account,Guests this can interfere when testing
            SkipRule = @('V-254442','V-254443','V-254444','V-254254.c','V-254439')
            OrgSettings = "C:\Tools\PowerSTIGDev\WindowsServer-2022-MS-1.5\WindowsServer-2022-MS-1.5.org.default.xml"
        }
    }
}

Example -OutputPath C:\Tools\PowerSTIGDev\WindowsServer-2022-MS-1.5
