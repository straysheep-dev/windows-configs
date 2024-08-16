<#
    Use embedded STIG data while skipping rules and inject exception data.
    Example for baselining WindowsClient 11.
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
        WindowsClient BaseLine
        {
            OsVersion   = '11'
            StigVersion = '1.6'
            # Domain and Forest don't need specified if you're already domain joined, unless you're scanning cross-forest
            #DomainName  = 'example.internal'
            #ForestName  = 'example.internal'
            # Rules 'V-253427','V-253429','V-253430' Involve DoD certificates which we won't have access to
            SkipRule = @('V-253427','V-253429','V-253430')
            OrgSettings = "C:\Tools\PowerSTIGDev\WindowsClient-11-1.6\WindowsClient-11-1.6.org.default.xml"
        }
    }
}

Example -OutputPath C:\Tools\PowerSTIGDev\WindowsClient-11-1.6
