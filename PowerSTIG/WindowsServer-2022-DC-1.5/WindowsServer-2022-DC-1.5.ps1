<#
    Use embedded STIG data while skipping rules and inject exception data.
    Example for baselining WindowsServer 2022 acting as a DC.
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
            OsRole      = 'DC'
            StigVersion = '1.5'
            # Domain and Forest don't need specified if you're already domain joined, unless you're scanning cross-forest
            #DomainName  = 'example.internal'
            #ForestName  = 'example.internal'
            #Exception   = @{'V-1075'= @{'ValueData'='1'} }
            # Rules '254442-4' Involve DoD certificates which we won't have access to
            # Rules 'V-254391' and 'V-254392' were failing to apply with "Cannot bind argument to parameter 'Ace' because it is null." and issues with "NTAccount" being empty
            # Rule 'V-254254.c' is not a finding if defaults have not been changed: https://github.com/microsoft/PowerStig/blob/f0a575bf7014a933e336c15572765f5764e0bc3c/source/StigData/Processed/WindowsServer-2022-DC-1.5.xml#L3665
            SkipRule = @('V-254442','V-254443','V-254444','V-254391','V-254392','V-254254.c')
            OrgSettings = "C:\Tools\PowerSTIGDev\WindowsServer-2022-DC-1.5\WindowsServer-2022-DC-1.5.org.default.xml"
        }
    }
}

Example -OutputPath C:\Tools\PowerSTIGDev\WindowsServer-2022-DC-1.5
