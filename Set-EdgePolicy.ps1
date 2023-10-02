# Set-EdgePolicy

# Keys are fully documentated here:
# https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies

# This policy configruation is based on the following two resources:
# https://www.microsoft.com/en-us/download/details.aspx?id=55319
# https://static.open-scap.org/ssg-guides/ssg-chromium-guide-stig.html

# Why syntactically correct scripts won't run:
# https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/10-script-modules?view=powershell-7.1

# Dot Sourcing: to load this script into the `Function PSDrive`:
# . .\Set-EdgePolicy.ps1

# Check your own syntax once the function is loaded into memory:
# PS > Get-Command -Name Set-EdgePolicy -Syntax

# Additional references:
# https://devblogs.microsoft.com/scripting/powertip-use-positional-parameters/
# https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/09-functions?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-if?view=powershell-7.1

# Filter Format
#  [scheme://][.]host[:port][/path][@query]

# Examples:
# "contoso.com"
# "https://ssl.server.com"
# "hosting.com/good_path"
# "https://server:8080/path"
# ".exact.hostname.com"

# Reset all admx values to 'Not configured' before running
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name *


function Set-EdgePolicy {

	[CmdletBinding()]
	Param(
		[Parameter(Position = 0)]
		[string]$Action
	)

	if ("$Action" -like "Apply") 
	{
		# Apply settings
		Write-Output "Setting Edge policy via registry..."

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
		}

		# Required for conferencing
		If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsAccessMicrophone") {
			Write-Output "Enabling microphone access..."
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone"
		}

		If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsAccessCamera") {
			Write-Output "Enabling camera access..."
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera"
		}

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AddressBarMicrosoftSearchInBingProviderEnabled -Type Dword -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AdsSettingForIntrusiveAdsSites -Type DWord -Value 0x00000002

#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AlwaysOpenPDFExternally -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AlternateErrorPagesEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ApplicationGuardTrafficIdentificationEnabled -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AudioSandboxEnabled -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutofillAddressEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutoImportAtFirstRun -Type DWord -Value 0x00000004

		# Review this
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AuthSchemes -Type String -Value "ntlm,negotiate"

		# 0 = Disabled
		# 1 = Upgrade when capable
		# 2 = Always upgrade to https
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutomaticHttpsDefault -Type DWord -Value 0x00000002

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutoplayAllowed -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BasicAuthOverHttpEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BingAdsSuppression -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BlockExternalExtensions -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BrowserLegacyExtensionPointsBlockingEnabled -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BrowserSignin -Type DWord -Value 0x00000000

		# BuiltInDnsClientEnabled does not control if DNS-over-HTTPS is used; Microsoft Edge always uses its built-in resolver for DNS-over-HTTPS requests.
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BuiltInDnsClientEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ClearBrowsingDataOnExit -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ClearCachedImagesAndFilesOnExit -Type DWord -Value 0x00000001

		# 1 = Plain text url only
		# 3 = Rich text url only
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ConfigureFriendlyURLFormat -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ConfigureShare -Type DWord -Value 0x00000001

		# 1 = Allow all
		# 2 = Deny all
		# 4 = Clear all on exit
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultCookiesSetting -Type DWord -Value 0x00000004

		# 2 = Deny all
		# 3 = Ask
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultFileSystemReadGuardSetting -Type DWord -Value 0x00000002

		# 2 = Deny all
		# 3 = Ask
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultFileSystemWriteGuardSetting -Type DWord -Value 0x00000002

		# 1 = Allow
		# 2 = Deny
		# 3 = Ask
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultGeolocationSetting -Type DWord -Value 0x00000002

		# 2 = Deny all
		# 3 = Allow exceptions
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultInsecureContentSetting -Type DWord -Value 0x00000002

		# 1 = Allow all
		# 2 = Deny all
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultJavaScriptSetting -Type DWord -Value 0x00000002

		# 01 = Allow JIT
		# 02 = Block JIT
		# Disabling the JavaScript JIT will mean that Microsoft Edge may render web content more slowly, and may also disable parts of JavaScript 
		# including WebAssembly. Disabling the JavaScript JIT may allow Microsoft Edge to render web content in a more secure configuration.
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultJavaScriptJitSetting -Type DWord -Value 0x00000002

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptJitAllowedForSites")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptJitAllowedForSites" -Force | Out-Null
		}
		# Examples
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForSites\" -Name "1" -Type String -Value "https://[*.]microsoft.com:443"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForSites\" -Name "2" -Type String -Value "https://[*.]google.com:443"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForSites\" -Name "3" -Type String -Value "https://[*.]duckduckgo.com:443"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultNotificationsSetting -Type DWord -Value 0x00000002

		# 1 = Allow all
		# 2 = Deny all
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultPopupsSetting -Type DWord -Value 0x00000002

		# Default search settings only apply to Domain joined or MDM/MCX devices, see ManagedSearchEngines for this
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSearchProviderContextMenuAccessAllowed -Type DWord -Value 0x00000000

#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSearchProviderEnabled -Type DWord -Value 0x00000001

#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSearchProviderSearchURL -Type String -Value "https://duckduckgo.com/?q={searchTerms}"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSensorsSetting -Type DWord -Value 0x00000002

		# 2 = Deny all
		# 3 = Ask
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultWebBluetoothGuardSetting -Type DWord -Value 0x00000002

		# 2 = Deny all
		# 3 = Ask
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultWebUsbGuardSetting -Type DWord -Value 0x00000003

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name Disable3DAPIs -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DisplayCapturePermissionsPolicyEnabled -Type DWord -Value 0x00000001

		# This will override the BuiltInDnsClientEnabled and use Edge's built-in DNS over HTTPS resolver
		# off (off) = Disable DNS-over-HTTPS
		# automatic (automatic) = Enable DNS-over-HTTPS with insecure fallback
		# secure (secure) = Enable DNS-over-HTTPS without insecure fallback
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DnsOverHttpsMode -Type String -Value "secure"

		# A list of separate providers is space-separated
		# Use the following to check if you're using DoH:
		# https://1.1.1.1/help
		# https://on.quad9.net/
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DnsOverHttpsTemplates -Type String -Value "https://cloudflare-dns.com/dns-query{?dns} https://dns.quad9.net/dns-query{?dns}"

		# Check value syntax
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DownloadDirectory -Type String -Value "C:\\Users\\${user_name}\\Downloads"

		# 0 = No restrictions
		# 1 = Block dangerous
		# 2 = Block dangerous and unwanted
		# 3 = Block all
		# Note: 2 and 3 prevent many regular downloads from working
		# Great in preventing accidentally clicked links from automatically downloading remote content
		# But restricts usability of many sites
		# Some sites can still get around this, but are likely allow-listed by Edge & Defender
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DownloadRestrictions -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EdgeCollectionsEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EnableMediaRouter -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EnableOnlineRevocationChecks -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EdgeShoppingAssistantEnabled -Type DWord -Value 0x00000000

		# Setting a single value of "*" will prevent installation of any extensions not specified under "ExtensionInstallForcelist"
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist" -Name "1" -Type String -Value "*"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Force | Out-Null
		}
		# Example Value:
		# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "1" -Type String -Value "abcdefghijklmnopabcdefghijklmnop"
		# uBlock Origin:
		# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "2" -Type String -Value "odfafepnkmbhccpbejgmiehpchacaeak"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name FavoritesBarEnabled -Type DWord -Value 0x00000000

#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ForceEphemeralProfiles -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name HideFirstRunExperience -Type DWord -Value 0x00000001

		# NewTabPageLocation settings  only apply to Domain joined or MDM/MCX devices
		# 0 = false
		# 1 = true
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name HomepageIsNewTabPage -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportAutofillFormData -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportBrowserSettings -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportCookies -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportExtensions -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportFavorites -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportHistory -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportHomepage -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportOpenTabs -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportPaymentInfo -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportSavedPasswords -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportSearchEngine -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportShortcuts -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportStartupPageSettings -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InPrivateModeAvailability -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InsecurePrivateNetworkRequestsAllowed -Type DWord -Value 0x00000000

		# 0 = None
		# 1 = IE Edge mode
		# 2 = IE Stand-alone mode
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InternetExplorerIntegrationLevel -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InternetExplorerIntegrationReloadInIEModeAllowed -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name LocalProvidersEnabled -Type Dword -Value 0x00000000

		# Dictionary of default search providers
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name ManagedSearchEngines -Type String -Value '[{"allow_search_engine_discovery": false},{"is_default": true,"keyword": "duckduckgo.com","name": "DuckDuckGo","search_url": "https://duckduckgo.com?q={searchTerms}"},{"keyword": "google.com","name": "Google","search_url": "{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}"},]'

		# Obsolete after Edge 88
#		MetricsReportingEnabled

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NativeMessagingUserLevelHosts -Type DWord -Value 0x00000000

		# NetworkPredictionAlways (0) = Predict network actions on any network connection
		# NetworkPredictionWifiOnly (1) = Not supported, if this value is used it will be treated as if 'Predict network actions on any network connection' (0) was set
		# NetworkPredictionNever (2) = Don't predict network actions on any network connection
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NetworkPredictionOptions -Type DWord -Value 0x00000002

		# 1 = Disable image of the day
		# 2 = Disable custom image
		# 3 = Disable all
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageAllowedBackgroundTypes -Type DWord -Value 0x00000003

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageContentEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageHideDefaultTopSites -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageQuickLinksEnabled -Type Dword -Value 0x00000000

		# NewTabPageLocation settings  only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageLocation -Type String -Value "about:blank"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageSearchBox -Type String -Value "redirect"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PasswordManagerEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PaymentMethodQueryEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PersonalizationReportingEnabled -Type DWord -Value 0x00000000

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PreventSmartScreenPromptOverride -Type DWord -Value 0x00000001

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PreventSmartScreenPromptOverrideForFiles -Type DWord -Value 0x00000001


		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name PromotionalTabsEnabled -Type DWord -Value 0x00000000

		# Need to confirm what this is doing
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name QuicAllowed -Type DWord -Value 0x00000000

		# Not available
#		RemoteAccessHostFirewallTraversal

		# Need to confirm what this is doing
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name ResolveNavigationErrorsUseWebService -Type DWord -Value 0x00000000

		# RestoreOnStartup settings only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name RestoreOnStartup -Type DWord -Value 0x00000005

		# Allows sessions and logins to persist when DefaultCookiesSetting = 4 (clear on exit)
		# "RestoreOnStartup" only works on managed devices (AD joined), to configure this manually: Settings > Start, home, and new tabs > Open tabs from the previous session
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit" -Force | Out-Null
		}
		# Examples
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit\" -Name "1" -Type String -Value "https://[*.]microsoft.com:443"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit\" -Name "2" -Type String -Value "https://[*.]google.com:443"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit\" -Name "3" -Type String -Value "https://[*.]duckduckgo.com:443"

		# 0 = False
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SavingBrowserHistoryDisabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SearchSuggestEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SharedArrayBufferUnrestrictedAccessAllowed -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ShowMicrosoftRewards -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ShowRecommendationsEnabled -Type DWord -Value 0x00000000

		# Not available
#		ShowFullUrlsInAddressBar

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SitePerProcess -Type DWord -Value 0x00000001

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SmartScreenEnabled -Type DWord -Value 0x00000001

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SmartScreenForTrustedDownloadsEnabled -Type DWord -Value 0x00000001

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SmartScreenPuaEnabled -Type DWord -Value 0x00000001

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SpellcheckEnabled -Type DWord -Value 0x00000000

		# 0 = Disabled
		# 1 = Enabled
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SpotlightExperiencesAndRecommendationsEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SSLErrorOverrideAllowed -Type DWord -Value 0x00000000

		# Will be removed in the future, still works until it's removed
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name SSLVersionMin -Type String -Value "tls1.2"

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name StartupBoostEnabled -Type DWord -Value 0x00000000

		# 0 = Disabled
		# 1 = Enabled
		# 2 = Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SyncDisabled -Type DWord -Value 0x00000001

		# 0 = Off
		# 1 = Basic
		# 2 = Balanced
		# 3 = Strict
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name TrackingPrevention -Type DWord -Value 0x00000003

		# 3DES will be removed from Edge around Oct 2021, this policy will stop working then.
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name TripleDESEnabled -Type DWord -Value 0x00000000

		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name TyposquattingCheckerEnabled -Type Dword -Value 0x00000001

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls" -Force | Out-Null
		}
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls\" -Name "1" -Type String -Value "https://microsoft.com:443"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls\" -Name "2" -Type String -Value "https://google.com:443"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls\" -Name "3" -Type String -Value "https://duckduckgo.com:443"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Force | Out-Null
		}
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Name "1" -Type String -Value "edge://*"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Name "2" -Type String -Value "file://*"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Name "3" -Type String -Value "https://[*.]microsoft.com"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Name "4" -Type String -Value "https://[*.]google.com"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Name "4" -Type String -Value "https://[*.]duckduckgo.com"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist" -Force | Out-Null
		}
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist" -Name "1" -Type String -Value "*"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist" -Name "1" -Type String -Value "javascript://*"
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist" -Name "1" -Type String -Value "https://[*.]example.localhost"

		Write-Output "Done."
	}
	elseif ("$Action" -like "Undo") 
	{
		# Undo all settings; return to defaults
		Write-Output "Reseting Edge policy to defaults; removing changes in the registry..."

		# Replace `Set-ItemProperty` -> `Remove-ItemProperty`
		# Replace ` -Type .*$` -> ``
		# Mirror above policies below this line.

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AddressBarMicrosoftSearchInBingProviderEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AdsSettingForIntrusiveAdsSites

#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AlwaysOpenPDFExternally

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AlternateErrorPagesEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ApplicationGuardTrafficIdentificationEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AudioSandboxEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutofillAddressEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutoImportAtFirstRun

		# Review this
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AuthSchemes

		# 0 = Disabled
		# 1 = Upgrade when capable
		# 2 = Always upgrade to https
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutomaticHttpsDefault

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name AutoplayAllowed

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BasicAuthOverHttpEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BackgroundModeEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BingAdsSuppression

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BlockExternalExtensions

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BrowserLegacyExtensionPointsBlockingEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BrowserSignin

		# BuiltInDnsClientEnabled does not control if DNS-over-HTTPS is used; Microsoft Edge always uses its built-in resolver for DNS-over-HTTPS requests.
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BuiltInDnsClientEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ClearBrowsingDataOnExit

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ClearCachedImagesAndFilesOnExit

		# 1 = Plain text url only
		# 3 = Rich text url only
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ConfigureFriendlyURLFormat

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ConfigureShare

		# 1 = Allow all
		# 2 = Deny all
		# 4 = Clear all on exit
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultCookiesSetting

		# 2 = Deny all
		# 3 = Ask
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultFileSystemReadGuardSetting

		# 2 = Deny all
		# 3 = Ask
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultFileSystemWriteGuardSetting

		# 1 = Allow
		# 2 = Deny
		# 3 = Ask
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultGeolocationSetting

		# 2 = Deny all
		# 3 = Allow exceptions
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultInsecureContentSetting

		# 1 = Allow all
		# 2 = Deny all
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultJavaScriptSetting

		# 01 = Allow JIT
		# 02 = Block JIT
		# Disabling the JavaScript JIT will mean that Microsoft Edge may render web content more slowly, and may also disable parts of JavaScript 
		# including WebAssembly. Disabling the JavaScript JIT may allow Microsoft Edge to render web content in a more secure configuration.
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultJavaScriptJitSetting

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptJitAllowedForSites"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptJitAllowedForSites")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptJitAllowedForSites" -Force | Out-Null
		}
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForSites\" -Name "1"
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForSites\" -Name "2"
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForSites\" -Name "3"

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultNotificationsSetting

		# 1 = Allow all
		# 2 = Deny all
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultPopupsSetting

		# Default search settings only apply to Domain joined or MDM/MCX devices, see ManagedSearchEngines for this
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSearchProviderContextMenuAccessAllowed

#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSearchProviderEnabled

#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSearchProviderSearchURL

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultSensorsSetting

		# 2 = Deny all
		# 3 = Ask
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultWebBluetoothGuardSetting

		# 2 = Deny all
		# 3 = Ask
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DefaultWebUsbGuardSetting

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name Disable3DAPIs

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DisplayCapturePermissionsPolicyEnabled

		# This will override the BuiltInDnsClientEnabled and use Edge's built-in DNS over HTTPS resolver
		# off (off) = Disable DNS-over-HTTPS
		# automatic (automatic) = Enable DNS-over-HTTPS with insecure fallback
		# secure (secure) = Enable DNS-over-HTTPS without insecure fallback
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DnsOverHttpsMode

		# A list of separate providers is space-separated
		# Use the following to check if you're using DoH:
		# https://1.1.1.1/help
		# https://on.quad9.net/
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DnsOverHttpsTemplates

		# Check value syntax
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DownloadDirectory

		# 0 = No restrictions
		# 1 = Block dangerous
		# 2 = Block dangerous and unwanted
		# 3 = Block all
		# Note: 2 and 3 prevent many regular downloads from working
		# Great in preventing accidentally clicked links from automatically downloading remote content
		# But restricts usability of many sites
		# Some sites can still get around this, but are likely allow-listed by Edge & Defender
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DownloadRestrictions

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EdgeCollectionsEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EnableMediaRouter

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EnableOnlineRevocationChecks

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name EdgeShoppingAssistantEnabled

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist" -Force | Out-Null
		}

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Force | Out-Null
		}

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name FavoritesBarEnabled

#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ForceEphemeralProfiles

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name HideFirstRunExperience

		# NewTabPageLocation settings  only apply to Domain joined or MDM/MCX devices
		# 0 = false
		# 1 = true
#		#Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name HomepageIsNewTabPage

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportAutofillFormData

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportBrowserSettings

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportCookies

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportExtensions

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportFavorites

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportHistory

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportHomepage

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportOpenTabs

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportPaymentInfo

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportSavedPasswords

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportSearchEngine

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportShortcuts

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ImportStartupPageSettings

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InPrivateModeAvailability

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InsecurePrivateNetworkRequestsAllowed

		# 0 = None
		# 1 = IE Edge mode
		# 2 = IE Stand-alone mode
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InternetExplorerIntegrationLevel

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name InternetExplorerIntegrationReloadInIEModeAllowed

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name LocalProvidersEnabled

		# Dictionary of default search providers
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name ManagedSearchEngines

		# Obsolete after Edge 88
#		MetricsReportingEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NativeMessagingUserLevelHosts

		# NetworkPredictionAlways (0) = Predict network actions on any network connection
		# NetworkPredictionWifiOnly (1) = Not supported, if this value is used it will be treated as if 'Predict network actions on any network connection' (0) was set
		# NetworkPredictionNever (2) = Don't predict network actions on any network connection
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NetworkPredictionOptions

		# 1 = Disable image of the day
		# 2 = Disable custom image
		# 3 = Disable all
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageAllowedBackgroundTypes

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageContentEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageHideDefaultTopSites

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageQuickLinksEnabled

		# NewTabPageLocation settings  only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageLocation

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageSearchBox

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PasswordManagerEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PaymentMethodQueryEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PersonalizationReportingEnabled

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PreventSmartScreenPromptOverride

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PreventSmartScreenPromptOverrideForFiles


		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name PromotionalTabsEnabled

		# Need to confirm what this is doing
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name QuicAllowed

		# Not available
#		RemoteAccessHostFirewallTraversal

		# Need to confirm what this is doing
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name ResolveNavigationErrorsUseWebService

		# RestoreOnStartup settings only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name RestoreOnStartup

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SaveCookiesOnExit" -Force | Out-Null
		}

		# 0 = False
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SavingBrowserHistoryDisabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SearchSuggestEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SharedArrayBufferUnrestrictedAccessAllowed

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ShowMicrosoftRewards

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ShowRecommendationsEnabled

		# Not available
#		ShowFullUrlsInAddressBar

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SitePerProcess

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SmartScreenEnabled

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SmartScreenForTrustedDownloadsEnabled

		# SmartScreen settings only apply to Domain joined or MDM/MCX devices
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SmartScreenPuaEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SpellcheckEnabled

		# 0 = Disabled
		# 1 = Enabled
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SpotlightExperiencesAndRecommendationsEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SSLErrorOverrideAllowed

		# Will be removed in the future, still works until it's removed
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name SSLVersionMin

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\" -Name StartupBoostEnabled

		# 0 = Disabled
		# 1 = Enabled
		# 2 = Force
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SyncDisabled

		# 0 = Off
		# 1 = Basic
		# 2 = Balanced
		# 3 = Strict
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name TrackingPrevention

		# 3DES will be removed from Edge around Oct 2021, this policy will stop working then.
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name TripleDESEnabled

		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name TyposquattingCheckerEnabled

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\JavaScriptAllowedForUrls" -Force | Out-Null
		}

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist" -Force | Out-Null
		}

		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist" -Force | Out-Null
		}


		Write-Output "Done."
	}
	else 
	{
		Write-Output "Usage: Set-EdgePolicy [Apply|Undo]"
	}
}
