# windows-configs
Various configuration files for Microsoft Windows operating systems

### Licenses
Unless a different license is included with a file as `<filename>.copyright-notice` all files are released under the MIT license.

## To do:
- [ ] create table of contents
- [ ] write overview and summary of files
- [ ] how to troubleshoot issues encountered with baselining systems

# Windows Baselining

See the tools available in the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

Choose what tools and policies to download that you'd like to apply to your environment.

The idea with the `.PolicyRules` files is they are configurations that are pre-made by Microsoft and ready to be installed using `LGPO.exe`

You can do all of this manually with PowerShell, and you will ultimately want to familiarize yourself with the descriptions of each setting should you run into any issues, but this will save a ton of time in getting things up and running.

Use `PolicyAnalyzer.exe` to view the `*.PolicyRules` files, compare them to other `*.PolicyRules` files or even your current system settings.

Use `LGPO.exe` to apply the configurations found in the `*.PolicyRules` files to your system.

For example the you might apply the [Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) for both Windows 11 Pro and the latest available version of Microsoft Edge.

Deploy and test these configurations in a temporary or virtual environment first, either a VM (local or cloud) or enabled the [Windows Sandbox](https://techcommunity.microsoft.com/t5/windows-kernel-internals-blog/windows-sandbox/ba-p/301849) feature.

Windows Sandbox is a temporary, and (depending on your `.wsb` configuration) fully isolated environment that can be started very quickly from either launching the application as you would any other, or by running a `.wsb` [configuration file](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file.md).
