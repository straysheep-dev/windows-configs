# Install winget
# https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
$progressPreference = 'silentlyContinue'
Write-Information "Installing WinGet and its dependencies..."
Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx -OutFile Microsoft.UI.Xaml.2.7.x64.appx
Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx
Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle

# Download and install Windows Terminal
# https://learn.microsoft.com/en-us/windows/package-manager/winget/#example
# Currently does not run in Windows Sandbox (without the Microsoft Store)
#Write-Information "Installing Windows Terminal..."
#winget install --id Microsoft.WindowsTerminal -e

# Download and install VSCode
# Install the latest each time, or install a copy that was previously downloaded on the host and is available in a shared folder
# https://techcommunity.microsoft.com/t5/itops-talk-blog/customize-windows-sandbox/ba-p/2301354
# https://github.com/microsoft/winget-pkgs/tree/master/manifests/m/Microsoft/VisualStudioCode
Write-Information "Installing VSCode..."
#curl -L "https://update.code.visualstudio.com/latest/win32-x64-user/stable" --output C:\users\WDAGUtilityAccount\Documents\vscode.exe 
#C:\users\WDAGUtilityAccount\Documents\vscode.exe /verysilent /suppressmsgboxes
winget install --id Microsoft.VisualStudioCode -e

# Download and install Git
# https://git-scm.com/download/win
Write-Information "Installing Git..."
winget install --id Git.Git -e --source winget

# Download and install Python3
# https://github.com/microsoft/winget-pkgs/tree/master/manifests/p/Python/Python/3
Write-Information "Installing Python3..."
winget install --id Python.Python.3.12 -e --source winget

# Install Visual Studio Community with winget
# https://learn.microsoft.com/en-us/visualstudio/install/use-command-line-parameters-to-install-visual-studio?view=vs-2022#use-winget-to-install-or-modify-visual-studio
#Write-Information "Installing Visual Studio Community..."
#winget install --id Microsoft.VisualStudio.2022.Community -e

Write-Information "Setup complete."