# Download Essential Tools

# To do:
# winget / windows terminal
# different powershell verisons
# Git for Windows
# python2
# ProcDot
# dnspy
# de4dot
# hexeditor
# winPEAS

# Specify release versions where possible to check against known hash values;
# Update those values after validating a newer version. (find + replace single variables)

# For now, all archives and installers go into a "Tools\<ToolName>\" path, and are kept after install / decompressing.

# Change this path to fit your requirements
$CurrentUser = (whoami).split("\")[1]
$ToolsPath = "C:\Users\$CurrentUser\Documents\Tools"
if(!(Test-Path $ToolsPath)) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Creating $ToolsPath..."
    mkdir "$ToolsPath"
}

$7zBin = "7z2107-x64.msi"
$7zPath = "$ToolsPath\7z"
$7zHash = "5447C9AC39C48F1BC7C88359B0520396A8C9707B307C107236A93A68E6FD3EB6"
$7zUri = "https://www.7-zip.org/a/"
if(!(Test-Path "$7zPath\$7zBin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading 7-zip msi installer..."
    mkdir "$7zPath"
    Invoke-WebRequest -Uri "$7zUri$7zBin" -OutFile "$7zPath\$7zBin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$7zPath\$7zBin" | Select-String "$7zHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$7zPath\$7zBin"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        # Run the interactive installer
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install with: cmd.exe /C $7zPath\$7zBin"
    }
}
else {
    Write-Host -ForegroundColor Green "7-zip installer found."
}


$pythonVer = "3.10.2"
$python3Bin = "python-3.10.2-amd64.exe"
$python3Hash = "42B181E9B5F424472212742A187260D4EDC73B7683AE83460C974508130E08AD"
$python3Sig = "python-3.10.2-amd64.exe.asc"
$python3Path = "$ToolsPath\Python3"
$pythonUri = "https://www.python.org/ftp/python"
if(!(Test-Path "$python3Path\$python3Bin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading python3 installer..."
    mkdir "$python3Path"
    Invoke-WebRequest -Uri "$pythonUri/$pythonVer/$python3Bin" -OutFile "$python3Path\$python3Bin"
    Invoke-WebRequest -Uri "$pythonUri/$pythonVer/$python3Sig" -OutFile "$python3Path\$python3Sig"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$python3Path\$python3Bin" | Select-String "$python3Hash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$python3Path\$python3Bin"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        # Run the interactive installer
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install with: cmd.exe /C $python3Path\$python3Bin"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Run scripts like:"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan ":\> py.exe .\pdfid.py --help"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan ":\> py.exe .\pdf-parser.py -s /URI C:\Path\To\A\file.pdf"
    }
}
else {
    Write-Host -ForegroundColor Green "python3 installer found."
}

$pestudioZip = "pestudio.zip"
$pestudioHash = "2AF46DC7568FED6DFE8FECA5FEF546F2B2D1BE150DBC12022ED78812DE0DDC9A"
$pestudioPath = "$ToolsPath\pestudio"
$pestudioUri = "https://www.winitor.com/tools/pestudio/current"
if(!(Test-Path "$pestudioPath\$pestudioZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading pestudio.zip..."
    mkdir "$pestudioPath"
    Invoke-WebRequest -Uri "$pestudioUri/$pestudioZip" -OutFile "$pestudioPath\$pestudioZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$pestudioPath\$pestudioZip" | Select-String "$pestudioHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "PeStudio may have been updated, check for the latest version at:"
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "https://www.winitor.com/download"
        ri "$pestudioPath\$pestudioZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$pestudioPath\$pestudioZip" -DestinationPath "$pestudioPath"
    }
}
else {
    Write-Host -ForegroundColor Green "PeStudio found."
}


$bstringsZip = "bstrings.zip"
$bstringsHash = "27829DC87C941C472C4DAA6498314A2568769912AFE3F06D79EFFE57C4B8C1EC"
$bstringsPath = "$ToolsPath\bstrings"
$bstringsUri = "https://github.com/EricZimmerman/bstrings/releases/download/1.3.0.0"
if(!(test-path "$bstringsPath\$bstringsZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $bstringsZip..."
    mkdir "$bstringsPath"
    Invoke-WebRequest -Uri "$bstringsUri/$bstringsZip" -OutFile "$bstringsPath\$bstringsZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$bstringsPath\$bstringsZip" | Select-String "$bstringsHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$bstringsPath\$bstringsZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$bstringsPath\$bstringsZip" -DestinationPath "$bstringsPath"
    }
}
else {
    Write-Host -ForegroundColor Green "bstrings.exe found."
}


$CFFBin = "ExplorerSuite.exe"
$CFFHash = "94f4348ec573b05990b1e19542986e46dc30a87870739f5d5430b60072d5144d"
$CFFPath = "$ToolsPath\CFF_Explorer_Suite"
$CFFUri = "https://ntcore.com/files"
if(!(test-path "$CFFPath\$CFFBin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $CFFBin..."
    mkdir "$CFFPath"
    Invoke-WebRequest -Uri "$CFFUri/$CFFBin" -OutFile "$CFFPath\$CFFBin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$CFFPath\$CFFBin" | Select-String "$CFFHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$CFFPath\$CFFBin"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
    }
}
else {
    Write-Host -ForegroundColor Green "CFF Explorer Suite found."
}


$CutterZip = "cutter-v2.0.5-x64.Windows.zip"
$CutterPath = "$ToolsPath\cutter"
$CutterHash = "5FD74940DE6D7F3999D0CA4A7CBD947B9F14E8312D7270CE587448D1B67B3096"
$CutterUri = "https://github.com/rizinorg/cutter/releases/download/v2.0.5"
if(!(test-path "$CutterPath\$CutterZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $CutterZip..."
    mkdir "$CutterPath"
    Invoke-WebRequest -Uri "$CutterUri/$CutterZip" -OutFile "$CutterPath\$CutterZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$CutterPath\$CutterZip" | Select-String "$CutterHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$CutterPath\$CutterZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$CutterPath\$CutterZip" -DestinationPath "$Cutter$Path"
    }
}
else {
    Write-Host -ForegroundColor Green "Cutter found."
}


$Cygwin64Bin = "setup-x86_64.exe"
$Cygwin64Sig = "setup-x86_64.exe.sig"
$Cygwin32Bin = ""
$Cygwin32Sig = ""
$Cygwin512Sums = "sha512.sum"
$CygwinPath = "$ToolsPath\Cygwin"
$CygwinUri = "https://cygwin.com"
$CygwinKey = "pubring.asc"
if(!(test-path "$CygwinPath\$Cygwin64Bin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading Cygwin..."
    mkdir "$CygwinPath"
    Invoke-WebRequest -Uri "$CygwinUri/$Cygwin64Bin" -OutFile "$CygwinPath\$Cygwin64Bin"
    Invoke-WebRequest -Uri "$CygwinUri/$Cygwin64Sig" -OutFile "$CygwinPath\$Cygwin64Sig"
    Invoke-WebRequest -Uri "$CygwinUri/$Cygwin512Sums" -OutFile "$CygwinPath\$Cygwin512Sums"
    Invoke-WebRequest -Uri "$CygwinUri/key/$CygwinKey" -OutFile "$CygwinPath\$CygwinKey"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash -Algorithm SHA512 "$CygwinPath\$Cygwin64Bin" | Select-String (Get-Content "$CygwinPath\$Cygwin512Sums").split(" ")[3])) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$CygwinPath\$Cygwin64Bin"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Be sure to verify with $CygwinPath\$CygwinKey as well."
    }
}
else {
    Write-Host -ForegroundColor Green "Cygwin found."
}



$dieZip = "die_win64_portable_3.03.zip"
$dieHash = "F793C8EA4578CAFCA7543FE407F03AC50AC15850E99983F1CC5EE19B0DDA7C78"
$diePath = "$ToolsPath\die"
$dieUri = "https://github.com/horsicq/DIE-engine/releases/download/3.03"
if(!(test-path "$diePath\$dieZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $dieZip..."
    mkdir "$diePath"
    Invoke-WebRequest -Uri "$dieUri/$dieZip" -OutFile "$diePath\$dieZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$diePath\$dieZip" | Select-String "$dieHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$diePath\$dieZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$diePath\$dieZip" -DestinationPath "$diePath"
    }
}
else {
    Write-Host -ForegroundColor Green "Die (Detect it easy) found."
}


$FlossZip = "floss-v1.7.0-windows.zip"
$FlossHash = "9B433A949B210BB8A856DE2546CB075C349E0C2582EE9BF6B5FE51D9F95E7690"
$FlossPath = "$ToolsPath\Floss"
$FlossUri = "https://github.com/mandiant/flare-floss/releases/download/v1.7.0"
if(!(test-path "$FlossPath\$FlossZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading floss.exe..."
    mkdir "$FlossPath"
    Invoke-WebRequest -Uri "/$FlossZip" -OutFile "$FlossPath\$FlossZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$FlossPath\$FlossZip" | Select-String "$FlossHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$FlossPath\$FlossZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$FlossPath\$FlossZip" -DestinationPath "$FlossPath"
    }
    Expand-Archive "$FlossPath\$FlossZip" -DestinationPath "$FlossPath"
    else {
        Write-Host -ForegroundColor Green "floss.exe found."
    }
}


$GhidraVer = "ghidra_10.1.1_PUBLIC_20211221"
$GhidraZip = "$GhidraVer.zip"
$GhidraHash = "d4ee61ed669cec7e20748462f57f011b84b1e8777b327704f1646c0d47a5a0e8"
$GhidraPath = "$ToolsPath\Ghidra"
$GhidraUri = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.1_build"
$OpenJDK11msi = "OpenJDK11U-jdk_x64_windows_hotspot_11.0.14_9.msi"
$OpenJDK11Path = "$ToolsPath\OpenJDK11U"
$OpenJDK11Sha2 = "OpenJDK11U-jdk_x64_windows_hotspot_11.0.14_9.msi.sha256.txt"
$OpenJDK11Hash = "067ff937c3220c5c5fc5c75d82061e99dd6f60d50561c565d231670a8b5e510b"
$OpenJDK11Uri = "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.14%2B9"
if(!(test-path "$GhidraPath\$GhidraZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading OpenJDK11U..."
    mkdir "$OpenJDK11Path"
    Invoke-WebRequest -Uri "$OpenJDK11Uri/$OpenJDK11msi" -OutFile "$OpenJDK11Path\$OpenJDK11msi"
    Invoke-WebRequest -Uri "$OpenJDK11Uri/$OpenJDK11Sha2" -OutFile "$OpenJDK11Path\$OpenJDK11Sha2"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$OpenJDK11Path\$OpenJDK11msi" | Select-String "$OpenJDK11Hash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$OpenJDK11Path\$OpenJDK11msi"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
    }
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading Ghidra..."
    mkdir "$GhidraPath"
    Invoke-WebRequest -Uri "$GhidraUri/$GhidraZip" -OutFile "$GhidraPath\$GhidraZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$GhidraPath\$GhidraZip" | Select-String "$GhidaHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$GhidraPath\$GhidraZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$GhidraPath\$GhidraZip" -DestinationPath "$GhidraPath"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install dependancy first with: cmd.exe /C $OpenJDK11Path\$OpenJDK11msi"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Then cmd.exe /C $GhidraPath\..\ghidraRun.bat"
    }
}
else {
    Write-Host -ForegroundColor Green "Ghidra found."
}


$IDABin = "idafree77_windows.exe"
$IDAHash = "D0A3599B4FC7519973F023E63F732D0364C4F3316BA50AF4BC6829DC1DD5D46C"
$IDAPath = "$ToolsPath\IDA"
$IDAUri = "https://out7.hex-rays.com/files"
if(!(test-path "$IDAPath\$IDABin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading IDA (Free)..."
    mkdir "$IDAPath"
    Invoke-WebRequest -Uri "$IDAUri/$IDABin" -OutFile "$IDAPath\$IDABin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$IDAPath\$IDABin" | Select-String "$IDAHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$IDAPath\$IDABin"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install with: cmd.exe /C $IDAPath\$IDABin"
    }
}
else {
    Write-Host -ForegroundColor Green "IDA found."
}


$ILSpyZip = "ILSpy_binaries_7.1.0.6543.zip"
$ILSpyHash = "AD61EC674510893C77F4795D27C1733493856230D03574E9490891676E397D0F"
$ILSpyPath = "$ToolsPath\ILSpy"
$ILSpyUri = "https://github.com/icsharpcode/ILSpy/releases/download/v7.1"
if(!(test-path "$ILSpyPath\$ILSpyZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading ILSpy..."
    mkdir "$ILSpyPath"
    Invoke-WebRequest -Uri "$ILSpyUri/$ILSpyZip" -OutFile "$ILSpyPath\$ILSpyZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$ILSpyPath\$ILSpyZip" | Select-String "$ILSpyHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$ILSpyPath\$ILSpyZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$ILSpyPath\$ILSpyZip" -DestinationPath "$ILSpyPath"
    }
}
else {
    Write-Host -ForegroundColor Green "ILSpy found."
}


$msys2Bin = "msys2-x86_64-20220128.exe"
$msys2Hash = "7d1e86477213c64dfc8fa2c28b891f878576db171df53f18014bb8679c7faa3e"
$msys2Sig = "msys2-x86_64-20220128.exe.sig"
$msys2Sha2 = "msys2-x86_64-20220128.exe.sha256"
$msys2Path = "$ToolsPath\msys2"
$msys2Uri = "https://github.com/msys2/msys2-installer/releases/download/2022-01-28"
if(!(test-path "$msys2Path\$msys2Bin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $msys2Bin..."
    mkdir "$msys2Path"
    Invoke-WebRequest -Uri "$msys2Uri/$msys2Bin" -OutFile "$msys2Path\$msys2Bin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$msys2Path\$msys2Bin" | Select-String "$msys2Hash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$msys2Path\$msys2Bin"
        ri "$msys2Path\$msys2Sig"
        ri "$msys2Path\$msys2Hash"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install with: cmd.exe /C $msys2Path\$msys2Bin"
    }
}
else {
    Write-Host -ForegroundColor Green "msys2 installer found."
}

$pdfidVer = "pdfid_v0_2_8"
$pdfidZip = "$pdfidVer.zip"
$pdfidHash = "0D0AA12592FA29BC5E7A9C3CFA0AAEBB711CEF373A0AE0AD523723C64C9D02B4"
$pdfparserVer = "pdf-parser_V0_7_5"
$pdfparserZip = "$pdfparserVer.zip"
$pdfparserHash = "5D970AFAC501A71D4FDDEECBD63060062226BF1D587A6A74702DDA79B5C2D3FB"
$oledumpVer = "oledump_V0_0_60"
$oledumpZip = "$oledumpVer.zip"
$oledumpHash = "D847E499CB84B034E08BCDDC61ADDADA39B90A5FA2E1ABA0756A05039C0D8BA2"
$DSToolsPath = "$ToolsPath\Didier_Stevens_Tools_Suite"
$DSToolsUri = "https://didierstevens.com/files/software/"
if(!(test-path "$DSToolsPath")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading PDF Tools..."
    mkdir "$DSToolsPath"
    Invoke-WebRequest -Uri "$DSToolsUri$pdfidZip" -OutFile "$DSToolsPath\$pdfidZip"
    Write-Host "Checking $pdfidZip signature..."
    if(!(Get-FileHash "$DSToolsPath\$pdfidZip" | Select-String "$pdfidHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$DSToolsPath\$pdfidZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$DSToolsPath\$pdfidZip" -DestinationPath "$DSToolsPath\$pdfidVer"
    }
    Invoke-WebRequest -Uri "$DSToolsUri$pdfparserZip" -OutFile "$DSToolsPath\$pdfparserZip"
    Write-Host "Checking $pdfparserZip signature..."
    if(!(Get-FileHash "$DSToolsPath\$pdfparserZip" | Select-String "$pdfparserHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$DSToolsPath\$pdfparserZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$DSToolsPath\$pdfparserZip" -DestinationPath "$DSToolsPath\$pdfparserVer"
    }
    Invoke-WebRequest -Uri "$DSToolsUri$oledumpZip" -OutFile "$DSToolsPath\$oledumpZip"
    Write-Host "Checking $oledumpZip signature..."
    if(!(Get-FileHash "$DSToolsPath\$oledumpZip" | Select-String "$oledumpHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$DSToolsPath\$oledumpZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$DSToolsPath\$oledumpZip" -DestinationPath "$DSToolsPath\$oledumpVer"
    }
}    
else {
    Write-Host -ForegroundColor Green "Didier Stevens Tools Suite found."
}


$ssdeepZip = "ssdeep-2.14.1-win32-binary.zip"
$ssdeepPath = "$ToolsPath\ssdeep"
$ssdeepUri = "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1"
if(!(test-path "$ssdeepPath\$ssdeepZip")) {
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading ssdeep.exe..."
  mkdir "$ssdeepPath"
  Invoke-WebRequest -Uri "$ssdeepUri/$ssdeepZip" -OutFile "$ssdeepPath\$ssdeepZip"
  Expand-Archive "$ssdeepPath\$ssdeepZip" -DestinationPath "$ssdeepPath"
}
else {
  Write-Host -ForegroundColor Green "ssdeep.exe found."
}

$SysinternalsZip = "SysinternalsSuite.zip"
$SysinternalsPath = "$ToolsPath\Sysinternals"
$SysinternalsUri = "https://download.sysinternals.com/files"
$SysmonConfig = "sysmonconfig-export.xml"
$SysmonConfigUri = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master"
if(!(test-path "$SysinternalsPath\$SysinternalsZip")) {
  mkdir "$SysinternalsPath"
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading Sysinternals Suite..."
  Invoke-WebRequest -Uri "$SysinternalsUri/$SysinternalsZip" -OutFile "$SysinternalsPath\$SysinternalsZip"
  Expand-Archive "$SysinternalsPath\$SysinternalsZip" -DestinationPath "$SysinternalsPath"
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading sysmon configuration file..."
  Invoke-WebRequest -Uri "$SysmonConfigUri/$SysmonConfig" -OutFile "$SysinternalsPath\$SysmonConfig"
}
else {
  Write-Host -ForegroundColor Green "Sysinternals Suite found."
}


$WiresharkSig = "SIGNATURES-3.6.0.txt"
$WiresharkHash = "8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255"
$WiresharkKey = "gerald_at_wireshark_dot_org.gpg"
$WiresharkBin = "Wireshark-win64-3.6.0.exe"
$WiresharkPath = "$ToolsPath\Wireshark"
$WiresharkUri1 = "https://www.wireshark.org/download"
$WiresharkUri2 = "https://2.na.dl.wireshark.org/win64"
if(!(test-path "$WiresharkPath\$WiresharkBin")) {
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading Wireshark installer..."
  mkdir "$WiresharkPath"
  Invoke-WebRequest -Uri "$WiresharkUri1/$WiresharkSig" -OutFile "$WiresharkPath\$WiresharkSig"
  Invoke-WebRequest -Uri "$WiresharkUri1/$WiresharkKey" -OutFile "$WiresharkPath\$WiresharkKey"
  Invoke-WebRequest -Uri "$WirehsarkUri2/$WiresharkBin" -OutFile "$WiresharkPath\$WiresharkBin"
  Write-Host "Checking file signature..."
  if(!(Get-FileHash "$WiresharkPath\$WiresharkBin" | Select-String "$WiresharkHash")) {
      Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
      ri "$WiresharkPath\$WiresharkBin"
      ri "$WiresharkPath\$WiresharkKey"
      ri "$WiresharkPath\$WiresharkSig"
  }
  else {
      Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
      Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install with: cmd.exe /C $WiresharkPath\$WiresharkBin"
  }
}
else {
  Write-Host -ForegroundColor Green "Wireshark installer found."
}

$x64dbgZip = "snapshot_2022-01-21_09-58.zip"
$x64dbgHash = "C446A826BC9FCE904817DF7C963E03D6CB73B9860AA06554680D3C42DD4D0096"
$x64dbgPath = "$ToolsPath\x64dbg"
$x64dbgUri = "https://github.com/x64dbg/x64dbg/releases/download/snapshot"
if(!(test-path "$x64dbgPath\$x64dbgZip")) {
    mkdir "$x64dbgPath"
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading x64dbg..."
    Invoke-WebRequest -Uri "$x64dbgUri/$x64dbgZip" -OutFile "$x64dbgPath\$x64dbgZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$x64dbgPath\$x64dbgZip" | Select-String "$x64dbgHash")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$x64dbgPath\$x64dbgZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$x64dbgPath\$x64dbgZip" -DestinationPath "$x64dbgPath"
    }
}
else {
    Write-Host -ForegroundColor Green "x64dbg found."
}
