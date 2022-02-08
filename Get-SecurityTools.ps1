# Download Essential Tools

# to do:
# winget / windows terminal
# different powershell verisons
# Cygwin
# Git for Windows
# python2
# oledump.py
#   https://didierstevens.com/files/software/oledump_V0_0_60.zip
#   D847E499CB84B034E08BCDDC61ADDADA39B90A5FA2E1ABA0756A05039C0D8BA2
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
if(!(Test-Path "$7zPath\$7zBin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading 7-zip msi installer..."
    mkdir "$7zPath"
    Invoke-WebRequest -Uri "https://www.7-zip.org/a/$7zBin" -OutFile "$7zPath\$7zBin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$7zPath\$7zBin" | Select-String "5447C9AC39C48F1BC7C88359B0520396A8C9707B307C107236A93A68E6FD3EB6")) {
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
$python3Sig = "python-3.10.2-amd64.exe.asc"
$python3Path = "$ToolsPath\Python3"
if(!(Test-Path "$python3Path\$python3Bin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading python3 installer..."
    mkdir "$python3Path"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$pythonVer/$python3Bin" -OutFile "$python3Path\$python3Bin"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$pythonVer/$python3Sig" -OutFile "$python3Path\$python3Sig"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$python3Path\$python3Bin" | Select-String "42B181E9B5F424472212742A187260D4EDC73B7683AE83460C974508130E08AD")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$python3Path\$python3Bin"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        # Run the interactive installer
        Write-Host -BackgroundColor DarkBlue -ForegroundColor Cyan "Install with: cmd.exe /C $python3Path\$python3Bin"
    }
}
else {
    Write-Host -ForegroundColor Green "python3 installer found."
}

$pestudioZip = "pestudio.zip"
$pestudioPath = "$ToolsPath\pestudio"
if(!(Test-Path "$pestudioPath\$pestudioZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading pestudio.zip..."
    mkdir "$pestudioPath"
    Invoke-WebRequest -Uri "https://www.winitor.com/tools/pestudio/current/$pestudioZip" -OutFile "$pestudioPath\$pestudioZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$pestudioPath\$pestudioZip" | Select-String "2AF46DC7568FED6DFE8FECA5FEF546F2B2D1BE150DBC12022ED78812DE0DDC9A")) {
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
$bstringsPath = "$ToolsPath\bstrings"
if(!(test-path "$bstringsPath\$bstringsZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $bstringsZip..."
    mkdir "$bstringsPath"
    Invoke-WebRequest -Uri "https://github.com/EricZimmerman/bstrings/releases/download/1.3.0.0/$bstringsZip" -OutFile "$bstringsPath\$bstringsZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$bstringsPath\$bstringsZip" | Select-String "27829DC87C941C472C4DAA6498314A2568769912AFE3F06D79EFFE57C4B8C1EC")) {
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


$CutterZip = "cutter-v2.0.5-x64.Windows.zip"
$CutterPath
# sha256sum=5FD74940DE6D7F3999D0CA4A7CBD947B9F14E8312D7270CE587448D1B67B3096
# Invoke-WebRequest -Uri "https://github.com/rizinorg/cutter/releases/download/v2.0.5/cutter-v2.0.5-x64.Windows.zip" -OutFile "cutter-v2.0.5-x64.Windows.zip"

$Cygwin64Bin
$Cygwin32Bin
$CygwinSig
$CygwinPath
# 32-bit = 719aefe3c8d29df6d074d516905eeda191cb1e8cb502ef1ecca5d0f81c4d7cb13664607443f15c81f02b561ece114af39445f65207a5463a8584746ca384d3ea
# 64-bit = 7897f5ad1aa7c2d3b5767ec1bfe23f945dbc0ad6e4e0fa68cfadc115a2f8c9ec73f5d40b227cbd869546da8696a2692d2b317c96d30b0d0045e23f0a5372ff72
#<https://cygwin.com/setup-x86_64.exe>
#<https://cygwin.com/setup-x86_64.exe.sig>
#<https://cygwin.com/sha512.sum>
#<https://cygwin.com/key/pubring.asc>


$dieZip = "die_win64_portable_3.03.zip"
$diePath = "$ToolPath\die"
if(!(test-path "$diePath\$dieZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $dieZip..."
    mkdir "$diePath"
    Invoke-WebRequest -Uri "https://github.com/horsicq/DIE-engine/releases/download/3.03/$dieZip" -OutFile "$diePath\$dieZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$diePath\$dieZip" | Select-String "F793C8EA4578CAFCA7543FE407F03AC50AC15850E99983F1CC5EE19B0DDA7C78")) {
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


# CFF Explorer Suite
# sha256sum=94f4348ec573b05990b1e19542986e46dc30a87870739f5d5430b60072d5144d
# https://ntcore.com/files/ExplorerSuite.exe


$FlossZip = "floss-v1.7.0-windows.zip"
$FlossPath = "$ToolsPath\Floss"
if(!(test-path "$FlossPath\$FlossZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading floss.exe..."
    mkdir "$FlossPath"
    Invoke-WebRequest -Uri "https://github.com/mandiant/flare-floss/releases/download/v1.7.0/$FlossZip" -OutFile "$FlossPath\$FlossZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$FlossPath\$FlossZip" | Select-String "9B433A949B210BB8A856DE2546CB075C349E0C2582EE9BF6B5FE51D9F95E7690")) {
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


$GhidraPath = "$ToolsPath\Ghidra\ghidra_10.1.1_PUBLIC_20211221.zip"
# https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.1_build/ghidra_10.1.1_PUBLIC_20211221.zip
# sha256sum=d4ee61ed669cec7e20748462f57f011b84b1e8777b327704f1646c0d47a5a0e8

# Ghidra dependency
# https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.14%2B9/OpenJDK11U-jdk_x64_windows_hotspot_11.0.14_9.msi.sha256.txt
# https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.14%2B9/OpenJDK11U-jdk_x64_windows_hotspot_11.0.14_9.msi
# sha256sum=067ff937c3220c5c5fc5c75d82061e99dd6f60d50561c565d231670a8b5e510b

$IDABin = "idafree77_windows.exe"
$IDAPath = "$ToolsPath\IDA"
if(!(test-path "$IDAPath\$IDABin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading IDA (Free)..."
    mkdir "$IDAPath"
    Invoke-WebRequest -Uri "https://out7.hex-rays.com/files/$IDABin" -OutFile "$IDAPath\$IDABin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$IDAPath\$IDABin" | Select-String "D0A3599B4FC7519973F023E63F732D0364C4F3316BA50AF4BC6829DC1DD5D46C")) {
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
$ILSpyPath = "$ToolsPath\ILSpy"
if(!(test-path "$ILSpyPath\$ILSpyZip")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading ILSpy..."
    mkdir "$ILSpyPath"
    Invoke-WebRequest -Uri "https://github.com/icsharpcode/ILSpy/releases/download/v7.1/$ILSpyZip" -OutFile "$ILSpyPath\$ILSpyZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$ILSpyPath\$ILSpyZip" | Select-String "AD61EC674510893C77F4795D27C1733493856230D03574E9490891676E397D0F")) {
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
$msys2Sig = "msys2-x86_64-20220128.exe.sig"
$msys2Hash = "msys2-x86_64-20220128.exe.sha256"
$msys2Path = "$ToolsPath\msys2"
if(!(test-path "$msys2Path\$msys2Bin")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading $msys2Bin..."
    mkdir "$msys2Path"
    Invoke-WebRequest -Uri "https://github.com/msys2/msys2-installer/releases/download/2022-01-28/$msys2Bin" -OutFile "$msys2Path\$msys2Bin"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$msys2Path\$msys2Bin" | Select-String "7d1e86477213c64dfc8fa2c28b891f878576db171df53f18014bb8679c7faa3e")) {
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

$pdfidZip = "pdfid_v0_2_8.zip"
$pdfparserZip = "pdf-parser_V0_7_5.zip"
$pdfToolsPath = "$ToolsPath\PDF Tools"
if(!(test-path "$pdfToolsPath")) {
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading PDF Tools..."
    mkdir "$pdfToolsPath"
    Invoke-WebRequest -Uri "https://didierstevens.com/files/software/$pdfidZip" -OutFile "$pdfToolsPath\$pdfidZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$pdfToolsPath\$pdfidZip" | Select-String "0D0AA12592FA29BC5E7A9C3CFA0AAEBB711CEF373A0AE0AD523723C64C9D02B4")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$pdfToolsPath\$pdfidZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$pdfToolsPath\$pdfidZip" -DestinationPath "$pdfToolsPath"
    }
    Invoke-WebRequest -Uri "https://didierstevens.com/files/software/$pdfparserZip" -OutFile "$pdfToolsPath\$pdfparserZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$pdfToolsPath\$pdfparserZip" | Select-String "5D970AFAC501A71D4FDDEECBD63060062226BF1D587A6A74702DDA79B5C2D3FB")) {
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "BAD CHECKSUM"
        ri "$pdfToolsPath\$pdfparserZip"
    }
    else {
        Write-Host -ForegroundColor Blue -BackgroundColor Green "Checksum OK"
        Expand-Archive "$pdfToolsPath\$pdfparserZip" -DestinationPath "$pdfToolsPath"
    }
}    
else {
    Write-Host -ForegroundColor Green "PDF Tools found."
}


$ssdeepZip = "ssdeep-2.14.1-win32-binary.zip"
$ssdeepPath = "$ToolsPath\ssdeep"
if(!(test-path "$ssdeepPath\$ssdeepZip")) {
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading ssdeep.exe..."
  mkdir "$ssdeepPath"
  Invoke-WebRequest -Uri "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/$ssdeepZip" -OutFile "$ssdeepPath\$ssdeepZip"
  Expand-Archive "$ssdeepPath\$ssdeepZip" -DestinationPath "$ssdeepPath"
}
else {
  Write-Host -ForegroundColor Green "ssdeep.exe found."
}

$SysinternalsZip = "SysinternalsSuite.zip"
$SysinternalsPath = "$ToolsPath\Sysinternals"
if(!(test-path "$SysinternalsPath\$SysinternalsZip")) {
  mkdir "$SysinternalsPath"
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading Sysinternals Suite..."
  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/$SysinternalsZip" -OutFile "$SysinternalsPath\$SysinternalsZip"
  Expand-Archive "$SysinternalsPath\$SysinternalsZip" -DestinationPath "$SysinternalsPath"
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading sysmon configuration file..."
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$SysinternalsPath\sysmonconfig-export.xml"
}
else {
  Write-Host -ForegroundColor Green "Sysinternals Suite found."
}


$WiresharkSig = "SIGNATURES-3.6.0.txt"
$WiresharkKey = "gerald_at_wireshark_dot_org.gpg"
$WiresharkBin = "Wireshark-win64-3.6.0.exe"
$WiresharkPath = "$ToolsPath\Wireshark"
if(!(test-path "$WiresharkPath\$WiresharkBin")) {
  Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading Wireshark installer..."
  mkdir "$WiresharkPath"
  Invoke-WebRequest -Uri "https://www.wireshark.org/download/$WiresharkSig" -OutFile "$WiresharkPath\$WiresharkSig"
  Invoke-WebRequest -Uri "https://www.wireshark.org/download/$WiresharkKey" -OutFile "$WiresharkPath\$WiresharkKey"
  Invoke-WebRequest -Uri "https://2.na.dl.wireshark.org/win64/$WiresharkBin" -OutFile "$WiresharkPath\$WiresharkBin"
  Write-Host "Checking file signature..."
  if(!(Get-FileHash "$WiresharkPath\$WiresharkBin" | Select-String "8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255")) {
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
$x64dbgPath = "$ToolsPath\x64dbg"
if(!(test-path "$x64dbgPath\$x64dbgZip")) {
    mkdir "$x64dbgPath"
    Write-Host -ForegroundColor White -BackgroundColor Blue "Downloading x64dbg..."
    Invoke-WebRequest -Uri "https://github.com/x64dbg/x64dbg/releases/download/snapshot/$x64dbgZip" -OutFile "$x64dbgPath\$x64dbgZip"
    Write-Host "Checking file signature..."
    if(!(Get-FileHash "$x64dbgPath\$x64dbgZip" | Select-String "C446A826BC9FCE904817DF7C963E03D6CB73B9860AA06554680D3C42DD4D0096")) {
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
