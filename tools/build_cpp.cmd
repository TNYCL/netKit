@echo off
setlocal
cd /d "%~dp0.."
if not exist artifacts mkdir artifacts
if not defined VCINSTALLDIR (
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\VC\Auxiliary\Build\vcvars64.bat" >nul
)
cl /nologo /std:c++17 /EHsc /W4 /WX /I include examples\cpp\main.cpp target\release\netkit_ffi.dll.lib /Fo:artifacts\cpp-example.obj /Fe:target\release\cpp-example.exe
if errorlevel 1 exit /b 1
cl /nologo /LD /TC /W4 /WX tests\fixtures\mock_pcap.c /Fo:artifacts\mock_pcap.obj /Fe:artifacts\mock_pcap.dll
if errorlevel 1 exit /b 1
target\release\cpp-example.exe
