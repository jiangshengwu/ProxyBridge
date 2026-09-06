param(
    [Parameter(Mandatory=$true)][string]$Compiler,
    [Parameter(Mandatory=$true)][string]$WinDivertPath,
    [string]$OutputPath = "$PSScriptRoot/build"
)
$ErrorActionPreference = 'Stop'
$Compiler = (Resolve-Path -LiteralPath $Compiler).Path
$WinDivertPath = (Resolve-Path -LiteralPath $WinDivertPath).Path
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$sources = @(Get-ChildItem "$PSScriptRoot/../src/*.c" | ForEach-Object FullName)
& $Compiler -O1 -g -DPROXYBRIDGE_EXPORTS -D_WIN32_WINNT=0x0601 "-I$WinDivertPath/include" @sources "$PSScriptRoot/core_tests.c" "-L$WinDivertPath/x64" -lWinDivert -lws2_32 -liphlpapi -o "$OutputPath/core_tests.exe"
if ($LASTEXITCODE) { throw 'Core test build failed' }
Copy-Item -LiteralPath "$WinDivertPath/x64/WinDivert.dll" -Destination $OutputPath -Force
& "$OutputPath/core_tests.exe"
if ($LASTEXITCODE) { throw 'Core tests failed' }
& $Compiler -O1 -D_WIN32_WINNT=0x0601 "$PSScriptRoot/gui_tests.c" "$PSScriptRoot/../gui/profile/profile.c" -luser32 -lgdi32 -lcomctl32 -lshell32 -lcomdlg32 -lwinhttp -ldwmapi -luxtheme -lole32 -o "$OutputPath/gui_tests.exe"
if ($LASTEXITCODE) { throw 'GUI test build failed' }
& "$OutputPath/gui_tests.exe"
if ($LASTEXITCODE) { throw 'GUI tests failed' }
