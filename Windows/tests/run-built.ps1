<# Runs LLVM-MinGW-built tests on native Windows; never loads the interception driver. #>
param([string]$OutputPath = "$PSScriptRoot/out/mingw-x64")
$ErrorActionPreference = 'Stop'
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$names = @('test_cli','test_conntrack','test_dialogs_ui','test_dns','test_engine','test_flows',
    'test_gui_misc','test_hosts','test_json','test_main_ui','test_profile','test_proto',
    'test_proxy_protocols','test_rules_match','test_rules_ui','test_service','core_tests','gui_tests')
$results = foreach ($name in $names) {
    $exe = Join-Path $OutputPath "$name.exe"
    if (-not (Test-Path -LiteralPath $exe)) { throw "Missing test: $exe" }
    $stdout = Join-Path $OutputPath "$name.stdout.log"
    $stderr = Join-Path $OutputPath "$name.stderr.log"
    $process = Start-Process -FilePath $exe -WorkingDirectory $OutputPath -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $process.WaitForExit(120000)) { $process.Kill(); throw "$name timed out" }
    Get-Content -LiteralPath $stdout | Write-Host
    Get-Content -LiteralPath $stderr | Write-Host
    [pscustomobject]@{Test=$name; ExitCode=$process.ExitCode}
}
$results | Format-Table -AutoSize | Out-String | Write-Host
if (@($results | Where-Object ExitCode -ne 0).Count) { throw 'Windows regression tests failed' }
Write-Host "All $($results.Count) native Windows test programs passed."
exit 0
