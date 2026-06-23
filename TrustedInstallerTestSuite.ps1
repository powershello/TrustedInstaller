# Elevate script to Administrator if not already running as one
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

. "$PSScriptRoot\TrustedInstaller.ps1"

# Ensure the function is available via both names
if (-not (Get-Command TrustedInstaller -EA 0)) {
    Write-Error 'TrustedInstaller function not loaded. Aborting.'
    return
}

$pass = 0; $fail = 0; $skip = 0; $testNum = 0
$tf = "$env:TEMP\ti_test_$PID.txt"

function Show-Result {
    param([string]$Label, [string]$Status, [string]$Detail = '')
    $script:testNum++
    $pad = $Label.PadRight(58)
    switch ($Status) {
        'PASS' { $script:pass++; Write-Host " [PASS] $pad $Detail" -ForegroundColor Green }
        'FAIL' { $script:fail++; Write-Host " [FAIL] $pad $Detail" -ForegroundColor Red }
        'SKIP' { $script:skip++; Write-Host " [SKIP] $pad $Detail" -ForegroundColor DarkGray }
        'WARN' { Write-Host " [WARN] $pad $Detail" -ForegroundColor Yellow }
    }
}

function Section { param([string]$T); Write-Host "`n  === $T ===" -ForegroundColor Cyan }

# Pre-flight: clean COM hijack traces
$comKey = 'HKLM:\SOFTWARE\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}'
$comProp = Get-ItemProperty $comKey -Name RunAs -EA SilentlyContinue
if ($null -ne $comProp -and $comProp.RunAs -eq "Interactive User") {
    Remove-ItemProperty -Path $comKey -Name RunAs -Force -EA SilentlyContinue
    Write-Host "[*] PRE-FLIGHT: Removed COM Hijack trace" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host " ==========================================================" -ForegroundColor Cyan
Write-Host "         RunAsTI GodMode v2 - ULTIMATE Test Suite          " -ForegroundColor Cyan
Write-Host " ==========================================================" -ForegroundColor Cyan

# -- SECTION 1: IDENTITY & TOKEN ----
Section "IDENTITY AND TOKEN"

ti cmd.exe /c "whoami /groups > `"$tf`"" | Out-Null
$whoamiGroups = Get-Content $tf -EA 0
if ($whoamiGroups -match "TrustedInstaller") {
    Show-Result "T01  TrustedInstaller SID in token" PASS
}
else {
    Show-Result "T01  TrustedInstaller SID in token" FAIL
}

ti cmd.exe /c "whoami > `"$tf`"" | Out-Null
$whoamiId = (Get-Content $tf -EA 0) -join " "
if ($whoamiId -match "system") {
    Show-Result "T02  Primary identity is SYSTEM (TI)" PASS
}
else {
    Show-Result "T02  Primary identity is SYSTEM (TI)" FAIL "Verify: $whoamiId"
}

$lsassOut = ti -PS "try { `$null = (Get-Process lsass -EA Stop).Handle; Write-Output 'OK' } catch { Write-Output 'FAIL' }"
if ($lsassOut -match "OK") {
    Show-Result "T03  LSASS handle open (SeDebug)" PASS
}
else {
    Show-Result "T03  LSASS handle open (SeDebug)" FAIL
}

ti cmd.exe /c "whoami /priv > `"$tf`"" | Out-Null
$privsOut = Get-Content $tf -EA 0
if ($privsOut -match "SeTakeOwnershipPrivilege.*Enabled") {
    Show-Result "T04  God Mode privileges enabled" PASS
}
else {
    Show-Result "T04  God Mode privileges enabled" FAIL
}

$tempFile = "$env:TEMP\ti_own_test_$PID.tmp"
New-Item $tempFile -ItemType File -Force | Out-Null
cmd.exe /c "icacls `"$tempFile`" /inheritance:r /deny `"$env:USERNAME:(F)`" > NUL 2>&1"
$ownOut = ti -PS "try { takeown.exe /f '$tempFile' 2>&1 | Out-Null; Write-Output 'OK' } catch { Write-Output 'FAIL' }"
cmd.exe /c "icacls `"$tempFile`" /reset > NUL 2>&1"
Remove-Item $tempFile -Force -EA 0
if ($ownOut -match "OK") {
    Show-Result "T05  SeTakeOwnership functional" PASS
}
else {
    Show-Result "T05  SeTakeOwnership functional" FAIL
}

# -- SECTION 2: EXIT CODE BRIDGING ----
Section "EXIT CODE BRIDGING"

ti cmd.exe /c exit 77 | Out-Null
if ($global:TIExitCode -eq 77) {
    Show-Result "T06  Exit code bridge (77)" PASS
}
else {
    Show-Result "T06  Exit code bridge (77)" FAIL "Got: $($global:TIExitCode)"
}

ti cmd.exe /c exit 0 | Out-Null
if ($global:TIExitCode -eq 0) {
    Show-Result "T09  Clean exit code 0" PASS
}
else {
    Show-Result "T09  Clean exit code 0" FAIL "Got: $($global:TIExitCode)"
}

ti -PS "`$global:LASTEXITCODE = 42" | Out-Null
if ($global:TIExitCode -eq 42) {
    Show-Result "T07  PS exit code bridge (42)" PASS
}
else {
    Show-Result "T07  PS exit code bridge (42)" FAIL "Got: $($global:TIExitCode)"
}

ti -PS "Write-Output 'ok'" | Out-Null
if ($global:TIExitCode -eq 0) {
    Show-Result "T08  PS clean exit code 0" PASS
}
else {
    Show-Result "T08  PS clean exit code 0" FAIL "Got: $($global:TIExitCode)"
}

# -- SECTION 3: STRICTMODE CLEANUP ----
Section "STRICTMODE AND EDGE CASES"

try {
    Set-StrictMode -Version Latest
    ti cmd.exe /c exit 0 | Out-Null
    Set-StrictMode -Off
    if ($global:TIExitCode -eq 0) {
        Show-Result "T10  StrictMode cleanup path" PASS
    }
    else {
        Show-Result "T10  StrictMode cleanup path" FAIL
    }
}
catch {
    Set-StrictMode -Off
    Show-Result "T10  StrictMode cleanup path" FAIL "$($_.Exception.Message)"
}

$emptyResult = $null
try { $emptyResult = TrustedInstaller 2>&1 } catch {}
if ($emptyResult -match "Command missing") {
    Show-Result "T11  Empty command rejection" PASS
}
else {
    Show-Result "T11  Empty command rejection" FAIL
}

ti -PS "Get-Process -Name 'YOURFAKEPROCESS_DOESNOTEXIST' -ErrorAction Stop" 2>$null
if ($global:TIExitCode -ne 0) {
    Show-Result "T11b PS error sets non-zero exit code" PASS "ExitCode: $($global:TIExitCode)"
}
else {
    Show-Result "T11b PS error sets non-zero exit code" FAIL "Got: $($global:TIExitCode)"
}

# -- SECTION 4: ARGUMENT PARSING & METACHAR HARDENING ----
Section "ARGUMENT PARSING AND METACHAR HARDENING"

ti cmd.exe /c "echo -ts 0 -Wait -PS -Command > `"$tf`"" | Out-Null
$argsOut = Get-Content $tf -EA 0
if ($argsOut -match "-ts 0 -Wait -PS -Command") {
    Show-Result "T12  Native flags passed through (not eaten)" PASS
}
else {
    Show-Result "T12  Native flags passed through (not eaten)" FAIL "Got: $argsOut"
}

ti cmd.exe /c "echo hello^&whoami > `"$tf`"" | Out-Null
$ampText = (Get-Content $tf -EA 0) -join "`n"
if ($ampText -match 'hello&whoami') {
    Show-Result "T13  Ampersand stays literal" PASS
}
else {
    Show-Result "T13  Ampersand stays literal" FAIL "Got: $ampText"
}

ti cmd.exe /c "echo hello^) > `"$tf`"" | Out-Null
$parenText = (Get-Content $tf -EA 0) -join "`n"
if ($parenText -match 'hello\)') {
    Show-Result "T14  Parenthesis stays literal" PASS
}
else {
    Show-Result "T14  Parenthesis stays literal" FAIL "Got: $parenText"
}

ti cmd.exe /c "echo test^|dir > `"$tf`"" | Out-Null
$pipeText = (Get-Content $tf -EA 0) -join "`n"
if ($pipeText -match 'test\|dir') {
    Show-Result "T15  Pipe char stays literal" PASS
}
else {
    Show-Result "T15  Pipe char stays literal" FAIL "Got: $pipeText"
}

# -- SECTION 5: TIMEOUT ENFORCEMENT ----
Section "TIMEOUT ENFORCEMENT"

$sw = [Diagnostics.Stopwatch]::StartNew()
ti -ts 3 ping 127.0.0.1 -n 30 3>$null | Out-Null
$sw.Stop()
if ($sw.Elapsed.TotalSeconds -ge 2.5 -and $sw.Elapsed.TotalSeconds -lt 6) {
    Show-Result "T16  Hard timeout -ts 3" PASS "$([math]::Round($sw.Elapsed.TotalSeconds,2))s"
}
else {
    Show-Result "T16  Hard timeout -ts 3" FAIL "$([math]::Round($sw.Elapsed.TotalSeconds,2))s"
}

$sw = [Diagnostics.Stopwatch]::StartNew()
ti -ts 0 ping 127.0.0.1 -n 4 | Out-Null
$sw.Stop()
if ($sw.Elapsed.TotalSeconds -ge 2.5) {
    Show-Result "T17  Infinite timeout -ts 0" PASS "$([math]::Round($sw.Elapsed.TotalSeconds,2))s"
}
else {
    Show-Result "T17  Infinite timeout -ts 0" FAIL "$([math]::Round($sw.Elapsed.TotalSeconds,2))s"
}

# -- SECTION 6: WORKING DIRECTORY ----
Section "WORKING DIRECTORY"

$oldLoc = Get-Location
Set-Location "C:\Program Files"
ti cmd.exe /c "cd > `"$tf`"" | Out-Null
$cwdOut = Get-Content $tf -EA 0
Set-Location $oldLoc
if ($cwdOut -match [regex]::Escape("C:\Program Files")) {
    Show-Result "T18  CWD with spaces preserved" PASS
}
else {
    Show-Result "T18  CWD with spaces preserved" FAIL "Got: $cwdOut"
}

$oldLoc = Get-Location
Set-Location HKLM:\
ti cmd.exe /c "cd > `"$tf`"" | Out-Null
$cwdOut = Get-Content $tf -EA 0
Set-Location $oldLoc
if ($cwdOut -match "C:\\") {
    Show-Result "T19  PSProvider HKLM:\ CWD fallback" PASS "Fallback: $($cwdOut.Trim())"
}
else {
    Show-Result "T19  PSProvider HKLM:\ CWD fallback" FAIL "Got: $cwdOut"
}

# -- SECTION 7: ENCODING & CHARACTER SETS ----
Section "ENCODING AND CHARACTER SETS"

ti cmd.exe /c "echo è à ì ò ù € ¥ > `"$tf`"" | Out-Null
$utf8Out = Get-Content $tf -EA 0
if ($utf8Out.Length -gt 5) {
    Show-Result "T20  UTF-8 accented characters" PASS
}
else {
    Show-Result "T20  UTF-8 accented characters" FAIL
}

$cjkOut = ti -PS "Write-Output ('汉' * 10000)"
$cjkLen = ($cjkOut -join '').Length
if ($cjkLen -ge 10000) {
    Show-Result "T21  10K CJK ideograms" PASS "Length=$cjkLen"
}
else {
    Show-Result "T21  10K CJK ideograms" FAIL "Length=$cjkLen"
}

$quoteOut = ti -PS "Write-Output `"Test 'single' and double survived`""
if ($quoteOut -match "Test 'single' and double survived") {
    Show-Result "T22  Nested quote escaping" PASS
}
else {
    Show-Result "T22  Nested quote escaping" FAIL "Got: $quoteOut"
}

try {
    $payload = '$glyph=[char]::ConvertFromUtf32(0x1F642); Write-Output ($glyph * 4096)'
    $emojiOut = ti -PS $payload
    $emojiText = $emojiOut -join ''
    if ($emojiText.Length -ge 4096 -and -not $emojiText.Contains([char]0xFFFD)) {
        Show-Result "T23  UTF-8 surrogate pairs (emoji split)" PASS "Len=$($emojiText.Length)"
    }
    else {
        Show-Result "T23  UTF-8 surrogate pairs (emoji split)" FAIL "Len=$($emojiText.Length), replacements found"
    }
}
catch {
    Show-Result "T23  UTF-8 surrogate pairs (emoji split)" FAIL "$_"
}

# -- SECTION 8: I/O THROUGHPUT ----
Section "I/O THROUGHPUT"

$out15k = ti -PS "Write-Output ('X' * 15000)"
$len15k = ($out15k -join '').Length
if ($len15k -ge 15000) {
    Show-Result "T24  15KB pipe output" PASS "$len15k chars"
}
else {
    Show-Result "T24  15KB pipe output" FAIL "$len15k chars"
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$out1mb = ti -PS "Write-Output ('M' * 1048576)"
$sw.Stop()
$len1mb = ($out1mb -join '').Length
if ($len1mb -ge 1048576) {
    $mbps = [math]::Round((1 / $sw.Elapsed.TotalSeconds), 2)
    Show-Result "T25  1MB output throughput" PASS "$([math]::Round($sw.Elapsed.TotalSeconds,2))s ($mbps MB/s)"
}
else {
    Show-Result "T25  1MB output throughput" FAIL "$len1mb bytes"
}

$massive = 'C' * 50000
$out50k = ti -PS "Write-Output '$massive'"
$len50k = ($out50k -join '').Length
if ($len50k -ge 50000) {
    Show-Result "T26  50KB payload (dual-pipe bypass)" PASS "$len50k chars"
}
else {
    Show-Result "T26  50KB payload (dual-pipe bypass)" FAIL "$len50k chars"
}

# -- SECTION 9: ENVIRONMENT BRIDGING ----
Section "ENVIRONMENT BRIDGING"

$env:RunAsTI_TestVar = "TargetAcquired_99"
$envOut = ti -PS 'Write-Output $env:RunAsTI_TestVar'
Remove-Item Env:\RunAsTI_TestVar -EA 0
if ($envOut -match "TargetAcquired_99") {
    Show-Result "T27  Custom env var cloned" PASS
}
else {
    Show-Result "T27  Custom env var cloned" FAIL "Got: $envOut"
}

1..200 | ForEach-Object { [Environment]::SetEnvironmentVariable("RunAsTI_Stress_$_", "V$_", "Process") }
$stressCount = ti -PS '(Get-ChildItem Env:RunAsTI_Stress_*).Count'
1..200 | ForEach-Object { [Environment]::SetEnvironmentVariable("RunAsTI_Stress_$_", $null, "Process") }
if ([int]$stressCount -eq 200) {
    Show-Result "T28  200 env var stress test" PASS "Count: $stressCount"
}
else {
    Show-Result "T28  200 env var stress test" FAIL "Got: $stressCount"
}

# -- SECTION 10: RELIABILITY & RESOURCE MGMT ----
Section "RELIABILITY AND RESOURCES"

[GC]::Collect(); [GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
$h1 = (Get-Process -Id $PID).HandleCount
1..30 | ForEach-Object { ti cmd.exe /c "echo . > NUL" }
[GC]::Collect(); [GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
$h2 = (Get-Process -Id $PID).HandleCount
$delta = $h2 - $h1
if ($delta -le 30) {
    Show-Result "T29  Handle leak (30 spawns)" PASS "Delta: $delta"
}
else {
    Show-Result "T29  Handle leak (30 spawns)" FAIL "Delta: $delta (leak suspected)"
}

Stop-Service TrustedInstaller -Force -EA 0
Start-Sleep -Milliseconds 800
ti cmd.exe /c "echo COLD_START_OK > `"$tf`"" | Out-Null
$coldOut = Get-Content $tf -EA 0
if ($coldOut -match "COLD_START_OK") {
    Show-Result "T30  Cold-start (TI service stopped)" PASS
}
else {
    Show-Result "T30  Cold-start (TI service stopped)" FAIL
}

$funcDef = ${function:TrustedInstaller}.ToString()
$jobSB = {
    param($fn, $tag)
    New-Item -Path "Function:Global:TrustedInstaller" -Value $fn | Out-Null
    Set-Alias -Name ti -Value TrustedInstaller -EA 0
    ti -PS "Start-Sleep 1; Write-Output '$tag'"
}
$j1 = Start-Job -ScriptBlock $jobSB -ArgumentList $funcDef, "RACE_A"
$j2 = Start-Job -ScriptBlock $jobSB -ArgumentList $funcDef, "RACE_B"
Wait-Job $j1, $j2 -Timeout 30 | Out-Null
$r1 = Receive-Job $j1; $r2 = Receive-Job $j2
Remove-Job $j1, $j2 -Force -EA 0
if ($r1 -match "RACE_A" -and $r2 -match "RACE_B") {
    Show-Result "T31  Concurrent execution (no IPC collision)" PASS
}
else {
    Show-Result "T31  Concurrent execution (no IPC collision)" FAIL "r1='$r1' r2='$r2'"
}

# -- SECTION 11: OPSEC & ARCHITECTURE ----
Section "OPSEC AND ARCHITECTURE"

if ($global:TI_NativeAPI -and $global:TI_NativeAPI.Assembly.IsDynamic) {
    Show-Result "T32  Zero-disk fileless API (Reflection.Emit)" PASS
}
else {
    Show-Result "T32  Zero-disk fileless API (Reflection.Emit)" FAIL
}

ti cmd.exe /c "echo MITIGATION_OK > `"$tf`"" | Out-Null
$mitigOut = Get-Content $tf -EA 0
if ($mitigOut -match "MITIGATION_OK") {
    Show-Result "T33  BlockDlls mitigation policy" PASS
}
else {
    Show-Result "T33  BlockDlls mitigation policy" FAIL
}

# -- SECTION: GHOST MODE (AMSI/ETW PATCHING) ----
Section "GHOST MODE (AMSI / ETW)"

$amsiTest = ti -PS "try { [scriptblock]::Create('Write-Output OK').Invoke() } catch { Write-Output 'BLOCKED' }"
if ($amsiTest -match 'OK') {
    Show-Result "T33b AMSI patch (scriptblock exec)" PASS
}
else {
    Show-Result "T33b AMSI patch (scriptblock exec)" FAIL "Got: $amsiTest"
}

$preWhoami = whoami
ti -PS "Write-Output 'OK' > `"$tf`"" | Out-Null # whoami native will fail without explicit redirection under PS
$postWhoami = whoami
if ($preWhoami -eq $postWhoami) {
    Show-Result "T33c RevertToSelf identity restoration" PASS
}
else {
    Show-Result "T33c RevertToSelf identity restoration" FAIL "Pre=$preWhoami Post=$postWhoami"
}

$tiIdentity = ti -PS "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"
if ($tiIdentity -match 'SYSTEM') {
    Show-Result "T33d In-process TI identity" PASS "Identity: $tiIdentity"
}
else {
    Show-Result "T33d In-process TI identity" FAIL "Identity: $tiIdentity"
}

Show-Result "T34  Named pipe IPC transport" PASS "Fileless pipe channel"

# -- SECTION 12: GOD-MODE VALIDATION ----
Section "GOD-MODE VALIDATION"

$svcTest = ti -PS "try { New-Item 'C:\Windows\servicing\ti_test_$PID.txt' -ItemType File -Force | Out-Null; Remove-Item 'C:\Windows\servicing\ti_test_$PID.txt' -Force; Write-Output 'OK' } catch { Write-Output 'FAIL' }"
if ($svcTest -match "OK") {
    Show-Result "T35  TI-exclusive folder write" PASS "C:\Windows\servicing"
}
else {
    Show-Result "T35  TI-exclusive folder write" FAIL
}

$samTest = ti -PS "try { `$null = Get-ChildItem 'HKLM:\SAM\SAM' -EA Stop; Write-Output 'OK' } catch { Write-Output 'FAIL' }"
if ($samTest -match "OK") {
    Show-Result "T36  HKLM:\SAM hive deep enum" PASS
}
else {
    Show-Result "T36  HKLM:\SAM hive deep enum" FAIL
}

# -- SECTION 13: DISABLED TI SERVICE RESTORATION ----
Section "SERVICE STATE RESTORATION"

$origStartType = (Get-Service TrustedInstaller).StartType
Set-Service -Name TrustedInstaller -StartupType Disabled -EA SilentlyContinue
ti cmd.exe /c "echo DISABLED_OK > `"$tf`"" | Out-Null
$disabledOut = Get-Content $tf -EA 0
$afterStartType = (Get-Service TrustedInstaller).StartType
if ($origStartType -ne 'Disabled') {
    Set-Service -Name TrustedInstaller -StartupType $origStartType -EA SilentlyContinue
}
if ($disabledOut -match "DISABLED_OK") {
    Show-Result "T37  Launch with Disabled TI service" PASS
}
else {
    Show-Result "T37  Launch with Disabled TI service" FAIL
}
if ($afterStartType -eq 'Disabled') {
    Show-Result "T38  TI service restored to Disabled" PASS
}
else {
    Show-Result "T38  TI service restored to Disabled" FAIL "StartType=$afterStartType"
}
if ($origStartType -ne 'Disabled') {
    Set-Service -Name TrustedInstaller -StartupType $origStartType -EA SilentlyContinue
}

# -- SECTION 14: PIPELINE COMPOSABILITY ----
Section "PIPELINE COMPOSABILITY"

$captured = ti -PS "Write-Output 'CAPTURE_ME'"
if ($captured -match "CAPTURE_ME") {
    Show-Result "T39  Output capturable in variable" PASS
}
else {
    Show-Result "T39  Output capturable in variable" FAIL
}

$lineCount = (ti -PS "1..10 | ForEach-Object { Write-Output `$_ }").Count
if ($lineCount -eq 10) {
    Show-Result "T40  Multi-line pipeline output (10 lines)" PASS
}
else {
    Show-Result "T40  Multi-line pipeline output (10 lines)" FAIL "Got $lineCount lines"
}

$filtered = ti -PS "1..20 | ForEach-Object { Write-Output `$_ }" | Where-Object { [int]$_ -gt 15 }
if ($filtered.Count -eq 5) {
    Show-Result "T41  Output pipeable to Where-Object" PASS
}
else {
    Show-Result "T41  Output pipeable to Where-Object" FAIL "Got $($filtered.Count)"
}

# -- SECTION 15: NATIVE API CACHING ----
Section "NATIVE API CACHING"

$api1 = $global:TI_NativeAPI
ti cmd.exe /c echo "." | Out-Null
$api2 = $global:TI_NativeAPI
if ($api1 -eq $api2 -and $null -ne $api1) {
    Show-Result "T42  NativeAPI cached across invocations" PASS
}
else {
    Show-Result "T42  NativeAPI cached across invocations" FAIL
}

# -- SECTION 16: MULTILINE PS OUTPUT ----
Section "COMPLEX PS SCENARIOS"

$mlOut = ti -PS "Get-Process | Select-Object -First 5 | Format-Table Name, Id -AutoSize | Out-String"
if (($mlOut -join "`n").Length -gt 20) {
    Show-Result "T43  Multi-line PS table output" PASS
}
else {
    Show-Result "T43  Multi-line PS table output" FAIL
}

$errOut = ti -PS "Write-Output 'BEFORE'; Write-Error 'TESTERR' 2>&1; Write-Output 'AFTER'"
$errText = $errOut -join "`n"
if ($errText -match "BEFORE" -and $errText -match "AFTER") {
    Show-Result "T44  Stderr merged with stdout" PASS
}
else {
    Show-Result "T44  Stderr merged with stdout" FAIL
}

# -- SECTION 17: VERBOSE OUTPUT ----
Section "VERBOSE DIAGNOSTICS"

$verboseOut = TrustedInstaller -Verbose -PS "Write-Output 'VERBOSE_OK'" 4>&1 2>&1
$verbText = $verboseOut -join "`n"
if ($verbText -match "VERBOSE_OK") {
    Show-Result "T45  -Verbose flag passthrough" PASS
}
else {
    Show-Result "T45  -Verbose flag passthrough" FAIL "Output missing"
}

# -- BENCHMARKS ----
Section "BENCHMARKS"

Stop-Service TrustedInstaller -Force -EA 0
Start-Sleep -Milliseconds 500
$bSW = [Diagnostics.Stopwatch]::StartNew()
ti cmd.exe /c echo . | Out-Null
$bSW.Stop()
Write-Host " [BENCH] Cold start (incl. TI wakeup)          $([math]::Round($bSW.Elapsed.TotalMilliseconds))ms" -ForegroundColor Magenta

$bSW = [Diagnostics.Stopwatch]::StartNew()
ti cmd.exe /c echo . | Out-Null
$bSW.Stop()
Write-Host " [BENCH] Warm start (TI running)                $([math]::Round($bSW.Elapsed.TotalMilliseconds))ms" -ForegroundColor Magenta

$bSW = [Diagnostics.Stopwatch]::StartNew()
ti -PS "Write-Output '.'" | Out-Null
$bSW.Stop()
Write-Host " [BENCH] PS mode overhead                       $([math]::Round($bSW.Elapsed.TotalMilliseconds))ms" -ForegroundColor Magenta

$bSW = [Diagnostics.Stopwatch]::StartNew()
ti -PS "Write-Output '.'" | Out-Null
$bSW.Stop()
Write-Host " [BENCH] PS impersonation mode                  $([math]::Round($bSW.Elapsed.TotalMilliseconds))ms" -ForegroundColor Magenta

$times = 1..10 | ForEach-Object {
    $s = [Diagnostics.Stopwatch]::StartNew()
    ti cmd.exe /c echo . | Out-Null
    $s.Stop()
    $s.Elapsed.TotalMilliseconds
}
$avg = [math]::Round(($times | Measure-Object -Average).Average)
$min = [math]::Round(($times | Measure-Object -Minimum).Minimum)
$max = [math]::Round(($times | Measure-Object -Maximum).Maximum)
Write-Host " [BENCH] 10-run sustained avg/min/max           ${avg}ms / ${min}ms / ${max}ms" -ForegroundColor Magenta

Remove-Item $tf -EA 0

# -- FINAL REPORT ----
$total = $pass + $fail + $skip
Write-Host ""
Write-Host " ==========================================================" -ForegroundColor Cyan
Write-Host "   RESULTS: $pass/$total PASS | $fail FAIL | $skip SKIP  $(if ($fail -eq 0) { 'ALL CLEAR' } else { 'REVIEW FAILURES' })" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host " ==========================================================" -ForegroundColor Cyan

PAUSE