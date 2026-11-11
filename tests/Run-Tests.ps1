#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ScriptPath = '',
    [string[]]$Suite = @(),
    [switch]$SelfTest,
    [switch]$List,
    [switch]$UsePester,
    [string]$ResultPath = '',
    [switch]$AdapterMode
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $ScriptPath) { $ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'codex-relay.ps1' }
. (Join-Path $PSScriptRoot 'Shared.ps1')

function Save-RelayTestResult {
    param($Value)
    if ($ResultPath) {
        $fullPath = [IO.Path]::GetFullPath($ResultPath)
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullPath))
        [IO.File]::WriteAllText($fullPath, (ConvertTo-Json -InputObject $Value -Depth 30), (New-Object Text.UTF8Encoding($true)))
    }
}
function Test-RelaySyntax {
    param([string]$MainPath)
    $files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File)
    if ($MainPath -and (Test-Path -LiteralPath $MainPath -PathType Leaf)) { $files += Get-Item -LiteralPath $MainPath }
    foreach ($file in $files) {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        Assert-Equal @($errors).Count 0 ('PowerShell parse error in ' + $file.FullName + ': ' + (($errors | ForEach-Object { $_.Message }) -join '; '))
        # Parse again in the actual Windows PowerShell 5.1 engine even when runner uses PS7.
        $engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $code = '$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile(''' + $file.FullName.Replace("'", "''") + ''',[ref]$t,[ref]$e);if($e.Count){$e | ForEach-Object {Write-Output $_.Message};exit 1}'
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $messages = & $engine -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
        Assert-Equal $LASTEXITCODE 0 ('Windows PowerShell 5.1 AST parse failed: ' + $file.Name + ' ' + ($messages -join ' '))
        foreach ($command in @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))) {
            if ($file.FullName -eq $MainPath) {
                Assert-True ($command.GetCommandName() -notin @('Invoke-Expression', 'iex')) 'Main script must not use Invoke-Expression for native launch'
            }
        }
    }
}
function Get-RelayConfigFingerprint {
    $paths = @((Join-Path $env:USERPROFILE '.codex\config.toml'))
    if ($env:CODEX_HOME) { $paths += Join-Path $env:CODEX_HOME 'config.toml' }
    $result = @{}
    foreach ($path in @($paths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $result[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash + ':' + (Get-Item -LiteralPath $path).LastWriteTimeUtc.Ticks
        } else { $result[$path] = '<absent>' }
    }
    return $result
}
function Assert-RelayConfigUnchanged {
    param($Before)
    $after = Get-RelayConfigFingerprint
    foreach ($path in $Before.Keys) { Assert-Equal $after[$path] $Before[$path] ('Tests detected an unexpected write to user Codex configuration: ' + $path) }
}
function Import-RelayLibrary {
    param([string]$Path, [string]$DataPath)
    # Probe in a child first so an accidental menu/read loop cannot hang this runner.
    $engine = (Get-Process -Id $PID).Path
    $code = '$ErrorActionPreference=''Stop''; . ''' + $Path.Replace("'", "''") + ''' -LibraryOnly -DataDirectory ''' + $DataPath.Replace("'", "''") + '''; if(Test-Path -LiteralPath ''' + $DataPath.Replace("'", "''") + '''){throw ''LibraryOnly initialized the data directory''}; Write-Output ''RELAY_LIBRARY_ONLY_OK'''
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $engine
    $info.Arguments = '-NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        Assert-True ($process.WaitForExit(10000)) 'LibraryOnly import hung (possible menu or network initialization)'
        Assert-Equal $process.ExitCode 0 ('LibraryOnly import failed: ' + $stderr.Result)
        Assert-Equal $stdout.Result.Trim() 'RELAY_LIBRARY_ONLY_OK' 'LibraryOnly import must not display menus or initialize storage'
    } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
}

$script:RTImportDirectory = $null
$script:RTBeforeConfig = Get-RelayConfigFingerprint
try {
    Test-RelaySyntax -MainPath $ScriptPath
    Write-Host 'PASS AST parsing (current engine + Windows PowerShell 5.1)'
    foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'Test-*.ps1' -File | Sort-Object Name)) { . $file.FullName }
    $script:RTSelected = @($script:RTTests | Where-Object { $Suite.Count -eq 0 -or $_.Suite -in $Suite })
    if ($List) {
        $script:RTSelected | Select-Object Suite, Name | Format-Table -AutoSize
        Write-Host ('Registered: ' + $script:RTSelected.Count)
        return
    }
    if (-not $SelfTest -and -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw "Main script not found: $ScriptPath. Use -ScriptPath or -SelfTest (infrastructure only)." }
    if ($UsePester) {
        $available = @(Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]'3.4' -and $_.Version -lt [version]'5.0' } | Sort-Object Version)
        if ($available.Count -eq 0) { throw 'Pester 3.4/4.x is not installed; omit -UsePester for the dependency-free runner.' }
        $pester = $available[0]
        Import-Module $pester.Path -Force
        $result = Invoke-Pester -Script @{ Path = (Join-Path $PSScriptRoot 'PesterAdapter.Tests.ps1'); Parameters = @{ ScriptPath = $ScriptPath; Suite = $Suite } } -PassThru
        Save-RelayTestResult ([ordered]@{ Engine = [string]$PSVersionTable.PSVersion; Runner = 'Pester'; PesterVersion = [string]$pester.Version; ScriptPath = $ScriptPath; TimestampUtc = [DateTime]::UtcNow.ToString('o'); Passed = $result.PassedCount; Failed = $result.FailedCount; Total = $result.TotalCount; Tests = @($result.TestResult | Select-Object Describe, Name, Passed, Result, FailureMessage) })
        if ($result.FailedCount -gt 0) { exit 1 }
        return
    }
    Start-RelayMockServer
    if ($SelfTest) {
        $health = Invoke-MockJson '/__health'
        Assert-True $health.ok
        $exe = Get-TestRecorderExe
        $output = Join-Path $script:RTRecorderDirectory 'selftest.json'
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $exe; $info.Arguments = 'one "two words"'; $info.UseShellExecute = $false
        $info.EnvironmentVariables['RELAY_TEST_RECORDER_PATH'] = $output
        $process = [Diagnostics.Process]::Start($info)
        try { Assert-True ($process.WaitForExit(5000)); Assert-Equal $process.ExitCode 0 } finally { $process.Dispose() }
        $record = [IO.File]::ReadAllText($output) | ConvertFrom-Json
        Assert-Equal @($record.Arguments) @('one', 'two words')
        Write-Host ('PASS infrastructure: loopback dynamic port, recorder compilation/native argv, ' + $script:RTTests.Count + ' registered test cases')
        return
    }
    $ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
    $script:RTImportDirectory = Join-Path ([IO.Path]::GetTempPath()) ('relay-import-' + [guid]::NewGuid().ToString('N'))
    Import-RelayLibrary -Path $ScriptPath -DataPath $script:RTImportDirectory
    . $ScriptPath -LibraryOnly -DataDirectory $script:RTImportDirectory
    Assert-True (-not (Test-Path -LiteralPath $script:RTImportDirectory)) 'LibraryOnly initialized storage in the runner'
    $required = @('Initialize-RelayStore', 'Normalize-RelayBaseUrl', 'Protect-RelayApiKey', 'Unprotect-RelayApiKey', 'Read-RelayJson', 'Write-RelayJson', 'Get-RelayProviders', 'Save-RelayProvider', 'New-RelayProvider', 'Remove-RelayProvider', 'Get-RelayModels', 'Get-RelayModelCache', 'Test-RelayResponse', 'Get-RelayCompatibility', 'ConvertTo-TomlString', 'Get-RelayCodexArguments', 'ConvertTo-WindowsArgument', 'Start-RelayCodex')
    foreach ($name in $required) { Get-Command $name -CommandType Function -ErrorAction Stop | Out-Null }
    if ($AdapterMode) { return }
    Assert-True ($script:RTSelected.Count -gt 0) 'No tests matched Suite filter'
    $passed = 0; $failed = 0
    $caseResults = New-Object System.Collections.ArrayList
    foreach ($test in $script:RTSelected) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        try {
            Invoke-RelayTestCase $test
            $passed++
            [void]$caseResults.Add([ordered]@{ Suite = $test.Suite; Name = $test.Name; Passed = $true; Seconds = $clock.Elapsed.TotalSeconds; Error = $null })
            Write-Host ('PASS [{0}] {1} ({2:N2}s)' -f $test.Suite, $test.Name, $clock.Elapsed.TotalSeconds)
        } catch {
            $failed++
            [void]$caseResults.Add([ordered]@{ Suite = $test.Suite; Name = $test.Name; Passed = $false; Seconds = $clock.Elapsed.TotalSeconds; Error = $_.Exception.Message; Stack = $_.ScriptStackTrace })
            Write-Host ('FAIL [{0}] {1}' -f $test.Suite, $test.Name)
            Write-Host $_.Exception.Message
            Write-Host $_.ScriptStackTrace
        }
    }
    Assert-RelayConfigUnchanged $script:RTBeforeConfig
    Write-Host ('RESULT Passed={0} Failed={1} Total={2} PS={3}' -f $passed, $failed, $script:RTSelected.Count, $PSVersionTable.PSVersion)
    Save-RelayTestResult ([ordered]@{ Engine = [string]$PSVersionTable.PSVersion; Runner = 'Standalone'; ScriptPath = $ScriptPath; TimestampUtc = [DateTime]::UtcNow.ToString('o'); Passed = $passed; Failed = $failed; Total = $script:RTSelected.Count; Tests = @($caseResults.ToArray()) })
    if ($failed -gt 0) { exit 1 }
} catch {
    Write-Error -Message $_ -ErrorAction Continue
    if ($AdapterMode) { throw }
    exit 2
} finally {
    if (-not $AdapterMode) {
        Stop-RelayMockServer
        Remove-TestRecorder
        if ($script:RTImportDirectory -and (Test-Path -LiteralPath $script:RTImportDirectory)) { Remove-Item -LiteralPath $script:RTImportDirectory -Force -Recurse }
        Assert-RelayConfigUnchanged $script:RTBeforeConfig
    }
}
