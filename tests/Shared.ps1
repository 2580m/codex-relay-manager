# Shared dependency-free test infrastructure; compatible with Windows PowerShell 5.1.
Set-StrictMode -Version 2.0
$script:RTTests = New-Object System.Collections.ArrayList
$script:RTRoot = $PSScriptRoot
$script:RTServer = $null
$script:RTBaseUrl = $null
$script:RTCaseDirectory = $null
$script:RTRecorderExe = $null
$script:RTModelSequence = 0

function Add-RelayTest {
    param([string]$Suite, [string]$Name, [scriptblock]$Body)
    [void]$script:RTTests.Add([pscustomobject]@{ Suite = $Suite; Name = $Name; Body = $Body })
}
function Assert-True {
    param($Condition, [string]$Message = 'Expected condition to be true')
    if (-not $Condition) { throw $Message }
}
function Assert-Equal {
    param($Actual, $Expected, [string]$Message = 'Values differ')
    $a = ConvertTo-Json -InputObject $Actual -Depth 30 -Compress
    $b = ConvertTo-Json -InputObject $Expected -Depth 30 -Compress
    if ($a -cne $b) { throw "$Message`nExpected: $b`nActual:   $a" }
}
function Assert-Match {
    param([AllowNull()][string]$Actual, [string]$Pattern, [string]$Message = 'Pattern did not match')
    if ($Actual -notmatch $Pattern) { throw "$Message`nPattern: $Pattern`nActual: $Actual" }
}
function Assert-Throws {
    param([scriptblock]$Body, [string]$Pattern = '.', [string]$Message = 'Expected a readable terminating error')
    $caught = $null
    try { & $Body | Out-Null } catch { $caught = $_ }
    if ($null -eq $caught) { throw $Message }
    Assert-Match ([string]$caught) $Pattern $Message
    return $caught
}
function Assert-StringArray {
    param([AllowNull()]$Value, [switch]$AllowEmpty)
    Assert-True ($null -ne $Value) 'Expected an array, not null'
    Assert-True ($Value -is [array]) 'Expected an array; singleton scalar is not the array contract'
    if (-not $AllowEmpty) { Assert-True ($Value.Count -gt 0) 'Expected at least one string' }
    foreach ($item in $Value) { Assert-True ($item -is [string]) 'Array contains a non-string item' }
}
function New-RelayTestDirectory {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('relay-tests-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($path)
    return $path
}
function Invoke-MockJson {
    param([string]$Path, [string]$Method = 'GET', $Value = $null)
    $parameters = @{ Uri = ($script:RTBaseUrl + $Path); Method = $Method; UseBasicParsing = $true; TimeoutSec = 5; ErrorAction = 'Stop' }
    if ($null -ne $Value) { $parameters.ContentType = 'application/json'; $parameters.Body = ConvertTo-Json -InputObject $Value -Depth 10 -Compress }
    $response = Invoke-WebRequest @parameters
    return ($response.Content | ConvertFrom-Json)
}
function Start-RelayMockServer {
    $node = Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $node.Source
    $info.Arguments = '"' + (Join-Path $script:RTRoot 'mock-server.cjs') + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $script:RTServer = New-Object Diagnostics.Process
    $script:RTServer.StartInfo = $info
    [void]$script:RTServer.Start()
    $lineTask = $script:RTServer.StandardOutput.ReadLineAsync()
    if (-not $lineTask.Wait(10000)) { Stop-RelayMockServer; throw 'Mock server readiness timed out' }
    $line = $lineTask.Result
    if ([string]::IsNullOrWhiteSpace($line)) { throw ('Mock server failed: ' + $script:RTServer.StandardError.ReadToEnd()) }
    $ready = $line | ConvertFrom-Json
    Assert-Equal $ready.host '127.0.0.1' 'Mock must bind only the IPv4 loopback interface'
    $script:RTBaseUrl = 'http://127.0.0.1:' + $ready.port
    Assert-True ((Invoke-MockJson '/__health').ok) 'Mock health check failed'
}
function Stop-RelayMockServer {
    if ($null -ne $script:RTServer) {
        try { if (-not $script:RTServer.HasExited) { $script:RTServer.Kill(); [void]$script:RTServer.WaitForExit(5000) } } finally { $script:RTServer.Dispose(); $script:RTServer = $null }
    }
}
function Set-MockFixture {
    param([string]$ApiKey, [string]$Fixture)
    Invoke-MockJson '/__control' 'POST' @{ key = $ApiKey; fixture = $Fixture } | Out-Null
}
function Get-MockRequests {
    return @((Invoke-MockJson '/__requests').requests)
}
function New-TestProvider {
    param([string]$Fixture = 'models-basic', [string]$Name = '本地 Relay "quoted"', [string]$BaseUrl = '')
    if (-not $BaseUrl) { $BaseUrl = $script:RTBaseUrl + '/v1' }
    $key = 'fixture:' + $Fixture + ':' + [guid]::NewGuid().ToString('N')
    return New-RelayProvider -Name $Name -BaseUrl $BaseUrl -ApiKey $key
}
function Get-TestProviderKey {
    param($Provider)
    return Unprotect-RelayApiKey -CipherText $Provider.EncryptedApiKey
}
function Assert-ResponseShape {
    param($Result)
    Assert-True ($null -ne $Result) 'Responses probe returned null'
    foreach ($property in @('Status', 'Message', 'Events')) { Assert-True ($null -ne $Result.PSObject.Properties[$property]) "Missing probe property $property" }
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$Result.Status)) 'Status must classify the outcome'
    Assert-True ($Result.Message -is [string]) 'Message must be a string'
    Assert-StringArray -Value $Result.Events -AllowEmpty
}
function Assert-Compatible {
    param($Result)
    Assert-ResponseShape $Result
    Assert-Match ([string]$Result.Status) '^(?i:compatible|success|passed|ok|supported|兼容|成功)$' 'Valid SSE must be classified as compatible'
}
function Assert-Incompatible {
    param($Result, [string]$Pattern = '.')
    Assert-ResponseShape $Result
    Assert-True ([string]$Result.Status -notmatch '^(?i:compatible|success|passed|ok|supported|兼容|成功)$') 'Invalid response was incorrectly classified compatible'
    Assert-Match (([string]$Result.Status) + ' ' + $Result.Message) $Pattern 'Outcome must provide a readable error classification'
}
function Assert-NoSecretInStore {
    param([string]$Secret)
    foreach ($file in @(Get-ChildItem -LiteralPath @($script:RTCaseDirectory, $script:RelayCredentialBaseDirectory) -Recurse -File)) {
        $text = [IO.File]::ReadAllText($file.FullName)
        Assert-True (-not $text.Contains($Secret)) ('Plaintext API key leaked to ' + $file.Name)
    }
}
function Invoke-RelayTestCase {
    param($Test)
    $script:RTCaseDirectory = New-RelayTestDirectory
    $oldCredentialBase = $script:RelayCredentialBaseDirectory
    # Temp/AppData may be writable by sandbox identities; exercise a safe private ancestry.
    $privateTestBase = Join-Path ([Environment]::GetFolderPath('UserProfile')) ('.relay-private-tests-' + [guid]::NewGuid().ToString('N'))
    $script:RelayCredentialBaseDirectory = $privateTestBase
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        Invoke-MockJson '/__control' 'POST' @{ reset = $true } | Out-Null
        $initialized = Initialize-RelayStore -Path $script:RTCaseDirectory
        Assert-Equal ([IO.Path]::GetFullPath([string]$initialized).TrimEnd('\', '/')) ([IO.Path]::GetFullPath($script:RTCaseDirectory).TrimEnd('\', '/')) 'Initialize-RelayStore must return its directory'
        Assert-Equal ([IO.Path]::GetFullPath([string]$script:RelayDataDirectory).TrimEnd('\', '/')) ([IO.Path]::GetFullPath($script:RTCaseDirectory).TrimEnd('\', '/')) 'Initialize-RelayStore must update script:RelayDataDirectory'
        & $Test.Body
    } finally {
        $ErrorActionPreference = $oldPreference
        if (Test-Path -LiteralPath $script:RTCaseDirectory) { Remove-Item -LiteralPath $script:RTCaseDirectory -Force -Recurse }
        $resolvedPrivate = [IO.Path]::GetFullPath($privateTestBase)
        $testPrivateParent = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile')).TrimEnd('\')
        if ([IO.Path]::GetDirectoryName($resolvedPrivate) -ine $testPrivateParent -or [IO.Path]::GetFileName($resolvedPrivate) -cnotmatch '^\.relay-private-tests-[a-f0-9]{32}$') { throw 'Test private cleanup escaped its dedicated test directory.' }
        if (Test-Path -LiteralPath $resolvedPrivate) { Remove-Item -LiteralPath $resolvedPrivate -Force -Recurse }
        $script:RelayCredentialBaseDirectory = $oldCredentialBase
    }
}
function Get-TestTomlLiteralValue {
    param([string]$Literal)
    Assert-True ($Literal.Length -ge 2 -and $Literal[0] -eq '"' -and $Literal[$Literal.Length - 1] -eq '"') 'Expected a TOML basic double-quoted literal'
    $output = New-Object Text.StringBuilder
    for ($i = 1; $i -lt $Literal.Length - 1; $i++) {
        $c = $Literal[$i]
        if ($c -eq '\') {
            $i++
            if ($i -ge $Literal.Length - 1) { throw 'Truncated TOML escape' }
            switch -CaseSensitive ($Literal[$i]) {
                'b' { [void]$output.Append([char]8) }
                't' { [void]$output.Append([char]9) }
                'n' { [void]$output.Append([char]10) }
                'f' { [void]$output.Append([char]12) }
                'r' { [void]$output.Append([char]13) }
                '"' { [void]$output.Append('"') }
                '\' { [void]$output.Append('\') }
                'u' {
                    Assert-True ($i + 4 -lt $Literal.Length - 1) 'Truncated TOML Unicode escape'
                    $hex = $Literal.Substring($i + 1, 4)
                    Assert-Match $hex '^[0-9a-fA-F]{4}$' 'Invalid TOML Unicode escape'
                    [void]$output.Append([char][Convert]::ToInt32($hex, 16)); $i += 4
                }
                'U' {
                    Assert-True ($i + 8 -lt $Literal.Length - 1) 'Truncated TOML Unicode escape'
                    $hex = $Literal.Substring($i + 1, 8)
                    Assert-Match $hex '^[0-9a-fA-F]{8}$' 'Invalid TOML Unicode escape'
                    [void]$output.Append([char]::ConvertFromUtf32([Convert]::ToInt32($hex, 16))); $i += 8
                }
                default { throw ('Unsupported TOML escape: \' + $Literal[$i]) }
            }
        } else {
            Assert-True ($c -ne '"' -and [int]$c -ge 32 -and [int]$c -ne 127) 'Unescaped quote or control character in TOML literal'
            [void]$output.Append($c)
        }
    }
    return $output.ToString()
}
function Get-TestConfigMap {
    param($Arguments)
    Assert-StringArray $Arguments
    Assert-Equal $Arguments.Count 14 'Expected seven --config/value pairs'
    $map = @{}
    for ($i = 0; $i -lt $Arguments.Count; $i += 2) {
        Assert-Equal $Arguments[$i] '--config' 'Config switches must be separate argv elements'
        $pair = $Arguments[$i + 1] -split '=', 2
        Assert-Equal $pair.Count 2 'Missing config assignment'
        Assert-True (-not $map.ContainsKey($pair[0])) 'Duplicate config key'
        $map[$pair[0]] = $pair[1]
    }
    return $map
}
function Get-TestRecorderExe {
    if ($script:RTRecorderExe -and (Test-Path -LiteralPath $script:RTRecorderExe)) { return $script:RTRecorderExe }
    $script:RTRecorderDirectory = New-RelayTestDirectory
    $script:RTRecorderExe = Join-Path $script:RTRecorderDirectory 'argv recorder.exe'
    # Windows PowerShell produces a .NET Framework executable runnable from PS5 and PS7.
    $compiler = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $source = Join-Path $script:RTRoot 'argv-recorder.cs'
    $command = "Add-Type -Path '" + $source.Replace("'", "''") + "' -OutputAssembly '" + $script:RTRecorderExe.Replace("'", "''") + "' -OutputType ConsoleApplication -ErrorAction Stop"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    & $compiler -NoProfile -NonInteractive -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $script:RTRecorderExe)) { throw 'Could not compile native argv/env recorder with Windows PowerShell Add-Type' }
    return $script:RTRecorderExe
}
function Invoke-TestRecorder {
    param([string[]]$Arguments, [string]$OutputPath, [string]$KeyName = '')
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Get-TestRecorderExe
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument -Value $_ }) -join ' ')
    $info.EnvironmentVariables['RELAY_TEST_RECORDER_PATH'] = $OutputPath
    $info.EnvironmentVariables['RELAY_TEST_KEY_NAME'] = $KeyName
    $process = [Diagnostics.Process]::Start($info)
    try { Assert-True ($process.WaitForExit(10000)) 'argv recorder timed out'; Assert-Equal $process.ExitCode 0 'argv recorder failed' } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
    return ([IO.File]::ReadAllText($OutputPath) | ConvertFrom-Json)
}
function Wait-TestRecorder {
    param([string]$Path)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt 10) {
        if (Test-Path -LiteralPath $Path) {
            try { return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop) } catch { }
        }
        Start-Sleep -Milliseconds 50
    }
    throw 'Native launch did not produce a complete recorder result within ten seconds'
}
function Remove-TestRecorder {
    if (Get-Variable RTRecorderDirectory -Scope Script -ErrorAction SilentlyContinue) {
        if (Test-Path -LiteralPath $script:RTRecorderDirectory) { Remove-Item -LiteralPath $script:RTRecorderDirectory -Recurse -Force }
    }
}
