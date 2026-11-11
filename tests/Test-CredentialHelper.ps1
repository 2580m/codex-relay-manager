# CredentialHelper suite for Run-Tests.ps1. Fixture keys and loopback only.
# Optional official CLI: RELAY_TEST_CODEX_EXE=<official 0.167.1 executable>.
# The test runner imports the main library; tests never override its functions.

function Invoke-CredentialTestProcess {
    param([string]$Command, [string[]]$Arguments, [string]$Cwd, [int]$Timeout = 25000, [hashtable]$Environment = @{})
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Command
    $info.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' ')
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false, $true)
    $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $info.WorkingDirectory = $Cwd
    foreach ($name in $Environment.Keys) {
        if ($null -eq $Environment[$name]) { $info.EnvironmentVariables.Remove($name) }
        else { $info.EnvironmentVariables[$name] = $Environment[$name] }
    }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    $stdoutBytes = New-Object IO.MemoryStream
    try {
        [void]$process.Start()
        # Read raw bytes: StreamReader would silently strip a BOM and hide a regression.
        $stdout = $process.StandardOutput.BaseStream.CopyToAsync($stdoutBytes)
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Timeout)) { $process.Kill(); [void]$process.WaitForExit(5000); throw 'Credential test child timed out.' }
        $null = $stdout.GetAwaiter().GetResult()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = (New-Object Text.UTF8Encoding($false, $true)).GetString($stdoutBytes.ToArray()); Stderr = $stderr.GetAwaiter().GetResult() }
    } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose(); $stdoutBytes.Dispose() }
}
function Invoke-CredentialTestHelper {
    param($Config, [string[]]$Arguments = @())
    if (-not $Arguments.Count) { $Arguments = $Config.Args }
    return Invoke-CredentialTestProcess $Config.Command $Arguments $Config.Cwd
}
function Set-CredentialTestAcl {
    param([string]$Path, $Acl)
    # Modify DACL only: Set-Acl can attempt a privileged SACL write.
    $type = if ([IO.Directory]::Exists($Path)) { [Security.AccessControl.DirectorySecurity] } else { [Security.AccessControl.FileSecurity] }
    $dacl = [Activator]::CreateInstance($type)
    $dacl.SetSecurityDescriptorSddlForm($Acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access), [Security.AccessControl.AccessControlSections]::Access)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        if ([IO.Directory]::Exists($Path)) { [IO.Directory]::SetAccessControl($Path, $dacl) }
        else { [IO.File]::SetAccessControl($Path, $dacl) }
    } else {
        $item = Get-Item -LiteralPath $Path
        [IO.FileSystemAclExtensions]::SetAccessControl($item, $dacl)
    }
}
function Assert-CredentialFailure {
    param($Result, [string]$Reason = '', [string]$Stage = '', [string]$ExceptionPattern = '', [string[]]$Secrets = @())
    Assert-True ($Result.ExitCode -ne 0) 'Invalid credentials unexpectedly succeeded'
    # Do not include captured streams in a failed assertion: they may contain the secret being tested.
    Assert-True ($Result.Stdout -ceq '') 'Failed helper emitted stdout'
    foreach ($secret in $Secrets) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            Assert-True (-not ($Result.Stdout + $Result.Stderr).Contains($secret)) 'Helper diagnostic exposed a fixture key, ciphertext or untrusted input'
        }
    }
    $diagnostic = [regex]::Match($Result.Stderr, '\ARelay credential helper failed\. stage=(?<stage>[A-Z][A-Z_]*); reason=(?<reason>[^\r\n]+); exception=(?<exception>[A-Za-z_][A-Za-z0-9_.+`]*); hresult=0x(?<hresult>[0-9A-Fa-f]{8})(?:\r?\n)?\z')
    Assert-True $diagnostic.Success 'Helper must emit one safe stage/reason/exception/HRESULT diagnostic on stderr'
    $safeStages = @('WINDOWS_CHECK', 'DATA_PATH', 'ROOT_ACL', 'HELPER_DIRECTORY_ACL', 'HELPER_FILE_ACL', 'HELPER_LOCATION', 'PROVIDER_RECORD', 'DPAPI_ASSEMBLY', 'DPAPI_DECRYPT', 'TOKEN_VALIDATION', 'TOKEN_OUTPUT')
    $safeReasons = @(
        'Credential helper requires Windows.', 'Invalid credential data path.', 'Invalid credential data root.',
        'Credential store must already exist.', 'Credential paths cannot contain reparse points.',
        'Credential root must have a protected ACL.', 'Credential paths must inherit the protected root ACL.',
        'Untrusted credential path owner.', 'Credential path ACL grants access to another identity.',
        'Credential path must grant current user full control.', 'CodexSandboxUsers may only have read and execute access, not write or administrative permissions.', 'Invalid credential Provider ID.',
        'Invalid credential store size.', 'Credential store must be an array.', 'Invalid credential provider record.',
        'Duplicate credential Provider ID.', 'Invalid credential ciphertext.', 'Credential provider not found.',
        'Invalid helper location.', 'Invalid credential length.', 'Invalid credential token.',
        'Access denied by Windows security or file permissions.', 'Required credential file or directory was not found.',
        'DPAPI decryption failed; verify the Windows user/profile and re-enter the API key if needed.',
        'Credential store could not be read or parsed; verify JSON format, encrypted data and file access.',
        'Decrypted token is not valid UTF-8 or contains unsupported characters.',
        'Windows file or stream operation failed; the file may be locked or unavailable.',
        'Windows DPAPI assembly could not be loaded.',
        'Unexpected failure at the reported stage; use the exception type and HRESULT for diagnosis.'
    )
    Assert-True ($safeStages -ccontains $diagnostic.Groups['stage'].Value) 'Helper exposed an unknown stage'
    Assert-True ($safeReasons -ccontains $diagnostic.Groups['reason'].Value) 'Helper exposed a non-whitelisted reason'
    if ($Reason) { Assert-Equal $diagnostic.Groups['reason'].Value $Reason 'Unexpected safe diagnostic reason' }
    if ($Stage) { Assert-Equal $diagnostic.Groups['stage'].Value $Stage 'Unexpected credential failure stage' }
    if ($ExceptionPattern) { Assert-Match $diagnostic.Groups['exception'].Value $ExceptionPattern 'Unexpected credential exception type' }
}

Add-RelayTest 'CredentialHelper' 'preview has no side effects; install returns static absolute auth config' {
    $p = New-TestProvider
    $before = [IO.File]::ReadAllText((Join-Path $script:RTCaseDirectory 'providers.json'))
    $preview = Get-RelayCredentialConfig $p
    $directory = Join-Path $script:RTCaseDirectory 'credentials'
    Assert-True (-not [IO.Directory]::Exists($directory))
    Assert-Equal $preview.Args @('-NoProfile', '-NonInteractive', '-File', (Join-Path $directory 'credential-helper.ps1'), '-DataDirectory', $script:RTCaseDirectory, '-ProviderId', $p.Id)
    Assert-Equal $preview.TimeoutMs 15000
    Assert-Equal $preview.RefreshIntervalMs 300000
    Assert-Equal $preview.Cwd $script:RTCaseDirectory
    Assert-True ([IO.Path]::IsPathRooted($preview.Command))
    Assert-Equal ([IO.Path]::GetFileName($preview.Command)) 'powershell.exe'
    $config = Install-RelayCredentialHelper $p
    Assert-Equal $config $preview
    Assert-Equal ([IO.File]::ReadAllText((Join-Path $script:RTCaseDirectory 'providers.json'))) $before
    $helper = $config.Args[3]
    $stamp = [IO.File]::GetLastWriteTimeUtc($helper)
    Assert-Equal (Install-RelayCredentialHelper $p) $config
    Assert-Equal ([IO.File]::GetLastWriteTimeUtc($helper)) $stamp
    Assert-True (-not (Get-Acl -LiteralPath $directory).AreAccessRulesProtected)
    Assert-True (-not (Get-Acl -LiteralPath $helper).AreAccessRulesProtected)
    $bytes = [IO.File]::ReadAllBytes($helper)
    Assert-True (-not ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191))
    Assert-NoSecretInStore (Get-TestProviderKey $p)
}
Add-RelayTest 'CredentialHelper' 'independent PS5 child emits exact UTF8 token only; same model different provider stays isolated' {
    $p = New-TestProvider; $other = New-TestProvider
    $config = Install-RelayCredentialHelper $p
    $otherConfig = Install-RelayCredentialHelper $other
    $first = Invoke-CredentialTestHelper $config
    $second = Invoke-CredentialTestHelper $otherConfig
    Assert-Equal $first.ExitCode 0; Assert-Equal $first.Stderr ''
    Assert-Equal $second.ExitCode 0; Assert-Equal $second.Stderr ''
    Assert-Equal $first.Stdout (Get-TestProviderKey $p)
    Assert-Equal $second.Stdout (Get-TestProviderKey $other)
    Assert-True ($first.Stdout -cne $second.Stdout)
    Assert-Equal $config.Command $otherConfig.Command
    Assert-Equal $config.Args[3] $otherConfig.Args[3]
    Assert-True ($config.Args[-1] -cne $otherConfig.Args[-1])
    # Keys with non-ASCII prove byte encoding, not just the default OEM codepage.
    $unicodeKey = 'fixture-utf8-' + [char]0x4e2d + [char]0x6587 + '-' + [guid]::NewGuid().ToString('N')
    $p.EncryptedApiKey = Protect-RelayApiKey $unicodeKey
    Write-RelayJson (Join-Path $script:RTCaseDirectory 'providers.json') @($p, $other)
    $unicode = Invoke-CredentialTestHelper $config
    Assert-Equal $unicode.ExitCode 0; Assert-Equal $unicode.Stdout $unicodeKey; Assert-Equal $unicode.Stderr ''
    Assert-NoSecretInStore $first.Stdout
    Assert-NoSecretInStore $second.Stdout
    Assert-NoSecretInStore $unicodeKey
    Assert-Equal @(Get-MockRequests).Count 0
}
Add-RelayTest 'CredentialHelper' 'unknown invalid traversal uppercase and control-character provider IDs fail without stdout' {
    $p = New-TestProvider; $config = Install-RelayCredentialHelper $p
    $secrets = @((Get-TestProviderKey $p), $p.EncryptedApiKey)
    foreach ($id in @('../escape', ('relay_' + ('A' * 32)), ($p.Id + "`n"), ('relay_' + ('0' * 32)))) {
        $arguments = [string[]]$config.Args.Clone(); $arguments[-1] = $id
        $reason = if ($id -ceq ('relay_' + ('0' * 32))) { 'Credential provider not found.' } else { 'Invalid credential Provider ID.' }
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config $arguments) -Reason $reason -Stage 'PROVIDER_RECORD' -ExceptionPattern '^System\.Management\.Automation\.RuntimeException$' -Secrets ($secrets + @($id))
        if ($id -ne ('relay_' + ('0' * 32))) { Assert-Throws { Get-RelayCredentialConfig ([pscustomobject]@{ Id = $id }) } 'Provider ID' | Out-Null }
    }
    $argsCopy = [string[]]$config.Args.Clone(); $argsCopy[5] += "`n"
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config $argsCopy) -Reason 'Invalid credential data path.' -Stage 'DATA_PATH' -Secrets $secrets
}
Add-RelayTest 'CredentialHelper' 'malformed JSON malicious ciphertext DPAPI failures duplicates and control tokens fail closed' {
    $p = New-TestProvider; $config = Install-RelayCredentialHelper $p
    $store = Join-Path $script:RTCaseDirectory 'providers.json'
    $original = [IO.File]::ReadAllText($store)
    $key = Get-TestProviderKey $p
    $originalCipher = $p.EncryptedApiKey
    $secrets = @($key, $originalCipher)
    foreach ($cipher in @('$(Write-Output INJECTED)', ('A' * 131076), 'AAAA', ($originalCipher + "`n"), ('A' * 17), (('A' * 21) + 'B=='))) {
        $p.EncryptedApiKey = $cipher
        Write-RelayJson $store @($p)
        $reason = if ($cipher -ceq ('A' * 17)) { 'Credential store could not be read or parsed; verify JSON format, encrypted data and file access.' } else { 'Invalid credential ciphertext.' }
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'PROVIDER_RECORD' -Reason $reason -Secrets ($secrets + @($cipher, 'INJECTED'))
    }
    # Valid Base64 is not necessarily a DPAPI blob; retain its safe Windows type and HRESULT.
    $p.EncryptedApiKey = [Convert]::ToBase64String((New-Object byte[] 128))
    Write-RelayJson $store @($p)
    $dpapi = Invoke-CredentialTestHelper $config
    Assert-CredentialFailure $dpapi -Stage 'DPAPI_DECRYPT' -Reason 'DPAPI decryption failed; verify the Windows user/profile and re-enter the API key if needed.' -ExceptionPattern '^System\.Security\.Cryptography\.CryptographicException$' -Secrets ($secrets + @($p.EncryptedApiKey))
    Assert-True ($dpapi.Stderr -notmatch 'hresult=0x00000000') 'DPAPI diagnostic lost its Windows failure HRESULT'
    foreach ($badToken in @("fixture`nINJECTED", "fixture`tTOKEN", ('fixture' + [char]0), ' fixture-leading', 'fixture-trailing ')) {
        $raw = [Text.Encoding]::UTF8.GetBytes($badToken)
        $p.EncryptedApiKey = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($raw, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
        Write-RelayJson $store @($p)
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'TOKEN_VALIDATION' -Reason 'Invalid credential token.' -Secrets ($secrets + @($badToken, $p.EncryptedApiKey, 'INJECTED'))
    }
    foreach ($invalidBytes in @(@{ Bytes = [byte[]]@(0xc3, 0x28); Reason = 'Decrypted token is not valid UTF-8 or contains unsupported characters.'; Type = '^System\.Text\.DecoderFallbackException$' }, @{ Bytes = [byte[]]@(); Reason = 'Invalid credential length.'; Type = '^System\.Management\.Automation\.RuntimeException$' })) {
        $p.EncryptedApiKey = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($invalidBytes.Bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
        Write-RelayJson $store @($p)
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'TOKEN_VALIDATION' -Reason $invalidBytes.Reason -ExceptionPattern $invalidBytes.Type -Secrets ($secrets + @($p.EncryptedApiKey))
    }
    # Put fixture secrets and error-looking text inside malformed JSON to detect parser-message leaks.
    $malformed = '[{"Id":"' + $p.Id + '","EncryptedApiKey":"' + $originalCipher + '","probe":"' + $key + '","raw":"JSON_PARSER_SENTINEL"}, invalid]'
    [IO.File]::WriteAllText($store, $malformed, (New-Object Text.UTF8Encoding($false)))
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'PROVIDER_RECORD' -Reason 'Credential store could not be read or parsed; verify JSON format, encrypted data and file access.' -Secrets ($secrets + @('JSON_PARSER_SENTINEL', $malformed))
    [IO.File]::WriteAllText($store, '{malformed', (New-Object Text.UTF8Encoding($false)))
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'PROVIDER_RECORD' -Reason 'Credential store must be an array.' -Secrets ($secrets + @('{malformed'))
    foreach ($record in @(@{ Id = $p.Id }, @{ EncryptedApiKey = $originalCipher }, @{ Id = $p.Id; EncryptedApiKey = 42 }, @{ Id = $p.Id; EncryptedApiKey = @($originalCipher) })) {
        Write-RelayJson $store @($record)
        $reason = if ($record.ContainsKey('Id') -and $record.ContainsKey('EncryptedApiKey')) { 'Invalid credential ciphertext.' } else { 'Invalid credential provider record.' }
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'PROVIDER_RECORD' -Reason $reason -Secrets $secrets
    }
    [IO.File]::WriteAllText($store, $original, (New-Object Text.UTF8Encoding($false)))
    $p = @(Get-RelayProviders)[0]
    Write-RelayJson $store @($p, $p)
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'PROVIDER_RECORD' -Reason 'Duplicate credential Provider ID.' -Secrets $secrets
    Remove-Item -LiteralPath $store -Force
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'PROVIDER_RECORD' -Reason 'Required credential file or directory was not found.' -Secrets $secrets
    Assert-True (-not [IO.File]::Exists($store)) 'Helper initialized missing store'
}
Add-RelayTest 'CredentialHelper' 'modified helper is preserved and refused rather than silently overwritten' {
    $p = New-TestProvider; $config = Install-RelayCredentialHelper $p
    $path = $config.Args[3]
    [IO.File]::AppendAllText($path, "`r`n# user modification", (New-Object Text.UTF8Encoding($false)))
    $before = [IO.File]::ReadAllText($path)
    Assert-Throws { Install-RelayCredentialHelper $p } 'modified' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($path)) $before
    Assert-Equal @(Get-ChildItem -LiteralPath (Split-Path $path -Parent) -Filter '*.tmp').Count 0
}
Add-RelayTest 'CredentialHelper' 'unprotected root and non-inheriting or broad child ACL are refused without ACL repair' {
    $p = New-TestProvider; $config = Install-RelayCredentialHelper $p
    $path = $config.Args[3]
    $secrets = @((Get-TestProviderKey $p), $p.EncryptedApiKey)
    $originalAcl = Get-Acl -LiteralPath $path
    $acl = Get-Acl -LiteralPath $path
    $acl.SetAccessRuleProtection($true, $true)
    Set-CredentialTestAcl -Path $path -Acl $acl
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'HELPER_FILE_ACL' -Reason 'Credential paths must inherit the protected root ACL.' -Secrets $secrets
    Assert-Throws { Install-RelayCredentialHelper $p } 'inherit' | Out-Null
    Set-CredentialTestAcl -Path $path -Acl $originalAcl
    $acl = Get-Acl -LiteralPath $path
    $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'Read', 'Allow')
    [void]$acl.AddAccessRule($rule); Set-CredentialTestAcl -Path $path -Acl $acl
    Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'HELPER_FILE_ACL' -Reason 'Credential path ACL grants access to another identity.' -Secrets $secrets
    Assert-Throws { Install-RelayCredentialHelper $p } 'another identity' | Out-Null
    Set-CredentialTestAcl -Path $path -Acl $originalAcl
    $rootAcl = Get-Acl -LiteralPath $script:RTCaseDirectory
    try {
        $acl = Get-Acl -LiteralPath $script:RTCaseDirectory
        $acl.SetAccessRuleProtection($false, $true)
        Set-CredentialTestAcl -Path $script:RTCaseDirectory -Acl $acl
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config) -Stage 'ROOT_ACL' -Reason 'Credential root must have a protected ACL.' -Secrets $secrets
        Assert-Throws { Get-RelayCredentialConfig $p } 'protected ACL' | Out-Null
        Assert-True (-not (Get-Acl -LiteralPath $script:RTCaseDirectory).AreAccessRulesProtected)
    } finally { Set-CredentialTestAcl -Path $script:RTCaseDirectory -Acl $rootAcl }
}
Add-RelayTest 'CredentialHelper' 'junction in an ancestor or credentials directory is rejected' {
    $p = New-TestProvider; $config = Install-RelayCredentialHelper $p
    $outer = New-RelayTestDirectory
    $oldRoot = $script:RelayDataDirectory
    $link = Join-Path $outer 'junction'
    try {
        New-Item -ItemType Junction -Path $link -Target $script:RTCaseDirectory -ErrorAction Stop | Out-Null
        $script:RelayDataDirectory = $link
        Assert-Throws { Get-RelayCredentialConfig $p } 'reparse' | Out-Null
        $argsCopy = [string[]]$config.Args.Clone(); $argsCopy[5] = $link
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config $argsCopy)
        $script:RelayDataDirectory = $oldRoot
        # Same real helper invoked through a reparse ancestor must also fail.
        $argsCopy = [string[]]$config.Args.Clone(); $argsCopy[3] = Join-Path $link 'credentials\credential-helper.ps1'
        Assert-CredentialFailure (Invoke-CredentialTestHelper $config $argsCopy)
    } finally {
        $script:RelayDataDirectory = $oldRoot
        if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) }
        Remove-Item -LiteralPath $outer -Force -Recurse
    }
}
Add-RelayTest 'CredentialHelper' 'missing store root is never initialized and no parent process environment is changed' {
    $p = New-TestProvider; $beforeEnvironment = [Environment]::GetEnvironmentVariables('Process')
    $oldRoot = $script:RelayDataDirectory
    $absent = Join-Path $script:RTCaseDirectory 'absent-store'
    try {
        $script:RelayDataDirectory = $absent
        Assert-Throws { Install-RelayCredentialHelper $p } 'already exist' | Out-Null
        Assert-True (-not [IO.Directory]::Exists($absent))
    } finally { $script:RelayDataDirectory = $oldRoot }
    $config = Install-RelayCredentialHelper $p
    $null = Invoke-CredentialTestHelper $config
    $afterEnvironment = [Environment]::GetEnvironmentVariables('Process')
    Assert-Equal $afterEnvironment.Count $beforeEnvironment.Count
    foreach ($name in $beforeEnvironment.Keys) { Assert-Equal $afterEnvironment[$name] $beforeEnvironment[$name] }
    Assert-True (-not [IO.File]::Exists((Join-Path $script:RTCaseDirectory 'auth.json')))
}

function Invoke-CredentialOfficialAppServer {
    param([string]$Executable, [string]$Root, [hashtable]$Environment)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = '--no-daemon app-server --stdio'
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    if ($info.PSObject.Properties['StandardInputEncoding']) { $info.StandardInputEncoding = New-Object Text.UTF8Encoding($false) }
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8; $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $info.WorkingDirectory = $Root
    foreach ($name in $Environment.Keys) {
        if ($null -eq $Environment[$name]) { $info.EnvironmentVariables.Remove($name) }
        else { $info.EnvironmentVariables[$name] = $Environment[$name] }
    }
    $rpc = @(
        @{ id=1; method='initialize'; params=@{ clientInfo=@{ name='credential-fixture'; version='1' }; capabilities=@{ experimentalApi=$true } } }
        @{ method='initialized' }
        @{ id=2; method='config/read'; params=@{} }
        @{ id=3; method='model/list'; params=@{ includeHidden=$true } }
    )
    $process = New-Object Diagnostics.Process; $process.StartInfo = $info
    $responses = @{}; $lines = New-Object 'Collections.Generic.List[string]'
    try {
        [void]$process.Start()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine((ConvertTo-Json $rpc[0] -Depth 10 -Compress)); $process.StandardInput.Flush()
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            $read = $process.StandardOutput.ReadLineAsync()
            if (-not $read.Wait([int][Math]::Max(1, ($deadline-[DateTime]::UtcNow).TotalMilliseconds))) { break }
            $line = $read.GetAwaiter().GetResult()
            if ($null -eq $line) { break }
            $lines.Add($line)
            $message = $line | ConvertFrom-Json
            if ($message.PSObject.Properties['id']) {
                $responses[[string]$message.id] = $message
                if ($message.id -eq 1) {
                    foreach ($request in $rpc[1..3]) { $process.StandardInput.WriteLine((ConvertTo-Json $request -Depth 10 -Compress)) }
                    $process.StandardInput.Flush()
                }
                if ($responses.ContainsKey('2') -and $responses.ContainsKey('3')) { break }
            }
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(5000)) { $process.Kill(); [void]$process.WaitForExit(5000) }
        $diagnostic = $stderr.GetAwaiter().GetResult()
        Assert-True ($responses.ContainsKey('2') -and $responses.ContainsKey('3')) ('Official app-server fixture RPC incomplete: ' + $diagnostic)
        foreach ($id in @('2','3')) { Assert-True ($null -ne $responses[$id].PSObject.Properties['result']) ('Official fixture RPC failed: ' + ($lines -join "`n")) }
        return [pscustomobject]@{ Config=$responses['2'].result; Models=$responses['3'].result; Stdout=($lines -join "`n"); Stderr=$diagnostic }
    } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
}
function Invoke-CredentialOfficialCli {
    param([string]$Executable, $Provider, $Auth, [string]$Root)
    $environment = @{}
    foreach ($name in [Environment]::GetEnvironmentVariables('Process').Keys) {
        if ($name -match '(?i)OPENAI|CODEX|CHATGPT|TOKEN|API_KEY|AUTHORIZATION') { $environment[$name] = $null }
    }
    foreach ($name in @('CODEX_HOME', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TEMP', 'TMP')) {
        $directory = Join-Path $Root $name
        [void][IO.Directory]::CreateDirectory($directory)
        $environment[$name] = $directory
    }
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')) { $environment[$name] = 'http://127.0.0.1:9' }
    $environment['NO_PROXY'] = '127.0.0.1,localhost'; $environment['no_proxy'] = '127.0.0.1,localhost'
    $environment['OTEL_SDK_DISABLED'] = 'true'; $environment['DO_NOT_TRACK'] = '1'
    $version = Invoke-CredentialTestProcess $Executable @('--version') $Root 10000 $environment
    Assert-Equal $version.ExitCode 0
    Assert-Match $version.Stdout '\b0\.167\.1\b' 'Official test requires pinned Codex 0.167.1'
    # Publish actual manager products into an explicitly isolated fixture config.
    # No provider/catalog/auth --config overrides and no hand-written external-auth TOML.
    $catalog = Add-RelayCodexModels -Provider $Provider -Models @('model-a', 'model-b')
    $configPath = Join-Path $environment['CODEX_HOME'] 'config.toml'
    $plan = New-RelaySharedConfigPlan -Provider $Provider -Model 'model-a' -ConfigPath $configPath -CatalogPath $catalog.ModelsPath -AuthConfig $Auth
    Assert-True (-not [IO.File]::Exists($configPath)) 'Planning unexpectedly wrote config'
    $installed = Install-RelayCredentialHelper $Provider
    Assert-Equal $installed $Auth
    $transaction = Invoke-RelaySharedConfigPlan $plan
    Assert-Equal $transaction.Status 'Applied'
    Assert-Equal ([IO.File]::ReadAllText($configPath)) $plan.Content
    $rpc = Invoke-CredentialOfficialAppServer $Executable $Root $environment
    $result = Invoke-CredentialTestProcess $Executable @('--no-daemon', 'exec', '--skip-git-repo-check', '--sandbox', 'read-only', '--ephemeral', '--json', 'Reply with OK. Do not use tools.') $Root 45000 $environment
    $result | Add-Member NoteProperty Rpc $rpc
    return $result
}
if ($env:RELAY_TEST_CODEX_EXE) {
    Add-RelayTest 'CredentialHelper' 'official 0.167.1 isolated CLI parses external auth and sends real provider-specific Bearer to loopback' {
        $p = New-TestProvider -Fixture 'sse-completed-only'
        $other = New-TestProvider -Fixture 'sse-completed-only'
        foreach ($provider in @($p, $other)) {
            $auth = Install-RelayCredentialHelper $provider
            $root = Join-Path $script:RTCaseDirectory ('official-' + $provider.Id)
            [void][IO.Directory]::CreateDirectory($root)
            $result = Invoke-CredentialOfficialCli $env:RELAY_TEST_CODEX_EXE $provider $auth $root
            $key = Get-TestProviderKey $provider
            $matching = @(Get-MockRequests | Where-Object { $_.authorization -ceq ('Bearer ' + $key) -and $_.path -eq '/v1/responses' })
            Assert-True ($matching.Count -gt 0) ('Official CLI never sent fixture Bearer to loopback: ' + $result.Stderr + $result.Stdout)
            $body = $matching[0].body | ConvertFrom-Json
            Assert-Equal $body.model 'model-a'
            Assert-Equal $result.ExitCode 0 'Official exec must complete successfully using shared config only'
            Assert-Equal $result.Rpc.Config.config.model_provider $provider.Id
            Assert-Equal $result.Rpc.Config.config.model 'model-a'
            $models = @($result.Rpc.Models.data | ForEach-Object { $_.model })
            Assert-True ($models -ccontains 'model-a' -and $models -ccontains 'model-b') 'Official model/list did not load actual manager catalog'
            Assert-True (-not ($result.Stdout + $result.Stderr + $result.Rpc.Stdout + $result.Rpc.Stderr).Contains($key)) 'Official process output exposed fixture token'
            Write-Host ('OFFICIAL shared-config+catalog+external-auth verified: provider=' + $provider.Id + ' config/read=true model/list=true model=' + $body.model + ' exit=' + $result.ExitCode + ' loopbackBearer=true')
            Assert-NoSecretInStore $key
        }
        $requests = @(Get-MockRequests | Where-Object { $_.path -eq '/v1/responses' })
        Assert-True ($requests.Count -ge 2)
        Assert-True (-not [IO.File]::Exists((Join-Path $script:RTCaseDirectory 'auth.json')))
    }
}
