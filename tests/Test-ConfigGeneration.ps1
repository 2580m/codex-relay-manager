Add-RelayTest 'ConfigGeneration' 'TOML basic strings round-trip quotes, slashes, Unicode and control characters' {
    $values = @('', 'plain', '中文 ✓', 'a"b', 'C:\path\ending\', "line1`nline2`r`n`tindent", ('back' + [char]8 + 'form' + [char]12), ('nul' + [char]0 + 'end'), ('del' + [char]127), '"; model = "injected" #')
    foreach ($value in $values) {
        $literal = ConvertTo-TomlString -Value $value
        Assert-True ($literal -is [string]) 'TOML literal must be a single string'
        Assert-Equal (Get-TestTomlLiteralValue $literal) $value 'TOML escaping did not round-trip'
    }
}
Add-RelayTest 'ConfigGeneration' 'Seven config pairs select Responses and disable OpenAI authentication' {
    $provider = New-TestProvider -Name 'Untrusted "name"; 中文'
    $model = 'model "quoted" \ path'
    $arguments = Get-RelayCodexArguments -Provider $provider -Model $model
    $map = Get-TestConfigMap $arguments
    Assert-True ($map.ContainsKey('model') -and $map.ContainsKey('model_provider')) 'Missing model/model_provider assignment'
    Assert-Equal (Get-TestTomlLiteralValue $map['model']) $model
    $providerId = Get-TestTomlLiteralValue $map['model_provider']
    Assert-Match $providerId '^[A-Za-z0-9_-]+$' 'Config provider identifier must be a safe bare TOML key segment'
    $prefix = 'model_providers.' + $providerId + '.'
    foreach ($key in @('name', 'base_url', 'env_key', 'wire_api', 'requires_openai_auth')) { Assert-True ($map.ContainsKey($prefix + $key)) ('Missing config key ' + $key) }
    Assert-Equal (Get-TestTomlLiteralValue $map[$prefix + 'name']) $provider.Name
    Assert-Equal (Get-TestTomlLiteralValue $map[$prefix + 'base_url']) $provider.BaseUrl
    Assert-Equal (Get-TestTomlLiteralValue $map[$prefix + 'wire_api']) 'responses'
    Assert-Equal $map[$prefix + 'requires_openai_auth'] 'false' 'TOML boolean must not be the quoted string "false"'
    Assert-Match (Get-TestTomlLiteralValue $map[$prefix + 'env_key']) '^[A-Za-z_][A-Za-z0-9_]*$' 'Invalid environment key name'
    Assert-True (-not (($arguments -join "`n").Contains((Get-TestProviderKey $provider)))) 'CLI arguments expose the plaintext key'
    Assert-True (-not (($arguments -join "`n").Contains($provider.EncryptedApiKey))) 'CLI arguments must reference env_key, not ciphertext'
    Assert-Equal @(Get-MockRequests).Count 0 'Config generation must be offline'
}
Add-RelayTest 'ConfigGeneration' 'Win32 escaping round-trips exact argv through a real recorder executable' {
    $values = @('', 'plain', 'two words', '中文 ✓', 'a"b', '"', '\', 'C:\two words\', 'tail\\', '\\"quoted\\"', "tab`there", "new`nline", '& | < > ^ % ! $ ; ` ( )', '--config', 'key="C:\quoted path\"')
    $output = Join-Path $script:RTCaseDirectory 'escaped-argv.json'
    $record = Invoke-TestRecorder -Arguments $values -OutputPath $output
    Assert-Equal @($record.Arguments) $values 'Native argv differs after ConvertTo-WindowsArgument'
}
Add-RelayTest 'ConfigGeneration' 'Start launches only the recorder with exact argv and child-only API key' {
    $provider = New-TestProvider -Name 'Native launch 中文'
    $model = 'model "quoted" C:\space path\'
    $expectedArguments = Get-RelayCodexArguments -Provider $provider -Model $model
    $map = Get-TestConfigMap $expectedArguments
    $providerId = Get-TestTomlLiteralValue $map['model_provider']
    $keyName = Get-TestTomlLiteralValue $map['model_providers.' + $providerId + '.env_key']
    $output = Join-Path $script:RTCaseDirectory 'launch-record.json'
    $names = @('RELAY_TEST_RECORDER_PATH', 'RELAY_TEST_KEY_NAME', $keyName, 'OPENAI_API_KEY') | Select-Object -Unique
    $old = @{}
    foreach ($name in $names) { $old[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    try {
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $output, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', $keyName, 'Process')
        [Environment]::SetEnvironmentVariable('OPENAI_API_KEY', 'parent-openai-must-survive', 'Process')
        [Environment]::SetEnvironmentVariable($keyName, 'parent-selected-must-survive', 'Process')
        $before = @{}
        foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) { $before[[string]$entry.Key] = [string]$entry.Value }
        Start-RelayCodex -Provider $provider -Model $model -Executable (Get-TestRecorderExe) | Out-Null
        $record = Wait-TestRecorder -Path $output
        Assert-Equal @($record.Arguments) @($expectedArguments) 'Start-RelayCodex altered CLI argument boundaries'
        Assert-Equal $record.KeyValue (Get-TestProviderKey $provider) 'Child did not receive the provider API key in configured env_key'
        $after = [Environment]::GetEnvironmentVariables('Process')
        Assert-Equal $after.Count $before.Count 'Launch added or removed parent process environment variables'
        foreach ($name in $before.Keys) { Assert-Equal ([string]$after[$name]) $before[$name] ('Parent environment changed: ' + $name) }
        Assert-True (-not (($record.Arguments -join "`n").Contains((Get-TestProviderKey $provider)))) 'Child argv leaks the API key'
        Assert-Equal @(Get-MockRequests).Count 0 'Native launch unexpectedly contacted HTTP'
    } finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $old[$name], 'Process') }
    }
    # Recorder JSON intentionally contains the child key; remove it before checking application storage.
    Remove-Item -LiteralPath $output -Force
    Assert-NoSecretInStore (Get-TestProviderKey $provider)
}
Add-RelayTest 'ConfigGeneration' 'Native launch injects an absent key only into the child' {
    $provider = New-TestProvider
    $map = Get-TestConfigMap (Get-RelayCodexArguments -Provider $provider -Model 'model-a')
    $providerId = Get-TestTomlLiteralValue $map['model_provider']
    $keyName = Get-TestTomlLiteralValue $map['model_providers.' + $providerId + '.env_key']
    $oldKey = [Environment]::GetEnvironmentVariable($keyName, 'Process')
    $oldPath = [Environment]::GetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', 'Process')
    $oldName = [Environment]::GetEnvironmentVariable('RELAY_TEST_KEY_NAME', 'Process')
    $output = Join-Path $script:RTCaseDirectory 'absent-key.json'
    try {
        [Environment]::SetEnvironmentVariable($keyName, $null, 'Process')
        $absentBefore = [Environment]::GetEnvironmentVariable($keyName, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $output, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', $keyName, 'Process')
        Start-RelayCodex -Provider $provider -Model 'model-a' -Executable (Get-TestRecorderExe) | Out-Null
        Assert-Equal (Wait-TestRecorder -Path $output).KeyValue (Get-TestProviderKey $provider)
        Assert-Equal ([Environment]::GetEnvironmentVariable($keyName, 'Process')) $absentBefore 'An initially absent key leaked into the parent environment'
    } finally {
        [Environment]::SetEnvironmentVariable($keyName, $oldKey, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $oldPath, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', $oldName, 'Process')
    }
}
Add-RelayTest 'ConfigGeneration' 'Missing executable fails without changing parent key' {
    $provider = New-TestProvider
    $map = Get-TestConfigMap (Get-RelayCodexArguments -Provider $provider -Model 'model-a')
    $providerId = Get-TestTomlLiteralValue $map['model_provider']
    $keyName = Get-TestTomlLiteralValue $map['model_providers.' + $providerId + '.env_key']
    $old = [Environment]::GetEnvironmentVariable($keyName, 'Process')
    Assert-Throws { Start-RelayCodex -Provider $provider -Model 'model-a' -Executable (Join-Path $script:RTCaseDirectory 'does-not-exist.exe') } | Out-Null
    Assert-Equal ([Environment]::GetEnvironmentVariable($keyName, 'Process')) $old
}
