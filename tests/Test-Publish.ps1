# Integration of catalog + helper + shared configuration; fixture paths only.
Add-RelayTest 'Publish' 'Publishing and restoring protects referenced provider and leaves no plaintext key' {
    $p = New-TestProvider
    $paths = Get-RelayCatalogPaths $p
    $config = Join-Path $script:RTCaseDirectory 'isolated-home\config.toml'
    $auth = Get-RelayCredentialConfig $p
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'selected' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig $auth
    $record = Publish-RelayCodexModels -Provider $p -Models @('other', 'selected') -Plan $plan
    Assert-Equal $record.Status 'Applied'
    Assert-Equal @(Get-RelayCatalogModels $p) @('other', 'selected')
    Assert-True (Test-RelayProviderSharedReference $p)
    $providersBefore = [IO.File]::ReadAllText((Get-RelayProviderStorePath))
    Assert-Throws { Remove-RelayProvider $p } 'referenced' | Out-Null
    Assert-Throws { Clear-RelayCodexCatalog $p } 'referenced' | Out-Null
    $changed = $p | ConvertTo-Json | ConvertFrom-Json
    $changed.BaseUrl = 'https://different.invalid/v1'
    Assert-Throws { Save-RelayProvider $changed } 'referenced' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText((Get-RelayProviderStorePath))) $providersBefore
    Assert-NoSecretInStore (Get-TestProviderKey $p)
    Restore-RelaySharedConfig -TransactionId $record.TransactionId | Out-Null
    Assert-True (-not [IO.File]::Exists($config))
    Assert-Equal (Test-RelayProviderSharedReference $p) $false
    Remove-RelayProvider $p
    Assert-True (-not [IO.File]::Exists($paths.ModelsPath))
}

Add-RelayTest 'Publish' 'Concurrent config edit aborts publishing and restores prior catalog bytes' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('old')
    $oldModels = [IO.File]::ReadAllText($paths.ModelsPath)
    $oldToml = [IO.File]::ReadAllText($paths.ConfigPath)
    $config = Join-Path $script:RTCaseDirectory 'fixture-config.toml'
    [IO.File]::WriteAllText($config, '# initial')
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'new' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig (Get-RelayCredentialConfig $p)
    [IO.File]::WriteAllText($config, '# externally changed after preview')
    Assert-Throws { Publish-RelayCodexModels -Provider $p -Models @('new') -Plan $plan } 'fingerprint' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($config)) '# externally changed after preview'
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $oldModels
    Assert-Equal ([IO.File]::ReadAllText($paths.ConfigPath)) $oldToml
    Assert-NoSecretInStore (Get-TestProviderKey $p)
}

Add-RelayTest 'Publish' 'CLI uses fresh provider ID to avoid persistent auth and env_key conflict' {
    $p = New-TestProvider
    $paths = Get-RelayCatalogPaths $p
    $config = Join-Path $script:RTCaseDirectory 'fixture-config.toml'
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'one' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig (Get-RelayCredentialConfig $p)
    Publish-RelayCodexModels -Provider $p -Models @('one') -Plan $plan | Out-Null
    $output = Join-Path $script:RTCaseDirectory 'launch.json'
    $oldPath = [Environment]::GetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', 'Process')
    $oldName = [Environment]::GetEnvironmentVariable('RELAY_TEST_KEY_NAME', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $output, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', 'CODEX_RELAY_API_KEY', 'Process')
        Start-RelayCodex -Provider $p -Model 'one' -Executable (Get-TestRecorderExe)
        $record = Wait-TestRecorder $output
        Assert-Equal @($record.Arguments).Count 18
        Assert-Equal $record.Arguments[-1] 'model_reasoning_effort="medium"'
        $map = Get-TestConfigMap @($record.Arguments[0..13])
        Assert-Equal $record.Arguments[14] '--config'
        Assert-Equal ($record.Arguments[15] -split '=', 2)[0] 'model_catalog_json'
        $launchId = Get-TestTomlLiteralValue $map['model_provider']
        Assert-True ($launchId -cne $p.Id)
        Assert-Match $launchId '^relay_[a-f0-9]{32}$'
        Assert-Equal (Get-TestTomlLiteralValue $map[('model_providers.' + $launchId + '.env_key')]) 'CODEX_RELAY_API_KEY'
        Assert-Equal (Get-TestTomlLiteralValue ($record.Arguments[15] -split '=', 2)[1]) $paths.ModelsPath
        Assert-Equal $record.KeyValue (Get-TestProviderKey $p)
        Assert-Equal ([IO.File]::ReadAllText($config)) $plan.Content
    } finally {
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $oldPath, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', $oldName, 'Process')
        if ([IO.File]::Exists($output)) { [IO.File]::Delete($output) }
    }
}
