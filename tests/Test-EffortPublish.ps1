Add-RelayTest 'EffortPublish' 'Publish commits API-accepted model metadata, shared default and desktop choices together' {
    $p = New-TestProvider
    $paths = Get-RelayCatalogPaths $p
    $config = Join-Path $script:RTCaseDirectory 'fixture-config.toml'
    $settings = @([pscustomobject]@{ Model = 'model-a'; SupportedLevels = @('low', 'high'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' })
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'model-a' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig (Get-RelayCredentialConfig $p) -EffortSettings $settings
    Publish-RelayCodexModels -Provider $p -Models @('model-a', 'model-b') -Plan $plan -EffortSettings $settings | Out-Null
    $catalog = Read-RelayJson $paths.ModelsPath
    Assert-Equal $catalog.models[0].default_reasoning_level 'low'
    Assert-Equal @($catalog.models[0].supported_reasoning_levels | ForEach-Object { $_.effort }) @('low', 'high')
    Assert-Equal $catalog.models[1].supported_reasoning_levels (New-RelayCatalogModel 'model-b').supported_reasoning_levels
    Assert-True ([IO.File]::ReadAllText($config).Contains('model_reasoning_effort = "low"'))
    $output = Join-Path $script:RTCaseDirectory 'record.json'
    $oldPath = [Environment]::GetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', 'Process')
    $oldName = [Environment]::GetEnvironmentVariable('RELAY_TEST_KEY_NAME', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $output, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', 'CODEX_RELAY_API_KEY', 'Process')
        Start-RelayCodex -Provider $p -Model 'model-a' -Executable (Get-TestRecorderExe)
        $record = Wait-TestRecorder $output
        Assert-Equal $record.Arguments.Count 18
        Assert-Equal $record.Arguments[-1] 'model_reasoning_effort="low"'
    } finally {
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $oldPath, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', $oldName, 'Process')
        if ([IO.File]::Exists($output)) { [IO.File]::Delete($output) }
    }
}

Add-RelayTest 'EffortPublish' 'Rejected shared commit restores metadata from before the effort update' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('model-a')
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    $config = Join-Path $script:RTCaseDirectory 'fixture-config.toml'
    [IO.File]::WriteAllText($config, '# initial')
    $settings = @([pscustomobject]@{ Model = 'model-a'; SupportedLevels = @('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' })
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'model-a' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig (Get-RelayCredentialConfig $p) -EffortSettings $settings
    [IO.File]::WriteAllText($config, '# external edit')
    Assert-Throws { Publish-RelayCodexModels -Provider $p -Models @('model-a') -Plan $plan -EffortSettings $settings } 'fingerprint' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    Assert-Equal ([IO.File]::ReadAllText($config)) '# external edit'
}
