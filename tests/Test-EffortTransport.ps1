Add-RelayTest 'EffortTransport' 'Responses effort uses nested reasoning object and separate cached evidence' {
    $p = New-TestProvider -Fixture 'sse-valid'
    $baseline = Test-RelayResponse -Provider $p -Model 'model-a'
    Assert-Equal $baseline.Status 'COMPATIBLE'
    $compatPath = Get-RelayCachePath $p compatibility
    $before = [IO.File]::ReadAllText($compatPath)
    $result = Test-RelayResponse -Provider $p -Model 'model-a' -ReasoningEffort high
    Assert-Equal $result.Status 'COMPATIBLE'
    Assert-Equal $result.ReasoningEffort 'high'
    Assert-Equal $result.Evidence 'REQUEST_ACCEPTANCE_ONLY'
    Assert-Equal ([IO.File]::ReadAllText($compatPath)) $before
    $requests = @(Get-MockRequests | Where-Object { $_.path -eq '/v1/responses' })
    Assert-Equal $requests.Count 2
    $body = $requests[1].body | ConvertFrom-Json
    Assert-Equal $body.reasoning.effort 'high'
    Assert-True (-not $body.PSObject.Properties['effort'])
    $records = @(Read-RelayJson (Get-RelayCachePath $p effort))
    Assert-Equal $records.Count 1
    Assert-Equal $records[0].ReasoningEffort 'high'
    Test-RelayResponse -Provider $p -Model 'model-a' -ReasoningEffort high | Out-Null
    Assert-Equal @(Read-RelayJson (Get-RelayCachePath $p effort)).Count 1
    Clear-RelayProviderCache $p
    Assert-True (-not [IO.File]::Exists((Get-RelayCachePath $p effort)))
}

Add-RelayTest 'EffortTransport' 'Invalid effort fails before any HTTP or cache write' {
    $p = New-TestProvider
    Assert-Throws { Test-RelayResponse -Provider $p -Model 'one' -ReasoningEffort 'injected-value' } | Out-Null
    Assert-Equal @(Get-MockRequests).Count 0
    Assert-True (-not [IO.File]::Exists((Get-RelayCachePath $p effort)))
}

Add-RelayTest 'EffortTransport' 'Shared plan merges desktop levels and keeps unrelated desktop options and metadata unchanged with no setting' {
    $p = New-TestProvider
    $paths = Get-RelayCatalogPaths $p
    $config = Join-Path $script:RTCaseDirectory 'effort-fixture.toml'
    $text = "model_reasoning_effort = 'high' # keep suffix`n[desktop]`nenabled-reasoning-efforts = ['medium'] # options`nother = 'preserve'`n[mcp_servers.existing]`ncommand = 'node'`n"
    [IO.File]::WriteAllText($config, $text)
    $auth = Get-RelayCredentialConfig $p
    $unchanged = New-RelaySharedConfigPlan -Provider $p -Model 'model-a' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig $auth
    Assert-True ($unchanged.Content.Contains("model_reasoning_effort = 'high' # keep suffix"))
    Assert-True ($unchanged.Content.Contains("enabled-reasoning-efforts = ['medium'] # options"))
    $settings = @([pscustomobject]@{ Model = 'model-a'; SupportedLevels = @('low', 'high'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' })
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'model-a' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig $auth -EffortSettings $settings
    Assert-True ($plan.Content.Contains('model_reasoning_effort = "low" # keep suffix'))
    Assert-Match $plan.Content '(?m)^enabled-reasoning-efforts = \["high", "low", "medium"\] # options$'
    Assert-True ($plan.Content.Contains("other = 'preserve'"))
    Assert-True ($plan.Content.Contains("[mcp_servers.existing]`ncommand = 'node'"))
    Assert-Equal ([IO.File]::ReadAllText($config)) $text
}

Add-RelayTest 'EffortTransport' 'Shared plan adds exactly one desktop table and validates default effort' {
    $p = New-TestProvider
    $path = Join-Path $script:RTCaseDirectory 'absent.toml'
    $catalog = Get-RelayCatalogPaths $p
    $auth = Get-RelayCredentialConfig $p
    $settings = @([pscustomobject]@{ Model = 'model-a'; SupportedLevels = @('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' })
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'model-a' -ConfigPath $path -CatalogPath $catalog.ModelsPath -AuthConfig $auth -EffortSettings $settings
    Assert-Equal ([regex]::Matches($plan.Content, '(?m)^\[desktop\]$')).Count 1
    Assert-Match $plan.Content '(?m)^enabled-reasoning-efforts = \["low"\]$'
    $settings[0].DefaultLevel = 'high'
    Assert-Throws { New-RelaySharedConfigPlan -Provider $p -Model 'model-a' -ConfigPath $path -CatalogPath $catalog.ModelsPath -AuthConfig $auth -EffortSettings $settings } 'Default effort' | Out-Null
}
