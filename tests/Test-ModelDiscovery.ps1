Add-RelayTest 'ModelDiscovery' 'Provider creation is offline and stores only an encrypted key' {
    $provider = New-TestProvider
    Assert-Equal @(Get-MockRequests).Count 0 'Provider creation must not request models'
    foreach ($field in @('Id', 'Name', 'BaseUrl', 'EncryptedApiKey')) { Assert-True (-not [string]::IsNullOrWhiteSpace([string]$provider.$field)) ('Missing provider field ' + $field) }
    Assert-Equal @(Get-RelayProviders).Count 1
    Assert-NoSecretInStore (Get-TestProviderKey $provider)
}
Add-RelayTest 'ModelDiscovery' 'Models are fetched with bearer authentication and cached as strings' {
    $provider = New-TestProvider
    $models = @(Get-RelayModels -Provider $provider -TimeoutSeconds 5)
    Assert-StringArray $models
    Assert-Equal @($models | Sort-Object) @('model-a', 'model-b')
    $requests = @(Get-MockRequests)
    Assert-Equal $requests.Count 1
    Assert-Equal $requests[0].method 'GET'
    Assert-Equal $requests[0].path '/v1/models'
    Assert-Equal $requests[0].authorization ('Bearer ' + (Get-TestProviderKey $provider))
    $cache = Get-RelayModelCache -Provider $provider
    Assert-True ($null -ne $cache) 'Successful discovery must persist a cache'
    Assert-True ($cache.Models -is [array]) 'Cached Models must be an array'
    Assert-Equal @($cache.Models | Sort-Object) @('model-a', 'model-b')
    Initialize-RelayStore -Path $script:RTCaseDirectory | Out-Null
    Assert-Equal @((Get-RelayModelCache -Provider $provider).Models | Sort-Object) @('model-a', 'model-b') 'Cache must survive store reload'
    Assert-NoSecretInStore (Get-TestProviderKey $provider)
}
Add-RelayTest 'ModelDiscovery' 'Duplicate model IDs are deduplicated' {
    $provider = New-TestProvider -Fixture 'models-duplicates'
    Assert-Equal @(Get-RelayModels -Provider $provider | Sort-Object) @('model-a', 'model-b')
}
Add-RelayTest 'ModelDiscovery' 'Empty model discovery is readable, preserves provider and never invents models' {
    $provider = New-TestProvider -Fixture 'models-empty'
    $models = @()
    try { $models = @(Get-RelayModels -Provider $provider) } catch {
        Assert-Match ([string]$_) '(?i)empty|no.?models|model|空|模型' 'Empty-list failure must be readable'
    }
    Assert-Equal $models.Count 0
    Assert-Equal @(Get-RelayProviders).Count 1 'Empty models must not roll back provider creation'
    $cache = Get-RelayModelCache -Provider $provider
    if ($null -ne $cache) { Assert-Equal @($cache.Models).Count 0 }
}
Add-RelayTest 'ModelDiscovery' 'Caches are isolated by provider and refreshed on successful fetch' {
    $a = New-TestProvider -Name 'A'
    $b = New-TestProvider -Name 'B' -Fixture 'models-b'
    Get-RelayModels -Provider $a | Out-Null
    Get-RelayModels -Provider $b | Out-Null
    Assert-Equal @((Get-RelayModelCache -Provider $a).Models | Sort-Object) @('model-a', 'model-b')
    Assert-Equal @((Get-RelayModelCache -Provider $b).Models) @('provider-b-only')
    Set-MockFixture (Get-TestProviderKey $a) 'models-refreshed'
    Assert-Equal @(Get-RelayModels -Provider $a) @('model-new')
    Assert-Equal @((Get-RelayModelCache -Provider $a).Models) @('model-new')
    Assert-Equal @((Get-RelayModelCache -Provider $b).Models) @('provider-b-only')
}
Add-RelayTest 'ModelDiscovery' 'Cache lookup performs no network I/O and does not expose another store' {
    $provider = New-TestProvider
    Get-RelayModels -Provider $provider | Out-Null
    $before = @(Get-MockRequests).Count
    Get-RelayModelCache -Provider $provider | Out-Null
    Assert-Equal @(Get-MockRequests).Count $before
    $other = New-RelayTestDirectory
    try {
        Initialize-RelayStore -Path $other | Out-Null
        $cache = Get-RelayModelCache -Provider $provider
        Assert-True ($null -eq $cache -or @($cache.Models).Count -eq 0) 'A different data directory must not inherit cached models'
    } finally { Initialize-RelayStore -Path $script:RTCaseDirectory | Out-Null; Remove-Item -LiteralPath $other -Recurse -Force }
}
Add-RelayTest 'ModelDiscovery' 'Failed refresh preserves the previous cache byte-for-byte logically' {
    $provider = New-TestProvider
    Get-RelayModels -Provider $provider | Out-Null
    $before = Get-RelayModelCache -Provider $provider | ConvertTo-Json -Depth 30 -Compress
    foreach ($fixture in @('http-401', 'http-403', 'http-404', 'http-429', 'http-500', 'nonjson', 'empty', 'models-invalid', 'timeout')) {
        Set-MockFixture (Get-TestProviderKey $provider) $fixture
        Assert-Throws { Get-RelayModels -Provider $provider -TimeoutSeconds 1 } | Out-Null
        Assert-Equal (Get-RelayModelCache -Provider $provider | ConvertTo-Json -Depth 30 -Compress) $before ('Failed refresh overwrote cache: ' + $fixture)
    }
}
Add-RelayTest 'ModelDiscovery' 'HTTP model failures throw readable classified errors without secrets' {
    $provider = New-TestProvider
    $key = Get-TestProviderKey $provider
    foreach ($status in @(401, 403, 404, 429, 500)) {
        Set-MockFixture $key ('http-' + $status)
        $errorRecord = Assert-Throws { Get-RelayModels -Provider $provider -TimeoutSeconds 2 } ([string]$status)
        Assert-True (-not ([string]$errorRecord).Contains($key)) 'Model error exposed bearer secret'
    }
}
Add-RelayTest 'ModelDiscovery' 'Empty, non-JSON and invalid model payloads fail readably' {
    $provider = New-TestProvider
    foreach ($fixture in @('empty', 'nonjson', 'models-invalid', 'models-blank', 'models-nonstring')) {
        Set-MockFixture (Get-TestProviderKey $provider) $fixture
        Assert-Throws { Get-RelayModels -Provider $provider -TimeoutSeconds 2 } '(?i)json|empty|invalid|format|data|model|空|格式|模型|解析|响应' | Out-Null
    }
}
Add-RelayTest 'ModelDiscovery' 'Model timeout is bounded and identified' {
    $provider = New-TestProvider -Fixture 'timeout'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    Assert-Throws { Get-RelayModels -Provider $provider -TimeoutSeconds 1 } '(?i)time.?out|timed out|超时|取消|cancel' | Out-Null
    Assert-True ($clock.Elapsed.TotalSeconds -lt 8) 'Timeout did not bound model request duration'
}
Add-RelayTest 'ModelDiscovery' 'Path-selected fixture works with a custom preserved API root' {
    $url = Normalize-RelayBaseUrl -Url ($script:RTBaseUrl + '/fixture/models-b/v1') -CustomPathMode Preserve
    $provider = New-RelayProvider -Name 'Path fixture' -BaseUrl $url -ApiKey ('opaque-' + [guid]::NewGuid().ToString('N'))
    Assert-Equal @(Get-RelayModels -Provider $provider) @('provider-b-only')
}
