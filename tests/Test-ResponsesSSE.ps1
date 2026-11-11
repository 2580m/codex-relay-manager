Add-RelayTest 'ResponsesSSE' 'Chunked UTF-8 SSE with delta and completed is compatible' {
    $provider = New-TestProvider -Fixture 'sse-valid'
    $result = Test-RelayResponse -Provider $provider -Model 'model-a' -TimeoutSeconds 8
    Assert-Compatible $result
    $events = $result.Events -join "`n"
    Assert-Match $events 'response\.output_text\.delta' 'Delta event was not observed across chunk boundaries'
    Assert-Match $events 'response\.completed' 'Completed event was not observed'
    $requests = @(Get-MockRequests)
    Assert-Equal $requests.Count 1 'A Responses probe must not fetch models or retry implicitly'
    Assert-Equal $requests[0].method 'POST'
    Assert-Equal $requests[0].path '/v1/responses'
    Assert-Equal $requests[0].authorization ('Bearer ' + (Get-TestProviderKey $provider))
    $body = $requests[0].body | ConvertFrom-Json
    Assert-Equal $body.model 'model-a'
    Assert-Equal $body.stream $true
    Assert-True ($null -ne $body.PSObject.Properties['input']) 'Responses request needs input'
    Assert-NoSecretInStore (Get-TestProviderKey $provider)
}
Add-RelayTest 'ResponsesSSE' 'Lifecycle plus completed without output is not a successful minimal text probe' {
    $provider = New-TestProvider -Fixture 'sse-lifecycle'
    $result = Test-RelayResponse -Provider $provider -Model 'model-a' -TimeoutSeconds 8
    Assert-Incompatible $result
    Assert-Match ($result.Events -join "`n") 'response\.(created|in_progress)'
    Assert-Match ($result.Events -join "`n") 'response\.completed'
}
Add-RelayTest 'ResponsesSSE' 'Delta without completed and completed without lifecycle are not compatible' {
    $provider = New-TestProvider
    foreach ($fixture in @('sse-delta-only', 'sse-completed-only', 'sse-no-lifecycle', 'sse-incomplete-status', 'sse-done-only', 'sse-empty')) {
        Set-MockFixture (Get-TestProviderKey $provider) $fixture
        Assert-Incompatible (Test-RelayResponse -Provider $provider -Model $fixture -TimeoutSeconds 8) '(?i)sse|stream|event|incomplete|empty|complet|delta|life.?cycle|流|事件|完成|空|兼容'
    }
}
Add-RelayTest 'ResponsesSSE' 'HTTP 200 JSON/HTML/empty must never be treated as SSE compatibility' {
    $provider = New-TestProvider
    foreach ($fixture in @('json-response', 'nonjson', 'empty')) {
        Set-MockFixture (Get-TestProviderKey $provider) $fixture
        Assert-Incompatible (Test-RelayResponse -Provider $provider -Model $fixture -TimeoutSeconds 3) '(?i)sse|stream|content.?type|event|empty|json|流|事件|类型|空|兼容|响应'
    }
}
Add-RelayTest 'ResponsesSSE' 'SSE error and response.failed have failure priority over completion' {
    $provider = New-TestProvider
    foreach ($fixture in @('sse-error', 'sse-failed', 'sse-error-then-completed')) {
        Set-MockFixture (Get-TestProviderKey $provider) $fixture
        $result = Test-RelayResponse -Provider $provider -Model $fixture -TimeoutSeconds 8
        Assert-Incompatible $result '(?i)error|fail|错误|失败'
        Assert-Match ($result.Events -join "`n") 'error|response\.failed'
    }
}
Add-RelayTest 'ResponsesSSE' 'Malformed SSE JSON cannot count as valid lifecycle evidence' {
    $provider = New-TestProvider -Fixture 'sse-malformed'
    Assert-Incompatible (Test-RelayResponse -Provider $provider -Model 'model-a' -TimeoutSeconds 8) '(?i)json|invalid|parse|sse|event|stream|格式|解析|流|事件|兼容'
}
Add-RelayTest 'ResponsesSSE' 'Responses HTTP failures return classifications instead of throwing' {
    $provider = New-TestProvider
    $key = Get-TestProviderKey $provider
    $classes = @{}
    foreach ($status in @(401, 403, 404, 429, 500)) {
        Set-MockFixture $key ('http-' + $status)
        $result = Test-RelayResponse -Provider $provider -Model ('http-' + $status) -TimeoutSeconds 3
        Assert-Incompatible $result ([string]$status)
        Assert-True (-not (($result | ConvertTo-Json -Depth 20).Contains($key))) 'Probe result exposed bearer secret'
        $classes[[string]$status] = [string]$result.Status
        switch ($status) {
            401 { Assert-Match ($result.Status + ' ' + $result.Message) '(?i)401|auth|unauthorized|密钥|认证' }
            403 { Assert-Match ($result.Status + ' ' + $result.Message) '(?i)403|forbidden|permission|权限|禁止' }
            404 { Assert-Match ($result.Status + ' ' + $result.Message) '(?i)404|not.?found|unsupported|不存在|不支持|未找到' }
            429 { Assert-Match ($result.Status + ' ' + $result.Message) '(?i)429|rate.?limit|quota|限流|限额|频率' }
            500 { Assert-Match ($result.Status + ' ' + $result.Message) '(?i)500|server|upstream|服务|上游' }
        }
    }
    # Numeric codes in Message are sufficient classification; Status enum names were not specified.
}
Add-RelayTest 'ResponsesSSE' 'Timeout applies after headers and initial SSE event, not only before headers' {
    $provider = New-TestProvider -Fixture 'sse-delayed'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $result = Test-RelayResponse -Provider $provider -Model 'slow-stream' -TimeoutSeconds 1
    Assert-Incompatible $result '(?i)time.?out|timed out|超时|cancel|取消'
    Assert-True ($clock.Elapsed.TotalSeconds -lt 8) 'Delayed streaming response ignored TimeoutSeconds'
}
Add-RelayTest 'ResponsesSSE' 'Pre-header timeout returns a timeout classification' {
    $provider = New-TestProvider -Fixture 'timeout'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    Assert-Incompatible (Test-RelayResponse -Provider $provider -Model 'slow-headers' -TimeoutSeconds 1) '(?i)time.?out|timed out|超时|cancel|取消'
    Assert-True ($clock.Elapsed.TotalSeconds -lt 8) 'Header timeout exceeded its bound'
}
Add-RelayTest 'ResponsesSSE' 'Compatibility records persist and remain isolated by provider' {
    $a = New-TestProvider -Fixture 'sse-valid' -Name 'A'
    $b = New-TestProvider -Fixture 'sse-failed' -Name 'B'
    Assert-Compatible (Test-RelayResponse -Provider $a -Model 'a-model' -TimeoutSeconds 8)
    Assert-Incompatible (Test-RelayResponse -Provider $b -Model 'b-model' -TimeoutSeconds 8)
    $aRecords = @(Get-RelayCompatibility -Provider $a)
    $bRecords = @(Get-RelayCompatibility -Provider $b)
    Assert-True ($aRecords.Count -gt 0 -and $bRecords.Count -gt 0) 'Each probe must save a compatibility record'
    $aJson = ConvertTo-Json -InputObject $aRecords -Depth 30 -Compress
    $bJson = ConvertTo-Json -InputObject $bRecords -Depth 30 -Compress
    Assert-Match $aJson 'a-model'
    Assert-Match $bJson 'b-model'
    Assert-True (-not $aJson.Contains('b-model')) 'Provider A contains provider B compatibility results'
    Assert-True (-not $bJson.Contains('a-model')) 'Provider B contains provider A compatibility results'
    Initialize-RelayStore -Path $script:RTCaseDirectory | Out-Null
    Assert-Equal (ConvertTo-Json -InputObject @(Get-RelayCompatibility -Provider $a) -Depth 30 -Compress) $aJson
    Assert-NoSecretInStore (Get-TestProviderKey $a)
    Assert-NoSecretInStore (Get-TestProviderKey $b)
}
Add-RelayTest 'ResponsesSSE' 'Empty compatibility history is returned without contacting the network' {
    $provider = New-TestProvider
    Assert-Equal @(Get-RelayCompatibility -Provider $provider).Count 0
    Assert-Equal @(Get-MockRequests).Count 0
}
