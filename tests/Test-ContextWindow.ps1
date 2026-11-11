# 上下文窗口管理（手动分模型原始数字 & 自动统一请求）合约测试

function Invoke-ContextUiMock {
    param(
        [Parameter(Mandatory)][scriptblock]$Body,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Answers,
        [scriptblock]$OnReadHost = $null
    )
    $queue = New-Object Collections.Queue
    foreach ($answer in $Answers) { $queue.Enqueue([string]$answer) }
    $prompts = New-Object Collections.ArrayList
    $output = New-Object Collections.ArrayList
    $state = [pscustomobject]@{
        Queue      = $queue
        Prompts    = $prompts
        Output     = $output
        OnReadHost = $OnReadHost
    }
    $mocks = @{
        'Read-Host' = {
            param([string]$Prompt = '')
            $st = $script:RTContextUiState
            if ($null -ne $st.OnReadHost) {
                & $st.OnReadHost $Prompt $st
            }
            if ($st.Queue.Count -eq 0) { throw ('Test UI ran out of scripted answers at prompt: ' + $Prompt) }
            $ans = [string]$st.Queue.Dequeue()
            [void]$st.Prompts.Add([pscustomobject]@{ Text = $Prompt; Answer = $ans })
            return $ans
        }
        'Write-Host' = {
            param([object]$Object = '', [ConsoleColor]$ForegroundColor = [ConsoleColor]::Gray, [switch]$NoNewline)
            [void]$script:RTContextUiState.Output.Add([pscustomobject]@{ Text = [string]$Object; Color = $ForegroundColor.ToString() })
        }
        'Write-RelaySafe' = {
            param([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray)
            [void]$script:RTContextUiState.Output.Add([pscustomobject]@{ Text = [string]$Text; Color = $Color.ToString() })
        }
    }
    $savedFunctions = @{}
    $installed = New-Object Collections.ArrayList
    $savedVar = Get-Variable -Name 'RTContextUiState' -Scope Script -ErrorAction SilentlyContinue
    try {
        $script:RTContextUiState = $state
        foreach ($name in $mocks.Keys) {
            $original = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
            $savedFunctions[$name] = $null
            if ($null -ne $original) { $savedFunctions[$name] = $original.ScriptBlock }
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $mocks[$name]
            [void]$installed.Add($name)
        }
        $result = @(& $Body)
        Assert-Equal $state.Queue.Count 0 ('UI returned with unconsumed scripted answers: ' + $state.Queue.Count)
        return [pscustomobject]@{
            Result  = @($result)
            Prompts = @($state.Prompts.ToArray())
            Output  = @($state.Output.ToArray())
        }
    } finally {
        foreach ($name in $installed) {
            if ($null -ne $savedFunctions[$name]) {
                Set-Item -LiteralPath ('Function:script:' + $name) -Value $savedFunctions[$name]
            } else {
                Remove-Item -LiteralPath ('Function:' + $name) -Force
            }
        }
        if ($null -ne $savedVar) {
            Set-Variable -Name 'RTContextUiState' -Scope Script -Value $savedVar.Value
        } else {
            Remove-Variable -Name 'RTContextUiState' -Scope Script -ErrorAction SilentlyContinue
        }
    }
}

Add-RelayTest 'ContextWindow' '原始整数校验严禁 K/M 单位、逗号、小数、布尔与非正数' {
    Assert-Equal (ConvertTo-RelayContextWindowValue '1000000') ([int64]1000000)
    Assert-Equal (ConvertTo-RelayContextWindowValue '  272000  ') ([int64]272000)
    Assert-Equal (ConvertTo-RelayContextWindowValue 200000) ([int64]200000)
    Assert-Equal (ConvertTo-RelayContextWindowValue ([int64]2000000)) ([int64]2000000)

    foreach ($bad in @('256K', '1M', '128k', '2m', '1000KB', '1048K', '1,000,000', '1000_000', '272000.0', '0', '-100', '', '   ', $null, $true, 0, -1, 1000000.5)) {
        [void](Assert-Throws { ConvertTo-RelayContextWindowValue $bad } '原始|正整数|单位|不能为空|不支持|大于 0')
    }

    foreach ($badEff in @('95%', '0', '101', '-5', '95.5', '1K', '')) {
        [void](Assert-Throws { ConvertTo-RelayEffectivePercentValue $badEff } '有效上下文比例')
    }
    Assert-Equal (ConvertTo-RelayEffectivePercentValue '95') 95
    Assert-Equal (ConvertTo-RelayEffectivePercentValue 100) 100

    [void](Assert-Throws { New-RelayContextSetting -Model 'm1' -ContextWindow 1000000 -MaxContextWindow 500000 } 'max_context_window 不能小于')
    [void](Assert-Throws { New-RelayContextSetting -Model 'm1' -ContextWindow 500000 -AutoCompactTokenLimit 600000 } 'auto_compact_token_limit 不能大于')
    [void](Assert-Throws { New-RelayContextSetting -Model 'm1' -ContextWindow '1M' } '单位')
    [void](Assert-Throws { New-RelayContextSetting -Model '   ' -ContextWindow 1000000 } '模型 ID')

    $ok = New-RelayContextSetting -Model 'm1' -ContextWindow 1000000 -MaxContextWindow 1048576 -EffectiveContextWindowPercent 90 -AutoCompactTokenLimit $null -Source 'MANUAL' -Evidence 'test'
    Assert-Equal $ok.Model 'm1'
    Assert-Equal $ok.ContextWindow ([int64]1000000)
    Assert-Equal $ok.MaxContextWindow ([int64]1048576)
    Assert-Equal $ok.EffectiveContextWindowPercent 90
    Assert-True ($null -eq $ok.AutoCompactTokenLimit)
}

Add-RelayTest 'ContextWindow' '手动分模型界面拒绝单位后缀并支持逐模型独立配置与取消' {
    $provider = New-TestProvider
    $paths = Add-RelayCodexModels $provider @('model-a', 'model-b', 'model-c')
    $beforeBytes = [IO.File]::ReadAllBytes($paths.ModelsPath)

    # 选择 [1] 手动分模型：
    # model-a: 先输 '256K'(拒绝), 再输 '1,000,000'(拒绝), 再输 '1000000', effective '95%'(拒绝) -> '90', auto_compact '1000001'(拒绝) -> '850000'
    # model-b: 直接回车跳过
    # model-c: '500000', 回车默认95, 'CLEAR' -> null
    $session = Invoke-ContextUiMock -Answers @(
        '1',
        '256K', '1,000,000', '1000000', '95%', '90', '1000001', '850000',
        '',
        '500000', '', 'CLEAR'
    ) -Body {
        Select-RelayContextSettingsUi -Provider $provider -Models @('model-a', 'model-b', 'model-c')
    }

    Assert-Equal @(Get-MockRequests).Count 0 '手动分模型设置不应发出任何网络请求'
    Assert-Equal $session.Result.Count 2
    Assert-Equal $session.Result[0].Model 'model-a'
    Assert-Equal $session.Result[0].ContextWindow ([int64]1000000)
    Assert-Equal $session.Result[0].MaxContextWindow ([int64]1000000)
    Assert-Equal $session.Result[0].EffectiveContextWindowPercent 90
    Assert-Equal $session.Result[0].AutoCompactTokenLimit ([int64]850000)
    Assert-Equal $session.Result[0].Source 'MANUAL'

    Assert-Equal $session.Result[1].Model 'model-c'
    Assert-Equal $session.Result[1].ContextWindow ([int64]500000)
    Assert-Equal $session.Result[1].MaxContextWindow ([int64]500000)
    Assert-Equal $session.Result[1].EffectiveContextWindowPercent 95
    Assert-True ($null -eq $session.Result[1].AutoCompactTokenLimit)

    Assert-True (@($session.Output | Where-Object { $_.Text -match '不允许使用 K、M 等单位' }).Count -ge 1)
    Assert-True (@($session.Output | Where-Object { $_.Text -match 'auto_compact_token_limit 不能大于 context_window' }).Count -ge 1)
    Assert-Equal ([IO.File]::ReadAllBytes($paths.ModelsPath)) $beforeBytes 'Select-RelayContextSettingsUi 不应直接改写磁盘'

    # 手动中途输入 0 取消全部；模式选择输入 0 直接返回
    $cancelMid = Invoke-ContextUiMock -Answers @('1', '1000000', '', '', '0') -Body {
        Select-RelayContextSettingsUi -Provider $provider -Models @('model-a', 'model-b')
    }
    Assert-Equal $cancelMid.Result.Count 0

    $skipMode = Invoke-ContextUiMock -Answers @('0') -Body {
        Select-RelayContextSettingsUi -Provider $provider -Models @('model-a', 'model-b')
    }
    Assert-Equal $skipMode.Result.Count 0
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'ContextWindow' '自动元数据获取只请求一次 /models 并拒绝带单位字段' {
    $provider = New-TestProvider -Fixture 'models-context'
    $res = Get-RelayContextFromModels -Provider $provider -Models @('model-a', 'model-b', 'model-openrouter', 'model-unit-k', 'model-no-meta', 'model-absent')
    $reqs = @(Get-MockRequests)
    Assert-Equal $reqs.Count 1
    Assert-Equal $reqs[0].method 'GET'
    Assert-Match $reqs[0].path '/models$'

    Assert-Equal $res.Settings.Count 3
    Assert-Equal @($res.Settings | ForEach-Object { $_.Model }) @('model-a', 'model-b', 'model-openrouter')
    Assert-Equal $res.Settings[0].ContextWindow ([int64]1000000)
    Assert-Equal $res.Settings[0].EffectiveContextWindowPercent 95
    Assert-Equal $res.Settings[0].Evidence '/models:context_window'
    Assert-Equal $res.Settings[1].ContextWindow ([int64]200000)
    Assert-Equal $res.Settings[1].Evidence '/models:context_length'
    Assert-Equal $res.Settings[2].ContextWindow ([int64]1048576)
    Assert-Equal $res.Settings[2].Evidence '/models:top_provider.context_length'

    Assert-Equal $res.Rejected.Count 1
    Assert-Equal $res.Rejected[0].Model 'model-unit-k'
    Assert-Match $res.Rejected[0].Reason 'K、M|单位'
    Assert-Equal @($res.MissingModels) @('model-unit-k', 'model-no-meta', 'model-absent')
}

Add-RelayTest 'ContextWindow' '自动 Responses 解析与 SSE 请求严格处理多形态回复并拒绝单位后缀' {
    # 1. Markdown fenced JSON & 对象映射 & 标量 & 拒绝含单位
    $fenced = "``````json`n{""models"":[{""id"":""m1"",""context_window"":1000000},{""id"":""m2"",""context_window"":""256K""}]}`n``````"
    $r1 = ConvertFrom-RelayContextResponseText -Text $fenced -TargetModels @('m1', 'm2', 'm3') -QueryModel 'q-model'
    Assert-Equal $r1.Settings.Count 1
    Assert-Equal $r1.Settings[0].Model 'm1'
    Assert-Equal $r1.Settings[0].ContextWindow ([int64]1000000)
    Assert-Equal $r1.Rejected.Count 1
    Assert-Equal $r1.Rejected[0].Model 'm2'
    Assert-Equal @($r1.MissingModels) @('m2', 'm3')

    $directObj = '{"m1": 1048576, "m2": null}'
    $rDirect = ConvertFrom-RelayContextResponseText -Text $directObj -TargetModels @('m1', 'm2') -QueryModel 'q-model'
    Assert-Equal $rDirect.Settings.Count 1
    Assert-Equal $rDirect.Settings[0].ContextWindow ([int64]1048576)
    Assert-Equal @($rDirect.MissingModels) @('m2')

    $rScalarSingle = ConvertFrom-RelayContextResponseText -Text '{"context_window": 512000}' -TargetModels @('m1') -QueryModel 'q-model'
    Assert-Equal $rScalarSingle.Settings.Count 1
    Assert-Equal $rScalarSingle.Settings[0].ContextWindow ([int64]512000)
    Assert-True ($null -eq $rScalarSingle.UniformValue)

    $rScalarMulti = ConvertFrom-RelayContextResponseText -Text '1000000' -TargetModels @('m1', 'm2') -QueryModel 'q-model'
    Assert-Equal $rScalarMulti.Settings.Count 0
    Assert-Equal $rScalarMulti.UniformValue ([int64]1000000)

    foreach ($badText in @('1M', '256K', '1,000,000', '', 'sorry no unit 256k')) {
        $rBad = ConvertFrom-RelayContextResponseText -Text $badText -TargetModels @('m1') -QueryModel 'q-model'
        Assert-Equal $rBad.Settings.Count 0
        Assert-True ($null -eq $rBad.UniformValue)
        Assert-Equal $rBad.Rejected.Count 1
    }

    # 2. 对 mock-server SSE fixture 发起真实统一请求
    $p = New-TestProvider -Fixture 'sse-context-json'
    $key = Get-TestProviderKey $p
    $resJson = Get-RelayContextFromResponses -Provider $p -QueryModel 'user-chosen-model' -TargetModels @('model-a', 'model-b', 'model-missing')
    Assert-Equal $resJson.Status 'COMPATIBLE'
    Assert-Equal $resJson.Settings.Count 2
    Assert-Equal $resJson.Settings[0].ContextWindow ([int64]1000000)
    Assert-Equal $resJson.Settings[1].ContextWindow ([int64]200000)
    Assert-Equal @($resJson.MissingModels) @('model-missing')
    Assert-Equal $resJson.Settings[0].Evidence 'responses:user-chosen-model'

    $reqs = @(Get-MockRequests)
    Assert-Equal $reqs[-1].method 'POST'
    Assert-Match $reqs[-1].path '/responses$'
    $reqBody = $reqs[-1].body | ConvertFrom-Json
    Assert-Equal $reqBody.model 'user-chosen-model'
    Assert-Equal $reqBody.stream $true

    Set-MockFixture $key 'sse-context-map'
    $resMap = Get-RelayContextFromResponses -Provider $p -QueryModel 'q' -TargetModels @('model-a', 'model-unit-k', 'model-no-meta')
    Assert-Equal $resMap.Status 'COMPATIBLE'
    Assert-Equal $resMap.Settings.Count 1
    Assert-Equal $resMap.Settings[0].Model 'model-a'
    Assert-Equal $resMap.Rejected.Count 1
    Assert-Equal $resMap.Rejected[0].Model 'model-unit-k'
    Assert-Equal @($resMap.MissingModels) @('model-unit-k', 'model-no-meta')

    Set-MockFixture $key 'sse-context-scalar'
    $resScalarMulti = Get-RelayContextFromResponses -Provider $p -QueryModel 'q' -TargetModels @('m1', 'm2')
    Assert-Equal $resScalarMulti.Status 'COMPATIBLE'
    Assert-Equal $resScalarMulti.Settings.Count 0
    Assert-Equal $resScalarMulti.UniformValue ([int64]1000000)

    $resScalarOne = Get-RelayContextFromResponses -Provider $p -QueryModel 'q' -TargetModels @('m1')
    Assert-Equal $resScalarOne.Settings.Count 1
    Assert-Equal $resScalarOne.Settings[0].ContextWindow ([int64]1000000)

    foreach ($badFix in @('sse-context-unit', 'sse-context-invalid')) {
        Set-MockFixture $key $badFix
        $resUnit = Get-RelayContextFromResponses -Provider $p -QueryModel 'q' -TargetModels @('m1', 'm2')
        Assert-Equal $resUnit.Status 'COMPATIBLE'
        Assert-Equal $resUnit.Settings.Count 0
        Assert-True ($resUnit.Rejected.Count -ge 1)
    }

    Set-MockFixture $key 'http-429'
    $res429 = Get-RelayContextFromResponses -Provider $p -QueryModel 'q' -TargetModels @('m1')
    Assert-Equal $res429.Status 'RATE_LIMITED'
    Assert-Equal $res429.Settings.Count 0

    Set-MockFixture $key 'http-500'
    $res500 = Get-RelayContextFromResponses -Provider $p -QueryModel 'q' -TargetModels @('m1')
    Assert-Equal $res500.Status 'UNKNOWN'
    Assert-Equal $res500.Settings.Count 0
}

Add-RelayTest 'ContextWindow' '自动界面先请求 /models，缺项时经确认用用户选定模型统一请求并二次确认后返回' {
    # 场景 A: /models 命中 model-a 与 model-openrouter，缺失 model-no-meta -> 用户确认用 M 输入模型查询 -> sse-context-json -> 最终 YES
    $p = New-TestProvider -Fixture 'models-context'
    $key = Get-TestProviderKey $p
    $onPrompt = {
        param([string]$Prompt, $State)
        if ($Prompt -match '/responses 发起一次统一请求') {
            Set-MockFixture $key 'sse-context-json'
        }
    }
    $session = Invoke-ContextUiMock -OnReadHost $onPrompt -Answers @('2', 'YES', 'M', 'probe-model', 'YES') -Body {
        Select-RelayContextSettingsUi -Provider $p -Models @('model-a', 'model-openrouter', 'model-no-meta')
    }
    $reqs = @(Get-MockRequests)
    Assert-Equal $reqs.Count 2
    Assert-Match $reqs[0].path '/models$'
    Assert-Match $reqs[1].path '/responses$'
    Assert-Equal (($reqs[1].body | ConvertFrom-Json).model) 'probe-model'
    Assert-Equal $session.Result.Count 3
    Assert-Equal @($session.Result | ForEach-Object { $_.Model }) @('model-a', 'model-openrouter', 'model-no-meta')
    Assert-Equal $session.Result[0].Source 'MODELS_METADATA'
    Assert-Equal $session.Result[0].ContextWindow ([int64]1000000)
    Assert-Equal $session.Result[1].Source 'MODELS_METADATA'
    Assert-Equal $session.Result[1].ContextWindow ([int64]1048576)
    Assert-Equal $session.Result[2].Source 'RESPONSES_QUERY'
    Assert-Equal $session.Result[2].ContextWindow ([int64]512000)

    # 场景 B: 统一标量回复时确认应用到全部待配置模型
    Set-MockFixture $key 'http-404'
    $onUniformPrompt = {
        param([string]$Prompt, $State)
        if ($Prompt -match '/responses 发起一次统一请求') {
            Set-MockFixture $key 'sse-context-scalar'
        }
    }
    $uniformSession = Invoke-ContextUiMock -OnReadHost $onUniformPrompt -Answers @('2', 'YES', '1', 'YES', 'YES') -Body {
        Select-RelayContextSettingsUi -Provider $p -Models @('m1', 'm2')
    }
    Assert-Equal $uniformSession.Result.Count 2
    Assert-Equal $uniformSession.Result[0].ContextWindow ([int64]1000000)
    Assert-Equal $uniformSession.Result[1].ContextWindow ([int64]1000000)
    Assert-Equal $uniformSession.Result[0].Evidence 'responses-uniform:m1'

    # 场景 C: 拒绝 /responses 回退仅确认 /models 结果；以及最终拒绝 YES 不返回结果
    Set-MockFixture $key 'models-context'
    $noFallback = Invoke-ContextUiMock -Answers @('2', 'NO', 'YES') -Body {
        Select-RelayContextSettingsUi -Provider $p -Models @('model-a', 'model-no-meta')
    }
    Assert-Equal $noFallback.Result.Count 1
    Assert-Equal $noFallback.Result[0].Model 'model-a'

    $declineApply = Invoke-ContextUiMock -Answers @('2', 'NO', 'NO') -Body {
        Select-RelayContextSettingsUi -Provider $p -Models @('model-a', 'model-no-meta')
    }
    Assert-Equal $declineApply.Result.Count 0
}

Add-RelayTest 'ContextWindow' 'Apply 与 Publish 独立写入上下文元数据、生成备份并在共享失败时原子回滚' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('m-large', 'm-medium', 'm-untouched')
    $beforeJson = [IO.File]::ReadAllText($paths.ModelsPath)

    # 原子性：批量中有未知模型时在创建备份和修改目录前全部拒绝
    $badBatch = @(
        (New-RelayContextSetting -Model 'm-large' -ContextWindow 1000000),
        (New-RelayContextSetting -Model 'unknown-slug' -ContextWindow 200000)
    )
    [void](Assert-Throws { Apply-RelayContextSettings -Provider $p -Settings $badBatch } '未知 Catalog model')
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $beforeJson
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak').Count 0

    $goodBatch = @(
        (New-RelayContextSetting -Model 'm-large' -ContextWindow 1000000 -MaxContextWindow 1048576 -EffectiveContextWindowPercent 95 -AutoCompactTokenLimit 850000 -Source 'MANUAL' -Evidence 'manual-per-model'),
        (New-RelayContextSetting -Model 'm-medium' -ContextWindow 200000 -MaxContextWindow 200000 -EffectiveContextWindowPercent 90 -AutoCompactTokenLimit $null -Source 'MODELS_METADATA' -Evidence '/models:context_length')
    )
    Apply-RelayContextSettings -Provider $p -Settings $goodBatch
    $backups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak')
    Assert-Equal $backups.Count 1
    Assert-Equal ([IO.File]::ReadAllText($backups[0].FullName)) $beforeJson

    $doc = Read-RelayJson $paths.ModelsPath
    $mLarge = @($doc.models | Where-Object { $_.slug -ceq 'm-large' })[0]
    $mMedium = @($doc.models | Where-Object { $_.slug -ceq 'm-medium' })[0]
    $mUntouched = @($doc.models | Where-Object { $_.slug -ceq 'm-untouched' })[0]
    Assert-Equal ([int64]$mLarge.context_window) ([int64]1000000)
    Assert-Equal ([int64]$mLarge.max_context_window) ([int64]1048576)
    Assert-Equal ([int]$mLarge.effective_context_window_percent) 95
    Assert-Equal ([int64]$mLarge.auto_compact_token_limit) ([int64]850000)
    Assert-Equal $mLarge.relay_context_evidence.Source 'MANUAL'

    Assert-Equal ([int64]$mMedium.context_window) ([int64]200000)
    Assert-Equal ([int]$mMedium.effective_context_window_percent) 90
    Assert-True ($null -eq $mMedium.auto_compact_token_limit)
    Assert-Equal $mMedium.relay_context_evidence.Source 'MODELS_METADATA'
    Assert-Equal ([int64]$mUntouched.context_window) ([int64]272000)

    # Publish-RelayCodexModels 应用 ContextSettings 且不向 config.toml 写全局 model_context_window
    $p2 = New-TestProvider
    $paths2 = Get-RelayCatalogPaths $p2
    $auth2 = Get-RelayCredentialConfig -Provider $p2
    $cfg2 = Join-Path $script:RTCaseDirectory 'fixture-config-publish.toml'
    $plan2 = New-RelaySharedConfigPlan -Provider $p2 -Model 'm-one' -ConfigPath $cfg2 -CatalogPath $paths2.ModelsPath -AuthConfig $auth2
    $pubCtx = @(
        (New-RelayContextSetting -Model 'm-one' -ContextWindow 1000000),
        (New-RelayContextSetting -Model 'm-two' -ContextWindow 400000 -EffectiveContextWindowPercent 92)
    )
    $tx = Publish-RelayCodexModels -Provider $p2 -Models @('m-one', 'm-two') -Plan $plan2 -ContextSettings $pubCtx
    Assert-True ($null -ne $tx)
    $doc2 = Read-RelayJson $paths2.ModelsPath
    Assert-Equal ([int64](@($doc2.models | Where-Object { $_.slug -ceq 'm-one' })[0].context_window)) ([int64]1000000)
    Assert-Equal ([int64](@($doc2.models | Where-Object { $_.slug -ceq 'm-two' })[0].context_window)) ([int64]400000)
    $sharedToml = [IO.File]::ReadAllText($plan2.ConfigPath)
    Assert-True ($sharedToml -notmatch '(?m)^\s*model_context_window\s*=') '共享 config.toml 不应写全局 model_context_window，以免覆盖多模型独立窗口'

    # 共享提交失败时回滚 models.json（恢复更新前状态）
    $snapshotBeforeFail = [IO.File]::ReadAllBytes($paths2.ModelsPath)
    $auth3 = Get-RelayCredentialConfig -Provider $p2
    $plan3 = New-RelaySharedConfigPlan -Provider $p2 -Model 'm-one' -ConfigPath $cfg2 -CatalogPath $paths2.ModelsPath -AuthConfig $auth3
    $failCtx = @((New-RelayContextSetting -Model 'm-one' -ContextWindow 2000000))
    $origInvokePlan = (Get-Command -Name 'Invoke-RelaySharedConfigPlan' -CommandType Function).ScriptBlock
    try {
        Set-Item -LiteralPath 'Function:script:Invoke-RelaySharedConfigPlan' -Value { param($Plan) throw 'simulated shared config failure' }
        [void](Assert-Throws {
            Publish-RelayCodexModels -Provider $p2 -Models @('m-one', 'm-three') -Plan $plan3 -ContextSettings $failCtx
        } 'simulated shared config failure')
    } finally {
        Set-Item -LiteralPath 'Function:script:Invoke-RelaySharedConfigPlan' -Value $origInvokePlan
    }
    Assert-Equal ([IO.File]::ReadAllBytes($paths2.ModelsPath)) $snapshotBeforeFail '共享提交失败必须完整回滚 models.json'
}

Add-RelayTest 'ContextWindow' '模板刷新保留有证据的上下文窗口并重置未标记的旧占位值' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('m-keep', 'm-placeholder')
    Apply-RelayContextSettings -Provider $p -Settings @(
        (New-RelayContextSetting -Model 'm-keep' -ContextWindow 1000000 -MaxContextWindow 1048576 -EffectiveContextWindowPercent 90 -AutoCompactTokenLimit 800000 -Source 'MANUAL' -Evidence 'manual-per-model')
    )
    $doc = Read-RelayJson $paths.ModelsPath
    foreach ($entry in $doc.models) {
        if ($entry.slug -ceq 'm-placeholder') {
            $entry.context_window = 12345
        }
        $entry.relay_official_template.Version = '0.0.0-old'
    }
    Write-RelayJson $paths.ModelsPath $doc

    $upgraded = Update-RelayCatalogOfficialTemplates -Provider $p -Models @('m-keep', 'm-placeholder')
    Assert-Equal $upgraded.ModelsPath $paths.ModelsPath
    $after = Read-RelayJson $paths.ModelsPath
    $keep = @($after.models | Where-Object { $_.slug -ceq 'm-keep' })[0]
    $placeholder = @($after.models | Where-Object { $_.slug -ceq 'm-placeholder' })[0]

    Assert-Equal ([int64]$keep.context_window) ([int64]1000000)
    Assert-Equal ([int64]$keep.max_context_window) ([int64]1048576)
    Assert-Equal ([int]$keep.effective_context_window_percent) 90
    Assert-Equal ([int64]$keep.auto_compact_token_limit) ([int64]800000)
    Assert-Equal $keep.relay_context_evidence.Source 'MANUAL'

    Assert-Equal ([int64]$placeholder.context_window) ([int64]272000)
    Assert-True (-not $placeholder.PSObject.Properties['relay_context_evidence'])
}

Add-RelayTest 'ContextWindow' '独立菜单管理 Update-RelayContextSettingsUi 支持单选调整并完整保留共享 config.toml' {
    $p = New-TestProvider
    $paths = Get-RelayCatalogPaths $p
    $auth = Get-RelayCredentialConfig -Provider $p
    $cfg = Join-Path $script:RTCaseDirectory 'fixture-config-standalone.toml'
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'model-x' -ConfigPath $cfg -CatalogPath $paths.ModelsPath -AuthConfig $auth
    $null = Publish-RelayCodexModels -Provider $p -Models @('model-x', 'model-y') -Plan $plan
    $sharedBefore = [IO.File]::ReadAllBytes($plan.ConfigPath)

    # [2] 单个模型 -> [1] model-x -> [1] 手动 -> 1000000, '', '' -> YES 确认
    $session = Invoke-ContextUiMock -Answers @('2', '1', '1', '1000000', '', '', 'YES') -Body {
        Update-RelayContextSettingsUi -Provider $p -ConfigPath $cfg
    }
    $doc = Read-RelayJson $paths.ModelsPath
    $mx = @($doc.models | Where-Object { $_.slug -ceq 'model-x' })[0]
    $my = @($doc.models | Where-Object { $_.slug -ceq 'model-y' })[0]
    Assert-Equal ([int64]$mx.context_window) ([int64]1000000)
    Assert-Equal ([int64]$my.context_window) ([int64]272000)
    Assert-Equal ([IO.File]::ReadAllBytes($plan.ConfigPath)) $sharedBefore '独立上下文管理不得改动共享 config.toml'
    Assert-True (@(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak').Count -ge 1)

    # 取消 [0] 不应新增备份或修改目录
    $beforeCancel = [IO.File]::ReadAllBytes($paths.ModelsPath)
    $bakCountBefore = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak').Count
    $cancel = Invoke-ContextUiMock -Answers @('0') -Body {
        Update-RelayContextSettingsUi -Provider $p -ConfigPath $cfg
    }
    Assert-Equal ([IO.File]::ReadAllBytes($paths.ModelsPath)) $beforeCancel
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak').Count $bakCountBefore
}

Add-RelayTest 'ContextWindow' 'JSON 深度校验保留带尾零的 ISO 时间并继续拒绝深层截断' {
    foreach ($timestamp in @('2026-11-12T01:02:03.1234000Z', '2026-11-12T01:02:03.0000000Z', '2026-11-12T01:02:03.1234567Z')) {
        $doc = [pscustomobject]@{ relay_context_evidence = [pscustomobject]@{ UpdatedAt = $timestamp } }
        Assert-RelayCatalogJsonDepth -Document $doc
        Assert-RelayCatalogJsonDepth -Document $doc -Kind 'effort'
        Assert-Equal $doc.relay_context_evidence.UpdatedAt $timestamp
    }
    $deep = [pscustomobject]@{ leaf = 'must survive' }
    for ($i = 0; $i -lt 35; $i++) { $deep = [pscustomobject]@{ child = $deep } }
    $savedWarning = $WarningPreference
    try {
        $WarningPreference = 'SilentlyContinue'
        [void](Assert-Throws { Assert-RelayCatalogJsonDepth -Document $deep } '超出安全 JSON 深度')
    } finally { $WarningPreference = $savedWarning }
}

Add-RelayTest 'ContextWindow' '顶层 JSON 数组按 ID 匹配且单元素、空数组和损坏数组不退化为标量' {
    $two = ConvertFrom-RelayContextResponseText -Text '[{"id":"m2","context_window":200000},{"id":"m1","context_window":1000000}]' -TargetModels @('m1', 'm2') -QueryModel q
    Assert-Equal @($two.Settings | ForEach-Object { $_.Model }) @('m1', 'm2')
    Assert-Equal @($two.Settings | ForEach-Object { $_.ContextWindow }) @([int64]1000000, [int64]200000)
    $single = ConvertFrom-RelayContextResponseText -Text '[{"id":"m1","context_window":1000000}]' -TargetModels @('m1', 'm2') -QueryModel q
    Assert-Equal $single.Settings.Count 1
    Assert-Equal $single.Settings[0].Model 'm1'
    Assert-Equal @($single.MissingModels) @('m2')
    Assert-True ($null -eq $single.UniformValue)
    foreach ($text in @('[{"id":"other-model","context_window":1000000}]', '[]', '[1000000]', '[{"id":"other-model","context_window":1000000}')) {
        $result = ConvertFrom-RelayContextResponseText -Text $text -TargetModels @('target-model') -QueryModel q
        Assert-Equal $result.Settings.Count 0
        Assert-True ($null -eq $result.UniformValue)
        Assert-Equal @($result.MissingModels) @('target-model')
    }
    $unit = ConvertFrom-RelayContextResponseText -Text '[{"id":"m1","context_window":"1M"}]' -TargetModels @('m1') -QueryModel q
    Assert-Equal $unit.Settings.Count 0
    Assert-Equal $unit.Rejected.Count 1
}

Add-RelayTest 'ContextWindow' '全局窗口覆盖在预览、发布和独立管理时拒绝且不修改目录或配置' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('m1')
    $auth = Get-RelayCredentialConfig $p
    $cfg = Join-Path $script:RTCaseDirectory 'context-conflicts.toml'
    $settings = @((New-RelayContextSetting -Model m1 -ContextWindow 1000000))
    $catalogBefore = [IO.File]::ReadAllBytes($paths.ModelsPath)
    foreach ($key in @('model_context_window', 'model_auto_compact_token_limit')) {
        $text = '# preserve this comment' + "`n" + '"' + $key + '" = 272000'
        [IO.File]::WriteAllText($cfg, $text)
        $before = [IO.File]::ReadAllBytes($cfg)
        # Skipping context management still preserves existing global settings.
        $legacyPlan = New-RelaySharedConfigPlan -Provider $p -Model m1 -ConfigPath $cfg -CatalogPath $paths.ModelsPath -AuthConfig $auth
        Assert-True $legacyPlan.Content.Contains($text)
        [void](Assert-Throws {
            New-RelaySharedConfigPlan -Provider $p -Model m1 -ConfigPath $cfg -CatalogPath $paths.ModelsPath -AuthConfig $auth -ContextSettings $settings
        } $key)
        [void](Assert-Throws { Publish-RelayCodexModels -Provider $p -Models @('m1') -Plan $legacyPlan -ContextSettings $settings } $key)
        $session = Invoke-ContextUiMock -Answers @() -Body {
            [void](Assert-Throws { Update-RelayContextSettingsUi -Provider $p -ConfigPath $cfg } $key)
        }
        Assert-Equal $session.Prompts.Count 0 'Conflict should be detected before any interactive/network work'
        Assert-Equal ([IO.File]::ReadAllBytes($cfg)) $before
        Assert-Equal ([IO.File]::ReadAllBytes($paths.ModelsPath)) $catalogBefore
        Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak').Count 0
        # Clearing the current file cannot make an old preview containing overrides safe.
        [IO.File]::WriteAllText($cfg, '')
        [void](Assert-Throws { Publish-RelayCodexModels -Provider $p -Models @('m1') -Plan $legacyPlan -ContextSettings $settings } $key)
    }
    Assert-RelayContextConfigOverrides -Text ('MODEL_CONTEXT_WINDOW = 272000' + "`n" + '[profiles.inactive]' + "`n" + 'model_context_window = 123')
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'ContextWindow' '发布与独立管理在保存前重新检查交互期间新增的全局覆盖' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('m1')
    $auth = Get-RelayCredentialConfig $p
    $cfg = Join-Path $script:RTCaseDirectory 'context-recheck.toml'
    [IO.File]::WriteAllText($cfg, '')
    $settings = @((New-RelayContextSetting -Model m1 -ContextWindow 1000000))
    $plan = New-RelaySharedConfigPlan -Provider $p -Model m1 -ConfigPath $cfg -CatalogPath $paths.ModelsPath -AuthConfig $auth -ContextSettings $settings
    $before = [IO.File]::ReadAllBytes($paths.ModelsPath)
    [IO.File]::WriteAllText($cfg, 'model_context_window = 272000')
    [void](Assert-Throws { Publish-RelayCodexModels -Provider $p -Models @('m1') -Plan $plan -ContextSettings $settings } 'model_context_window')
    [IO.File]::WriteAllText($cfg, '')
    $onConfirm = {
        param([string]$Prompt, $State)
        if ($Prompt -match '将先备份 models.json') { [IO.File]::WriteAllText($cfg, 'model_auto_compact_token_limit = 150000') }
    }
    $session = Invoke-ContextUiMock -Answers @('1', '1', '1000000', '', '', 'YES') -OnReadHost $onConfirm -Body {
        [void](Assert-Throws { Update-RelayContextSettingsUi -Provider $p -ConfigPath $cfg } 'model_auto_compact_token_limit')
    }
    Assert-Equal ([IO.File]::ReadAllBytes($paths.ModelsPath)) $before
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak').Count 0
    Assert-Equal @($session.Output | Where-Object { $_.Text -match '^已备份并更新' }).Count 0
}
