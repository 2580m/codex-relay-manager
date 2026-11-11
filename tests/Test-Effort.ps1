# Effort contract tests import only the main library via Run-Tests.ps1, never the implementation fragment.
# Every API call is replaced by a function fixture; these tests incur no real API cost.
function Invoke-EffortUiFixture {
    param([string[]]$Answers, [hashtable]$Statuses = @{}, [scriptblock]$Action)
    $fixture = [pscustomobject]@{
        Answers = (New-Object 'Collections.Generic.Queue[string]')
        Calls = (New-Object 'Collections.Generic.List[object]')
        Messages = (New-Object 'Collections.Generic.List[string]')
        Statuses = $Statuses
    }
    foreach ($answer in $Answers) { $fixture.Answers.Enqueue($answer) }
    $saved = @{}
    foreach ($name in @('Read-Host', 'Test-RelayResponse', 'Write-RelaySafe')) {
        $command = Get-Command $name -CommandType Function -ErrorAction SilentlyContinue
        $saved[$name] = $null; if ($command) { $saved[$name] = $command.ScriptBlock }
    }
    try {
        function Read-Host {
            param([string]$Prompt)
            $fixture.Messages.Add($Prompt)
            if (-not $fixture.Answers.Count) { throw ('Unexpected Read-Host: ' + $Prompt) }
            return $fixture.Answers.Dequeue()
        }
        function Write-RelaySafe { param([string]$Text, $Color); $fixture.Messages.Add($Text) }
        function Test-RelayResponse {
            param($Provider, [string]$Model, [string]$ReasoningEffort)
            $effort = '<baseline>'; if ($PSBoundParameters.ContainsKey('ReasoningEffort')) { $effort = $ReasoningEffort }
            $fixture.Calls.Add([pscustomobject]@{ Model = $Model; Effort = $effort; ProviderId = $Provider.Id })
            $status = 'COMPATIBLE'
            $key = $Model + '|' + $effort
            if ($fixture.Statuses.ContainsKey($key)) { $status = $fixture.Statuses[$key] }
            return [pscustomobject]@{ Status = $status; Message = 'fixture only'; Events = @() }
        }
        & $Action $fixture
        Assert-Equal $fixture.Answers.Count 0 'The UI did not consume exactly the expected prompts'
    } finally {
        foreach ($name in $saved.Keys) {
            if ($null -ne $saved[$name]) { Set-Item -LiteralPath ('Function:' + $name) -Value $saved[$name] }
            else { Remove-Item -LiteralPath ('Function:' + $name) -ErrorAction SilentlyContinue }
        }
    }
}

Add-RelayTest 'Effort' '固定七个预定义探测等级不混入 ultra；模型列表仍由调用方提供' {
    Assert-Equal @(Get-RelayEffortLevels) @('none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max')
}

Add-RelayTest 'Effort' '0不设置既不请求不确认也不改已有目录；空设置 Apply 无写入' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one')
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    $files = @(Get-ChildItem -LiteralPath $paths.Directory).Count
    Invoke-EffortUiFixture -Answers @('0') -Action {
        param($f)
        $settings = @(Select-RelayEffortSettingsUi -Provider $p -Models @('one'))
        Assert-Equal $settings @()
        Apply-RelayEffortSettings -Provider $p -Settings $settings
        Assert-Equal $f.Calls.Count 0
    }
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory).Count $files
}

Add-RelayTest 'Effort' '单模型取消序号或费用确认不发生请求；全部二次拒绝无费用' {
    $p = New-TestProvider
    foreach ($answers in @(@('1', '0'), @('1', '1', 'no'), @('2', 'no'), @('2', 'YES', 'no'))) {
        Invoke-EffortUiFixture -Answers $answers -Action {
            param($f)
            Assert-Equal @(Select-RelayEffortSettingsUi $p @('one', 'two')) @()
            Assert-Equal $f.Calls.Count 0
        }
    }
}

Add-RelayTest 'Effort' '单模型仅请求指定模型基线加七候选；单次费用确认及固定免责声明' {
    $p = New-TestProvider
    Invoke-EffortUiFixture -Answers @('bad', '1', 'bad', '3', '2', 'YES') -Action {
        param($f)
        $s = @(Select-RelayEffortSettingsUi $p @('one', '动态模型'))
        Assert-Equal $s.Count 1
        Assert-Equal $s[0].Model '动态模型'
        Assert-StringArray $s[0].SupportedLevels
        Assert-Equal $s[0].SupportedLevels @(Get-RelayEffortLevels)
        Assert-Equal $s[0].DefaultLevel 'none'
        Assert-Equal $s[0].Source 'API_ACCEPTED'
        Assert-Equal $f.Calls.Count 8
        Assert-Equal @($f.Calls | ForEach-Object { $_.Model } | Select-Object -Unique) @('动态模型')
        Assert-Equal @($f.Calls | ForEach-Object { $_.Effort }) (@('<baseline>') + @(Get-RelayEffortLevels))
        Assert-Match ($f.Messages -join "`n") '最多 8 次请求'
        Assert-Match ($f.Messages -join "`n") '不证明.*实际生效'
        Assert-Equal @($f.Messages | Where-Object { $_ -match '输入 YES' }).Count 1
    }
}

Add-RelayTest 'Effort' '全部检测双确认并按模型去重；基线不兼容不探测该模型等级' {
    $p = New-TestProvider
    Invoke-EffortUiFixture -Answers @('2', 'YES', 'YES') -Statuses @{ 'one|<baseline>' = 'INCOMPATIBLE' } -Action {
        param($f)
        $s = @(Select-RelayEffortSettingsUi $p @('one', 'two', 'two'))
        Assert-Equal $s.Count 1
        Assert-Equal $s[0].Model 'two'
        Assert-Equal @($f.Calls | Where-Object { $_.Model -ceq 'one' }).Count 1
        Assert-Equal $f.Calls.Count 9
        Assert-Equal @($f.Messages | Where-Object { $_ -match '输入 YES' }).Count 2
        Assert-Match ($f.Messages -join "`n") '最多 16 次请求'
    }
}

Add-RelayTest 'Effort' '所有非兼容分类不标支持；零 accepted 不生成空设置' {
    $p = New-TestProvider
    $statuses = @{}; foreach ($level in @(Get-RelayEffortLevels)) { $statuses['one|' + $level] = 'UNKNOWN' }
    $statuses['one|none'] = 'INCOMPATIBLE'; $statuses['one|minimal'] = 'MODEL_UNAVAILABLE'
    Invoke-EffortUiFixture -Answers @('1', '1', 'YES') -Statuses $statuses -Action {
        param($f)
        Assert-Equal @(Select-RelayEffortSettingsUi $p @('one')) @()
        Assert-Equal $f.Calls.Count 8
    }
}

Add-RelayTest 'Effort' '认证限流网络错误仅停止当前模型剩余探测并保留先前 accepted' {
    $p = New-TestProvider
    foreach ($stop in @('AUTH_FAILED', 'RATE_LIMITED', 'NETWORK_ERROR')) {
        Invoke-EffortUiFixture -Answers @('2', 'YES', 'YES') -Statuses @{ 'one|minimal' = $stop } -Action {
            param($f)
            $s = @(Select-RelayEffortSettingsUi $p @('one', 'two'))
            Assert-Equal $s.Count 2
            Assert-Equal $s[0].SupportedLevels @('none')
            Assert-Equal $s[0].DefaultLevel 'none'
            Assert-Equal @($f.Calls | Where-Object { $_.Model -ceq 'one' } | ForEach-Object { $_.Effort }) @('<baseline>', 'none', 'minimal')
            Assert-Equal @($f.Calls | Where-Object { $_.Model -ceq 'two' }).Count 8
        }
    }
}

Add-RelayTest 'Effort' '默认保留已有 accepted 等级否则选首个 accepted 而非隐选 high' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one')
    $doc = Read-RelayJson $paths.ModelsPath; $doc.models[0].default_reasoning_level = 'medium'; Write-RelayJson $paths.ModelsPath $doc
    Invoke-EffortUiFixture -Answers @('1', '1', 'YES') -Action {
        param($f)
        $s = @(Select-RelayEffortSettingsUi $p @('one'))
        Assert-Equal $s[0].DefaultLevel 'medium'
    }
    $statuses = @{ 'one|none' = 'INCOMPATIBLE'; 'one|minimal' = 'INCOMPATIBLE'; 'one|medium' = 'INCOMPATIBLE' }
    Invoke-EffortUiFixture -Answers @('1', '1', 'YES') -Statuses $statuses -Action {
        param($f)
        $s = @(Select-RelayEffortSettingsUi $p @('one'))
        Assert-Equal $s[0].DefaultLevel 'low'
        Assert-Equal $s[0].SupportedLevels @('low', 'high', 'xhigh', 'max')
    }
}

Add-RelayTest 'Effort' 'Apply只改选中模型两个effort字段保留所有metadata并备份原字节' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one', 'two')
    $doc = Read-RelayJson $paths.ModelsPath
    $doc | Add-Member NoteProperty custom_root ([pscustomobject]@{ keep = @('root') })
    $doc.models[0].context_window = 12345
    $doc.models[0] | Add-Member NoteProperty custom_metadata ([pscustomobject]@{ nested = @('a', 42) })
    $doc.models[1].supported_reasoning_levels = @([pscustomobject]@{ effort = 'high'; description = 'custom old metadata' })
    Write-RelayJson $paths.ModelsPath $doc
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    $beforeConfig = [IO.File]::ReadAllText($paths.ConfigPath)
    Apply-RelayEffortSettings $p @([pscustomobject]@{ Model = 'one'; SupportedLevels = [string[]]@('low'); DefaultLevel = $null; Source = 'API_ACCEPTED' })
    $after = Read-RelayJson $paths.ModelsPath
    Assert-True ($after.models[0].supported_reasoning_levels -is [array])
    Assert-Equal $after.models[0].supported_reasoning_levels.Count 1
    Assert-Equal $after.models[0].supported_reasoning_levels[0].effort 'low'
    Assert-Match $after.models[0].supported_reasoning_levels[0].description '不证明.*实际生效'
    Assert-Equal $after.models[0].default_reasoning_level $null
    $doc.models[0].default_reasoning_level = $after.models[0].default_reasoning_level
    $doc.models[0].supported_reasoning_levels = $after.models[0].supported_reasoning_levels
    Assert-Equal $after $doc
    Assert-Equal ([IO.File]::ReadAllText($paths.ConfigPath)) $beforeConfig
    $backups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak')
    Assert-Equal $backups.Count 1
    Assert-Equal ([IO.File]::ReadAllText($backups[0].FullName)) $before
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'Effort' '未知模型大小写差异无效默认及未知等级整批拒绝且不创建备份' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one')
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    $valid = [pscustomobject]@{ Model = 'one'; SupportedLevels = [string[]]@('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' }
    foreach ($bad in @(
        [pscustomobject]@{ Model = 'unknown'; SupportedLevels = @('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'ONE'; SupportedLevels = @('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'one'; SupportedLevels = @('low'); DefaultLevel = 'high'; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'one'; SupportedLevels = @('ultra'); DefaultLevel = $null; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'one'; SupportedLevels = @(); DefaultLevel = $null; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'one'; SupportedLevels = @('low', 'low'); DefaultLevel = $null; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'one'; SupportedLevels = @('low'); DefaultLevel = $null; Source = 'INVALID' },
        [pscustomobject]@{ Model = 'one'; SupportedLevels = @('low'); DefaultLevel = $null; Source = 'MANUAL' }
    )) {
        Assert-Throws { Apply-RelayEffortSettings $p @($bad) } | Out-Null
        Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    }
    $unknown = [pscustomobject]@{ Model = 'missing'; SupportedLevels = @('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' }
    Assert-Throws { Apply-RelayEffortSettings $p @($valid, $unknown) } '未知' | Out-Null
    Assert-Throws { Apply-RelayEffortSettings $p @($valid, $valid) } '重复' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter '*.bak').Count 0
}

Add-RelayTest 'Effort' '损坏catalog不覆盖且写入失败保留原件和备份；共享stub失败后恢复' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one')
    $valid = [pscustomobject]@{ Model = 'one'; SupportedLevels = @('low'); DefaultLevel = 'low'; Source = 'API_ACCEPTED' }
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    [IO.File]::WriteAllText($paths.ModelsPath, '{broken')
    Assert-Throws { Apply-RelayEffortSettings $p @($valid) } 'JSON' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) '{broken'
    [IO.File]::WriteAllText($paths.ModelsPath, $before)
    $original = ${function:Write-RelayJson}
    try {
        function Write-RelayJson { param($Path, $Value); throw 'INJECTED_EFFORT_WRITE_FAILURE' }
        Assert-Throws { Apply-RelayEffortSettings $p @($valid) } 'INJECTED_EFFORT_WRITE_FAILURE' | Out-Null
    } finally { Set-Item Function:Write-RelayJson $original }
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    $backups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak')
    Assert-Equal $backups.Count 1
    Assert-Equal ([IO.File]::ReadAllText($backups[0].FullName)) $before
    $originalResponse = ${function:Test-RelayResponse}
    Assert-Throws { Invoke-EffortUiFixture -Answers @() -Action { throw 'FIXTURE_RESTORE' } } 'FIXTURE_RESTORE' | Out-Null
    Assert-Equal (${function:Test-RelayResponse}.ToString()) $originalResponse.ToString()
}
