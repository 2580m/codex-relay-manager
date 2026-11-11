# Catalog 合约测试：只使用 Shared 创建的隔离管理器目录，不触碰用户 .codex。
# 可选官方实机验证：设置 RELAY_TEST_CODEX_EXE 为官方原生 EXE 后运行 -Suite Catalog。

function Assert-CatalogOfficialCapabilities {
    param($Actual, $Template, [switch]$Exact)
    # 别名的标识、证据描述和官方升级/套餐提示允许不同，能力字段必须完整复制。
    foreach ($property in $Template.PSObject.Properties) {
        if (-not $Exact -and $property.Name -in @('slug', 'display_name', 'description', 'upgrade', 'availability_nux', 'available_in_plans')) { continue }
        Assert-True ($null -ne $Actual.PSObject.Properties[$property.Name]) ('Missing official catalog field: ' + $property.Name)
        $expected = $property.Value
        # 官方 nullable tools 在中转目录中规范成数组，以兼容现有 schema 校验。
        if ($property.Name -eq 'experimental_supported_tools' -and $null -eq $expected) { $expected = @() }
        Assert-Equal $Actual.PSObject.Properties[$property.Name].Value $expected ('Official catalog field differs: ' + $property.Name)
    }
}

function Assert-CatalogNoUpgrade {
    param($Entry)
    Assert-True ((-not $Entry.PSObject.Properties['upgrade']) -or $null -eq $Entry.upgrade) 'Relay catalog must not redirect the requested slug through an official upgrade'
}

Add-RelayTest 'Catalog' '路径按 Provider 隔离且查询不创建目录' {
    $p = New-TestProvider
    $paths = Get-RelayCatalogPaths $p
    Assert-Equal $paths.Directory (Join-Path (Join-Path $script:RTCaseDirectory 'catalog') $p.Id)
    Assert-Equal $paths.ModelsPath (Join-Path $paths.Directory 'models.json')
    Assert-Equal $paths.ConfigPath (Join-Path $paths.Directory 'relay.config.toml')
    Assert-StringArray @(Get-RelayCatalogModels $p) -AllowEmpty
    Clear-RelayCodexCatalog $p
    Assert-True (-not [IO.Directory]::Exists($paths.Directory))
}

Add-RelayTest 'Catalog' '拒绝大写和路径穿越 Provider ID' {
    foreach ($id in @('relay_0123456789ABCDEF0123456789abcdef', '../relay_0123456789abcdef0123456789abcdef', 'relay_0123456789abcdef0123456789abcdef.extra')) {
        $p = [pscustomobject]@{ Id = $id }
        Assert-Throws { Get-RelayCatalogPaths $p } 'Provider ID' | Out-Null
        Assert-Throws { Add-RelayCodexModels $p @('one') } 'Provider ID' | Out-Null
        Assert-Throws { Get-RelayCatalogModels $p } 'Provider ID' | Out-Null
        Assert-Throws { Clear-RelayCodexCatalog $p } 'Provider ID' | Out-Null
    }
}

Add-RelayTest 'Catalog' '批量生成官方目录与无 key 无默认模型的独立 TOML' {
    $p = New-TestProvider -Name '中转 "quoted" C:\目录\'
    $key = Get-TestProviderKey $p
    $paths = Add-RelayCodexModels $p @('动态模型 "quoted" C:\路径\', 'second', 'second', 'SECOND')
    Assert-Equal @(Get-RelayCatalogModels $p) @('动态模型 "quoted" C:\路径\', 'second', 'SECOND')
    $doc = Read-RelayJson $paths.ModelsPath
    Assert-True ($doc.models -is [array])
    Assert-Equal $doc.models.Count 3
    $official = Get-RelayOfficialCatalog
    $template = @($official.models | Where-Object { $_.slug -ceq 'gpt-5.5' })
    Assert-Equal $template.Count 1
    foreach ($entry in $doc.models) {
        Assert-CatalogOfficialCapabilities $entry $template[0]
        Assert-Equal $entry.display_name $entry.slug
        Assert-Equal @($entry.supported_reasoning_levels | ForEach-Object { $_.effort }) @('low', 'medium', 'high', 'xhigh')
        Assert-Equal $entry.default_reasoning_level 'medium'
        Assert-Equal $entry.shell_type 'shell_command'
        Assert-Equal $entry.input_modalities @('text', 'image')
        Assert-Equal $entry.support_verbosity $true
        Assert-Equal $entry.supports_search_tool $true
        Assert-Equal $entry.supports_reasoning_summary_parameter $true
        Assert-Equal $entry.node_repl_disabled $false
        Assert-Equal $entry.include_skills_usage_instructions $true
        Assert-Equal $entry.include_apps_usage_instructions $true
        Assert-Equal $entry.include_plugin_usage_instructions $true
        Assert-Equal $entry.supports_image_detail_original $true
        Assert-True ($entry.model_messages.instructions_template.Length -gt 10000) 'Official instructions must not be replaced by a short placeholder'
        Assert-Equal $entry.context_window 272000
        Assert-Equal $entry.relay_official_template.Version '0.167.1'
        Assert-Equal $entry.relay_official_template.Slug 'gpt-5.5'
        Assert-Equal $entry.relay_official_template.ExactMatch $false
        Assert-CatalogNoUpgrade $entry
    }
    $config = [IO.File]::ReadAllText($paths.ConfigPath)
    Assert-Match $config ('(?m)^model_provider = ' + [regex]::Escape((ConvertTo-TomlString $p.Id)) + '$')
    Assert-Match $config ('(?m)^model_catalog_json = ' + [regex]::Escape((ConvertTo-TomlString $paths.ModelsPath)) + '$')
    Assert-Match $config ('(?m)^name = ' + [regex]::Escape((ConvertTo-TomlString $p.Name)) + '$')
    Assert-Match $config '(?m)^env_key = "CODEX_RELAY_API_KEY"$'
    Assert-True ($config -notmatch '(?m)^\s*model\s*=')
    Assert-True (-not $config.Contains($p.EncryptedApiKey))
    foreach ($path in @($paths.ModelsPath, $paths.ConfigPath)) {
        $bytes = [IO.File]::ReadAllBytes($path)
        Assert-True (-not ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'JSON/TOML must be UTF8 without BOM'
    }
    Assert-NoSecretInStore $key
    Assert-Equal @(Get-MockRequests).Count 0 'Adding a catalog must not probe the network'
}

Add-RelayTest 'Catalog' '精确官方 gpt-6.1-sol 使用自身完整模板而非 gpt-5.5 能力' {
    $official = Get-RelayOfficialCatalog
    $template = @($official.models | Where-Object { $_.slug -ceq 'gpt-6.1-sol' })
    Assert-Equal $template.Count 1
    $entry = New-RelayCatalogModel -Slug 'gpt-6.1-sol'
    Assert-CatalogOfficialCapabilities $entry $template[0] -Exact
    Assert-Equal $entry.slug 'gpt-6.1-sol'
    Assert-Equal $entry.display_name 'GPT-6.1-Sol'
    Assert-Equal $entry.default_reasoning_level 'low'
    Assert-Equal @($entry.supported_reasoning_levels | ForEach-Object { $_.effort }) @('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    Assert-Equal $entry.include_skills_usage_instructions $false
    Assert-Equal $entry.include_apps_usage_instructions $false
    Assert-Equal $entry.include_plugin_usage_instructions $false
    Assert-Equal $entry.model_messages.instructions_template.Length 21769
    Assert-Equal $entry.context_window 272000
    Assert-Equal $entry.relay_official_template.Version '0.167.1'
    Assert-Equal $entry.relay_official_template.Slug 'gpt-6.1-sol'
    Assert-Equal $entry.relay_official_template.ExactMatch $true
    # 同一官方匹配结果也必须能实际写入并通过目录校验。
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('gpt-6.1-sol')
    $doc = Read-RelayJson $paths.ModelsPath
    Assert-Equal $doc.models.Count 1
    Assert-Equal $doc.models[0] $entry
}

Add-RelayTest 'Catalog' '非官方别名保留原 slug 且仅精确大小写匹配官方模板不升级模型' {
    $official = Get-RelayOfficialCatalog
    $template = @($official.models | Where-Object { $_.slug -ceq 'gpt-5.5' })[0]
    # 无连字符的别名和仅大小写不同的 ID 都不是官方 exact match。
    $slugs = @('gpt6.1sol', 'gpt-6.1sol', 'GPT-6.1-SOL', 'custom/provider-model')
    foreach ($slug in $slugs) {
        $entry = New-RelayCatalogModel -Slug $slug
        Assert-Equal $entry.slug $slug
        Assert-Equal $entry.display_name $slug
        Assert-CatalogOfficialCapabilities $entry $template
        Assert-Equal $entry.relay_official_template.Slug 'gpt-5.5'
        Assert-Equal $entry.relay_official_template.ExactMatch $false
        Assert-CatalogNoUpgrade $entry
        foreach ($field in @('availability_nux', 'available_in_plans')) {
            Assert-True (-not $entry.PSObject.Properties[$field]) ('Alias must not inherit official-only hint: ' + $field)
        }
    }
    # 精确 gpt-5.5 则保留官方 upgrade 等字段，不能把别名清理规则用于官方条目。
    $exact = New-RelayCatalogModel -Slug 'gpt-5.5'
    Assert-CatalogOfficialCapabilities $exact $template -Exact
    Assert-Equal $exact.relay_official_template.ExactMatch $true
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p $slugs
    Assert-Equal @(Get-RelayCatalogModels $p) $slugs
    $doc = Read-RelayJson $paths.ModelsPath
    foreach ($entry in $doc.models) { Assert-CatalogNoUpgrade $entry }
}

Add-RelayTest 'Catalog' '官方目录和新模型深复制不污染后续模板或其它别名' {
    $official = Get-RelayOfficialCatalog
    $template = @($official.models | Where-Object { $_.slug -ceq 'gpt-5.5' })[0]
    $first = New-RelayCatalogModel -Slug 'first-alias'
    $second = New-RelayCatalogModel -Slug 'second-alias'
    $first.model_messages.instructions_template = 'mutated placeholder'
    $first.supported_reasoning_levels[0].effort = 'mutated'
    $first.truncation_policy.limit = 1
    Assert-CatalogOfficialCapabilities $second $template
    Assert-CatalogOfficialCapabilities (New-RelayCatalogModel -Slug 'third-alias') $template
    # getter 返回对象的外部修改也不能成为后续官方条目的数据源。
    $template.model_messages.instructions_template = 'mutated official document'
    $template.supported_reasoning_levels[0].effort = 'mutated'
    $fresh = New-RelayCatalogModel -Slug 'gpt-5.5'
    Assert-Equal $fresh.model_messages.instructions_template.Length 21459
    Assert-Equal @($fresh.supported_reasoning_levels | ForEach-Object { $_.effort }) @('low', 'medium', 'high', 'xhigh')
    $freshOfficial = @((Get-RelayOfficialCatalog).models | Where-Object { $_.slug -ceq 'gpt-5.5' })[0]
    Assert-CatalogOfficialCapabilities $fresh $freshOfficial -Exact
}

Add-RelayTest 'Catalog' '按 slug 增量合并并保留根字段和自定义 metadata' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('first')
    $doc = Read-RelayJson $paths.ModelsPath
    $doc | Add-Member NoteProperty custom_root ([pscustomobject]@{ keep = @('custom', 42) })
    $doc.models[0].display_name = '自定义显示名称'
    $doc.models[0] | Add-Member NoteProperty custom_metadata ([pscustomobject]@{ nested = @('a', 'b') })
    Write-RelayJson $paths.ModelsPath $doc
    $beforeJson = [IO.File]::ReadAllText($paths.ModelsPath)
    $beforeConfig = [IO.File]::ReadAllText($paths.ConfigPath)
    $null = Add-RelayCodexModels $p @('first', 'new', 'new')
    $after = Read-RelayJson $paths.ModelsPath
    Assert-Equal $after.custom_root $doc.custom_root
    Assert-Equal $after.models[0] $doc.models[0]
    Assert-Equal @(Get-RelayCatalogModels $p) @('first', 'new')
    $jsonBackups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak')
    $configBackups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'relay.config.toml.*.bak')
    Assert-Equal $jsonBackups.Count 1
    Assert-Equal $configBackups.Count 1
    Assert-Equal ([IO.File]::ReadAllText($jsonBackups[0].FullName)) $beforeJson
    Assert-Equal ([IO.File]::ReadAllText($configBackups[0].FullName)) $beforeConfig
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter '*.tmp' -Force).Count 0
    Assert-NoSecretInStore (Get-TestProviderKey $p)
}

Add-RelayTest 'Catalog' '不同 Provider 同名模型独立且 Clear 保留其它 Provider 和用户文件' {
    $p = New-TestProvider; $other = New-TestProvider
    $paths = Add-RelayCodexModels $p @('same', 'extra')
    $otherPaths = Add-RelayCodexModels $other @('same')
    $otherBefore = [IO.File]::ReadAllText($otherPaths.ModelsPath)
    $null = Add-RelayCodexModels $p @('third')
    $userFile = Join-Path $paths.Directory 'user-note.txt'
    [IO.File]::WriteAllText($userFile, 'keep')
    Clear-RelayCodexCatalog $p
    Clear-RelayCodexCatalog $p
    Assert-True ([IO.File]::Exists($userFile))
    Assert-Equal @(Get-RelayCatalogModels $p) @()
    Assert-Equal ([IO.File]::ReadAllText($otherPaths.ModelsPath)) $otherBefore
    Assert-Equal @(Get-RelayCatalogModels $other) @('same')
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Force).Count 1
}

Add-RelayTest 'Catalog' '空批量和控制字符在写入前全部拒绝' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('old')
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    Assert-Throws { Add-RelayCodexModels $p @() } '至少' | Out-Null
    Assert-Throws { Add-RelayCodexModels $p @('new', "bad`nmodel") } '模型 ID' | Out-Null
    Assert-Throws { Add-RelayCodexModels $p @('new', ' ') } '模型 ID' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Force).Count 2
}

Add-RelayTest 'Catalog' '损坏目录和缺官方字段拒绝覆盖原件' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('old')
    foreach ($text in @('{bad', '{"models":[{"slug":"custom"}]}', '{"models":{}}')) {
        [IO.File]::WriteAllText($paths.ModelsPath, $text)
        Assert-Throws { Add-RelayCodexModels $p @('new') } 'JSON|Catalog' | Out-Null
        Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $text
    }
}

Add-RelayTest 'Catalog' '重复现有 slug 拒绝合并以免丢失自定义 metadata' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one')
    $doc = Read-RelayJson $paths.ModelsPath
    $doc.models = @($doc.models[0], $doc.models[0])
    Write-RelayJson $paths.ModelsPath $doc
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    Assert-Throws { Add-RelayCodexModels $p @('two') } '重复 slug' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
}

Add-RelayTest 'Catalog' '含凭据 URL 或独立配置拒绝备份和写入' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one')
    $p.BaseUrl = 'http://user:secret@127.0.0.1/v1'
    Assert-Throws { Add-RelayCodexModels $p @('two') } 'URL' | Out-Null
    $p.BaseUrl = $script:RTBaseUrl + '/v1'
    [IO.File]::WriteAllText($paths.ConfigPath, 'experimental_bearer_token = "local-fake-secret"')
    Assert-Throws { Add-RelayCodexModels $p @('two') } '密钥' | Out-Null
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter '*.bak').Count 0
    Assert-Equal @(Get-RelayCatalogModels $p) @('one')
}

Add-RelayTest 'Catalog' '第二文件提交失败时回滚目录并清除暂存文件' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('old')
    $before = [IO.File]::ReadAllText($paths.ModelsPath)
    $original = ${function:Set-RelayCatalogFile}
    $script:RTCatalogCommitCount = 0
    $script:RTCatalogOriginalCommit = $original
    try {
        function Set-RelayCatalogFile {
            param([string]$StagedPath, [string]$Destination, [string]$BackupPath)
            $script:RTCatalogCommitCount++
            if ($script:RTCatalogCommitCount -eq 2) { throw 'INJECTED_SECOND_COMMIT_FAILURE' }
            & $script:RTCatalogOriginalCommit $StagedPath $Destination $BackupPath
        }
        Assert-Throws { Add-RelayCodexModels $p @('new') } 'INJECTED_SECOND_COMMIT_FAILURE' | Out-Null
        Assert-Equal $script:RTCatalogCommitCount 2
    } finally { Set-Item Function:Set-RelayCatalogFile $original }
    Assert-Equal ([IO.File]::ReadAllText($paths.ModelsPath)) $before
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter '*.tmp' -Force).Count 0
}

Add-RelayTest 'Catalog' '原始七对启动参数不变且追加 catalog override 与模板默认 effort' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('one', 'two')
    $arguments = @(Get-RelayCodexArguments $p 'two')
    $map = Get-TestConfigMap $arguments
    Assert-Equal $arguments.Count 14
    $extended = $arguments + @('--config', ('model_catalog_json=' + (ConvertTo-TomlString $paths.ModelsPath)), '--config', 'model_reasoning_effort="medium"')
    $output = Join-Path $script:RTCaseDirectory 'catalog-argv.json'
    $oldPath = $env:RELAY_TEST_RECORDER_PATH
    $oldName = $env:RELAY_TEST_KEY_NAME
    try {
        $env:RELAY_TEST_RECORDER_PATH = $output
        $env:RELAY_TEST_KEY_NAME = 'CODEX_RELAY_API_KEY'
        Start-RelayCodex $p 'two' -Executable (Get-TestRecorderExe)
        $record = Wait-TestRecorder $output
        Assert-Equal @($record.Arguments) $extended
        Assert-Equal $record.KeyValue (Get-TestProviderKey $p)
        Assert-Equal (Get-TestTomlLiteralValue ($record.Arguments[-3] -split '=', 2)[1]) $paths.ModelsPath
        Assert-Equal $record.Arguments[-1] 'model_reasoning_effort="medium"'
    } finally {
        [Environment]::SetEnvironmentVariable('RELAY_TEST_RECORDER_PATH', $oldPath, 'Process')
        [Environment]::SetEnvironmentVariable('RELAY_TEST_KEY_NAME', $oldName, 'Process')
    }
}

function Invoke-CatalogIsolatedOfficialCli {
    param([string]$Executable, [string]$ModelsPath, [string]$ConfigPath, [string]$Root)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = (@('--no-daemon', 'app-server', '--stdio', '--config', ('model_catalog_json=' + (ConvertTo-TomlString $ModelsPath))) | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' '
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    if ($info.PSObject.Properties['StandardInputEncoding']) { $info.StandardInputEncoding = New-Object Text.UTF8Encoding($false) }
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8; $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    foreach ($name in @($info.EnvironmentVariables.Keys)) {
        if ($name -match '(?i)OPENAI|CODEX|CHATGPT|TOKEN|API_KEY|AUTHORIZATION') { [void]$info.EnvironmentVariables.Remove($name) }
    }
    foreach ($name in @('CODEX_HOME', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TEMP', 'TMP')) {
        $directory = Join-Path $Root $name
        [void][IO.Directory]::CreateDirectory($directory)
        $info.EnvironmentVariables[$name] = $directory
    }
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')) { $info.EnvironmentVariables[$name] = 'http://127.0.0.1:9' }
    $info.EnvironmentVariables['NO_PROXY'] = '127.0.0.1,localhost'
    $info.EnvironmentVariables['OTEL_SDK_DISABLED'] = 'true'
    $info.EnvironmentVariables['DO_NOT_TRACK'] = '1'
    $info.EnvironmentVariables['CODEX_RELAY_API_KEY'] = 'LOCAL_FAKE_CATALOG_KEY_NOT_REAL_AUTH'
    $info.WorkingDirectory = $Root
    # 这是全新隔离 CODEX_HOME/config.toml，不是用户配置。TOML 直接使用 Add 的实际产物。
    [IO.File]::Copy($ConfigPath, (Join-Path $info.EnvironmentVariables['CODEX_HOME'] 'config.toml'))
    $rpc = @(
        @{ id = 1; method = 'initialize'; params = @{ clientInfo = @{ name = 'catalog-test'; version = '1' }; capabilities = @{ experimentalApi = $true } } }
        @{ method = 'initialized' }
        @{ id = 2; method = 'model/list'; params = @{ includeHidden = $true } }
    )
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stderr = $process.StandardError.ReadToEndAsync()
        $lines = New-Object 'Collections.Generic.List[string]'
        $process.StandardInput.WriteLine((ConvertTo-Json -InputObject $rpc[0] -Depth 10 -Compress))
        $process.StandardInput.Flush()
        $initialized = $false; $receivedModels = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(25)
        while ([DateTime]::UtcNow -lt $deadline) {
            $read = $process.StandardOutput.ReadLineAsync()
            $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $read.Wait($remaining)) { break }
            $line = $read.GetAwaiter().GetResult()
            if ($null -eq $line) { break }
            $lines.Add($line)
            $message = $line | ConvertFrom-Json
            if (-not $initialized -and $message.PSObject.Properties['id'] -and $message.id -eq 1) {
                $initialized = $true
                $process.StandardInput.WriteLine((ConvertTo-Json -InputObject $rpc[1] -Depth 10 -Compress))
                $process.StandardInput.WriteLine((ConvertTo-Json -InputObject $rpc[2] -Depth 10 -Compress))
                $process.StandardInput.Flush()
            }
            if ($message.PSObject.Properties['id'] -and $message.id -eq 2) { $receivedModels = $true; break }
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(5000)) { $process.Kill(); [void]$process.WaitForExit(5000) }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = ($lines -join "`n"); Stderr = $stderr.GetAwaiter().GetResult(); ReceivedModels = $receivedModels }
    } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
}

if ($env:RELAY_TEST_CODEX_EXE) {
    Add-RelayTest 'Catalog' '官方0.167.1隔离 CLI 确实加载 Add 产物并拒绝无效 schema' {
        $p = New-TestProvider
        # 随机 slug 证明并非命中官方内置目录，也不涉及任何外网请求。
        $slugs = @(('catalog-' + [guid]::NewGuid().ToString('N')), ('catalog-' + [guid]::NewGuid().ToString('N')))
        Assert-Equal $slugs.Count 2
        $paths = Add-RelayCodexModels $p $slugs
        $root = Join-Path $script:RTCaseDirectory 'official-positive'
        [void][IO.Directory]::CreateDirectory($root)
        $result = Invoke-CatalogIsolatedOfficialCli $env:RELAY_TEST_CODEX_EXE $paths.ModelsPath $paths.ConfigPath $root
        Assert-Equal $result.ExitCode 0 ($result.Stdout + $result.Stderr)
        $messages = @($result.Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
        $reply = @($messages | Where-Object { $_.PSObject.Properties['id'] -and $_.id -eq 2 })
        Assert-Equal $reply.Count 1 ($result.Stdout + $result.Stderr)
        Assert-True ($null -ne $reply[0].PSObject.Properties['result']) ($result.Stdout + $result.Stderr)
        $loaded = @($reply[0].result.data | ForEach-Object { $_.model })
        foreach ($slug in $slugs) { Assert-True ($loaded -ccontains $slug) ('Actual model/list missing catalog slug: ' + $result.Stdout + $result.Stderr) }
        Write-Host ('OFFICIAL CATALOG model/list loaded: ' + ($loaded -join ', '))
        $invalid = Read-RelayJson $paths.ModelsPath
        $invalid.models[0].PSObject.Properties.Remove('shell_type')
        Write-RelayJson $paths.ModelsPath $invalid
        $negativeRoot = Join-Path $script:RTCaseDirectory 'official-negative'
        [void][IO.Directory]::CreateDirectory($negativeRoot)
        $negative = Invoke-CatalogIsolatedOfficialCli $env:RELAY_TEST_CODEX_EXE $paths.ModelsPath $paths.ConfigPath $negativeRoot
        Assert-Match ($negative.Stdout + $negative.Stderr) 'shell_type|catalog' 'Official CLI must report invalid catalog instead of silently using it'
        $negativeMessages = @($negative.Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
        $warning = @($negativeMessages | Where-Object { $_.PSObject.Properties['method'] -and $_.method -ceq 'configWarning' })
        Assert-Match ($negative.Stdout + $negative.Stderr) 'missing field [`'']?shell_type' 'Official parser must identify the removed required field'
        $details = @($warning | ForEach-Object { $_.params.details } | Where-Object { $_ -match 'shell_type' })
        if (-not $details.Count) { $details = @($negative.Stderr.Trim()) }
        Write-Host ('OFFICIAL CATALOG negative: ' + ($details -join ' '))
    }
}
