# Official template contracts. Only isolated Shared.ps1 fixtures are written; no .tools/runtime source dependency.
# Get-RelayOfficialCatalog is the public source oracle; template provenance metadata is deliberately not assumed.
function Get-OfficialTemplateTestModel {
    param([string]$Slug = 'gpt-5.5')
    $matches = @((Get-RelayOfficialCatalog).models | Where-Object { $_.slug -ceq $Slug })
    Assert-Equal $matches.Count 1 ('Official source must contain exactly one ' + $Slug)
    return $matches[0]
}
function Assert-OfficialTemplateTestFields {
    param($Actual, $Expected, [string[]]$Except = @())
    foreach ($property in $Expected.PSObject.Properties) {
        if ($Except -ccontains $property.Name) { continue }
        Assert-True ($null -ne $Actual.PSObject.Properties[$property.Name]) ('Missing official field: ' + $property.Name)
        # null experimental tools is normalized to the required JSON array by the public constructor.
        if ($property.Name -ceq 'experimental_supported_tools' -and $null -eq $property.Value) {
            Assert-Equal $Actual.experimental_supported_tools @()
        } else { Assert-Equal $Actual.PSObject.Properties[$property.Name].Value $property.Value ('Official field differs: ' + $property.Name) }
    }
}
function Get-OfficialTemplateTestHash {
    param($Document)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $json = ConvertTo-Json -InputObject $Document -Depth 100 -Compress
        return [Convert]::ToBase64String($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)))
    } finally { $hash.Dispose() }
}
function Get-OfficialTemplateTestBytes {
    param([string]$Path)
    return [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))
}
function Set-OfficialTemplateTestPlaceholder {
    param($Paths)
    $document = Read-RelayJson $Paths.ModelsPath
    foreach ($entry in $document.models) {
        $entry.shell_type = 'disabled'
        $entry.input_modalities = @('text')
        $entry.node_repl_disabled = $true
        $entry.include_apps_usage_instructions = $false
        $entry.include_skills_usage_instructions = $false
        $entry.include_plugin_usage_instructions = $false
        $entry.model_messages = [pscustomobject]@{ instructions_template = 'You are a coding assistant.' }
        $entry.supported_reasoning_levels = @()
        $entry.default_reasoning_level = $null
        $entry | Add-Member NoteProperty context_window 12345 -Force
    }
    Write-RelayJson $Paths.ModelsPath $document
    return $document
}
function Assert-OfficialTemplateTestPaths {
    param($Actual, $Expected)
    foreach ($field in @('Directory', 'ModelsPath', 'ConfigPath')) {
        Assert-True ($null -ne $Actual.PSObject.Properties[$field]) ('Missing returned path ' + $field)
        Assert-Equal $Actual.PSObject.Properties[$field].Value $Expected.PSObject.Properties[$field].Value
    }
}

Add-RelayTest 'OfficialTemplates' '官方 document 完整 schema、精确模板 clone 与只读 source' {
    $source = Get-RelayOfficialCatalog
    Assert-True ($source.models -is [array]) 'Official document must expose a models array'
    Assert-True ($source.models.Count -gt 1)
    $before = Get-OfficialTemplateTestHash $source
    foreach ($official in $source.models) {
        $model = New-RelayCatalogModel -Slug $official.slug
        Assert-OfficialTemplateTestFields $model $official
        Assert-RelayCatalogDocument ([pscustomobject]@{ models = @($model) })
    }
    $model = New-RelayCatalogModel -Slug 'gpt-5.5'
    Assert-Equal $model.shell_type 'shell_command'
    Assert-True ($model.input_modalities -ccontains 'image')
    Assert-Equal $model.node_repl_disabled $false
    foreach ($field in @('include_apps_usage_instructions', 'include_skills_usage_instructions', 'include_plugin_usage_instructions')) { Assert-Equal $model.PSObject.Properties[$field].Value $true }
    Assert-True ($model.model_messages.instructions_template.Length -gt 10000) 'Official long prompt must not be reduced to a placeholder'
    foreach ($required in @('display_name', 'supported_reasoning_levels', 'shell_type', 'visibility', 'supported_in_api', 'priority', 'support_verbosity', 'truncation_policy', 'experimental_supported_tools', 'model_messages')) {
        $invalid = New-RelayCatalogModel -Slug 'gpt-5.5'
        $invalid.PSObject.Properties.Remove($required)
        Assert-Throws { Assert-RelayCatalogDocument ([pscustomobject]@{ models = @($invalid) }) } | Out-Null
    }
    $model.model_messages.instructions_template = 'MUTATED COPY'
    $model.input_modalities[0] = 'MUTATED COPY'
    Assert-Equal (Get-OfficialTemplateTestHash $source) $before 'Constructor mutated the supplied official source object'
    Assert-Equal (Get-OfficialTemplateTestHash (Get-RelayOfficialCatalog)) $before 'Official source changed after mutating a clone'
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '未知及大小写不同 ID 使用完整 GPT5.5 fallback 且绝不改写 route' {
    $official = Get-OfficialTemplateTestModel
    foreach ($slug in @('vendor/Custom-Model', 'GPT-5.5', 'gpt-5.5-custom', '未知模型 "quoted" C:\route\')) {
        $model = New-RelayCatalogModel -Slug $slug
        Assert-Equal $model.slug $slug
        Assert-Equal $model.display_name $slug 'Fallback must not impersonate an official model display name'
        Assert-OfficialTemplateTestFields $model $official @('slug', 'display_name', 'description', 'upgrade', 'availability_nux', 'available_in_plans')
        Assert-True (-not $model.PSObject.Properties['upgrade'] -or $null -eq $model.upgrade) 'Fallback must not inherit official migration/upgrade routes'
        Assert-Match $model.description '模板|template'
    }
    $p = New-TestProvider
    $slugs = @('vendor/custom', 'GPT-5.5', 'gpt-5.5')
    $paths = Add-RelayCodexModels $p $slugs
    Assert-Equal @(Get-RelayCatalogModels $p) $slugs
    foreach ($entry in (Read-RelayJson $paths.ModelsPath).models) { Assert-Equal $entry.shell_type 'shell_command' }
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '全部升级覆盖旧 placeholder、完整备份且保留 custom metadata 和未知显示名称' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('gpt-5.5', 'vendor/custom')
    $doc = Set-OfficialTemplateTestPlaceholder $paths
    $doc | Add-Member NoteProperty custom_root ([pscustomobject]@{ keep = @('root', 42) })
    foreach ($entry in $doc.models) { $entry | Add-Member NoteProperty custom_metadata ([pscustomobject]@{ nested = @('keep', 17); enabled = $true }) }
    $doc.models[0].display_name = 'old official display'
    $doc.models[1].display_name = '用户自己的显示名称'
    $doc.models[1] | Add-Member NoteProperty upgrade ([pscustomobject]@{ model = 'wrong-route'; migration_markdown = 'stale migration' }) -Force
    Write-RelayJson $paths.ModelsPath $doc
    $before = Get-OfficialTemplateTestBytes $paths.ModelsPath
    $configBefore = Get-OfficialTemplateTestBytes $paths.ConfigPath
    $sourceBefore = Get-OfficialTemplateTestHash (Get-RelayOfficialCatalog)
    $result = Update-RelayCatalogOfficialTemplates -Provider $p
    Assert-OfficialTemplateTestPaths $result $paths
    $after = Read-RelayJson $paths.ModelsPath
    Assert-Equal $after.custom_root $doc.custom_root
    Assert-Equal @($after.models | ForEach-Object { $_.slug }) @('gpt-5.5', 'vendor/custom')
    Assert-OfficialTemplateTestFields $after.models[0] (Get-OfficialTemplateTestModel)
    Assert-OfficialTemplateTestFields $after.models[1] (New-RelayCatalogModel -Slug 'vendor/custom') @('display_name')
    foreach ($entry in $after.models) { Assert-Equal $entry.custom_metadata $doc.models[0].custom_metadata }
    Assert-Equal $after.models[1].display_name '用户自己的显示名称'
    Assert-True (-not $after.models[1].PSObject.Properties['upgrade'] -or $null -eq $after.models[1].upgrade)
    $backups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak')
    Assert-Equal $backups.Count 1
    Assert-Equal (Get-OfficialTemplateTestBytes $backups[0].FullName) $before 'Backup must preserve original bytes exactly'
    Assert-Equal (Get-OfficialTemplateTestBytes $paths.ConfigPath) $configBefore
    Assert-Equal (Get-OfficialTemplateTestHash (Get-RelayOfficialCatalog)) $sourceBefore
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter '*.tmp' -Force).Count 0
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '选择升级只改目标且显式空 Models 默认全部' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('selected', 'untouched')
    $old = Set-OfficialTemplateTestPlaceholder $paths
    $result = Update-RelayCatalogOfficialTemplates -Provider $p -Models @('selected')
    Assert-OfficialTemplateTestPaths $result $paths
    $doc = Read-RelayJson $paths.ModelsPath
    Assert-OfficialTemplateTestFields $doc.models[0] (New-RelayCatalogModel -Slug 'selected')
    Assert-Equal $doc.models[1] $old.models[1] 'Unselected model changed'
    $result = Update-RelayCatalogOfficialTemplates -Provider $p -Models @()
    Assert-OfficialTemplateTestPaths $result $paths
    foreach ($entry in (Read-RelayJson $paths.ModelsPath).models) { Assert-OfficialTemplateTestFields $entry (New-RelayCatalogModel -Slug $entry.slug) }
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '无 caller settings 也保留已有 API accepted effort 等级描述及默认值' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('accepted', 'empty-placeholder')
    $doc = Set-OfficialTemplateTestPlaceholder $paths
    $doc.models[0].supported_reasoning_levels = @(
        [pscustomobject]@{ effort = 'low'; description = 'API accepted; 不证明实际生效。' },
        [pscustomobject]@{ effort = 'max'; description = 'API accepted fixture; REQUEST_ACCEPTANCE_ONLY' }
    )
    $doc.models[0].default_reasoning_level = 'max'
    $doc.models[0] | Add-Member NoteProperty relay_effort_evidence ([pscustomobject]@{ source = 'API_ACCEPTED'; tested = $true })
    Write-RelayJson $paths.ModelsPath $doc
    $null = Update-RelayCatalogOfficialTemplates -Provider $p
    $after = Read-RelayJson $paths.ModelsPath
    Assert-Equal $after.models[0].supported_reasoning_levels $doc.models[0].supported_reasoning_levels
    Assert-Equal $after.models[0].default_reasoning_level 'max'
    Assert-OfficialTemplateTestFields $after.models[0] (New-RelayCatalogModel -Slug 'accepted') @('supported_reasoning_levels', 'default_reasoning_level')
    Assert-Equal $after.models[1].supported_reasoning_levels (Get-OfficialTemplateTestModel).supported_reasoning_levels 'Old empty effort placeholder must receive official defaults'
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '实际 API evidence cache 支持的非空 effort 不被模板默认值覆盖且 cache 只读' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('cache-backed')
    $doc = Set-OfficialTemplateTestPlaceholder $paths
    $doc.models[0].supported_reasoning_levels = @([pscustomobject]@{ effort = 'max'; description = 'Fixture-local verified choice' })
    $doc.models[0].default_reasoning_level = 'max'
    Write-RelayJson $paths.ModelsPath $doc
    $cache = Get-RelayCachePath -Provider $p -Kind effort
    Write-RelayJson $cache @([pscustomobject]@{ ProviderId = $p.Id; Model = 'cache-backed'; ReasoningEffort = 'max'; Status = 'COMPATIBLE'; Evidence = 'REQUEST_ACCEPTANCE_ONLY'; TestedAt = [DateTime]::UtcNow.ToString('o'); Message = 'fixture'; Events = @('response.completed') })
    $cacheBefore = Get-OfficialTemplateTestBytes $cache
    $null = Update-RelayCatalogOfficialTemplates -Provider $p
    $after = Read-RelayJson $paths.ModelsPath
    Assert-Equal $after.models[0].supported_reasoning_levels $doc.models[0].supported_reasoning_levels
    Assert-Equal $after.models[0].default_reasoning_level 'max'
    Assert-Equal (Get-OfficialTemplateTestBytes $cache) $cacheBefore
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '未知目标或大小写差异使整个 batch 写入及备份前拒绝' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('known')
    $null = Set-OfficialTemplateTestPlaceholder $paths
    $before = Get-OfficialTemplateTestBytes $paths.ModelsPath
    $configBefore = Get-OfficialTemplateTestBytes $paths.ConfigPath
    $filesBefore = @(Get-ChildItem -LiteralPath $paths.Directory -Force | ForEach-Object { $_.Name })
    foreach ($bad in @('missing', 'KNOWN')) {
        Assert-Throws { Update-RelayCatalogOfficialTemplates -Provider $p -Models @('known', $bad) } | Out-Null
        Assert-Equal (Get-OfficialTemplateTestBytes $paths.ModelsPath) $before
        Assert-Equal (Get-OfficialTemplateTestBytes $paths.ConfigPath) $configBefore
        Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Force | ForEach-Object { $_.Name }) $filesBefore
    }
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '相同 slug 的 Provider 隔离且升级不访问任何模型或 Responses API' {
    $p = New-TestProvider; $other = New-TestProvider
    $paths = Add-RelayCodexModels $p @('same')
    $otherPaths = Add-RelayCodexModels $other @('same')
    $null = Set-OfficialTemplateTestPlaceholder $paths
    $null = Set-OfficialTemplateTestPlaceholder $otherPaths
    $otherBefore = Get-OfficialTemplateTestBytes $otherPaths.ModelsPath
    $otherConfig = Get-OfficialTemplateTestBytes $otherPaths.ConfigPath
    $original = ${function:New-RelayHttpClient}
    try {
        function New-RelayHttpClient { throw 'OFFICIAL_TEMPLATE_MUST_NOT_OPEN_HTTP_CLIENT' }
        $null = Update-RelayCatalogOfficialTemplates -Provider $p
    } finally { Set-Item Function:New-RelayHttpClient $original }
    Assert-Equal (Read-RelayJson $paths.ModelsPath).models[0].shell_type 'shell_command'
    Assert-Equal (Get-OfficialTemplateTestBytes $otherPaths.ModelsPath) $otherBefore
    Assert-Equal (Get-OfficialTemplateTestBytes $otherPaths.ConfigPath) $otherConfig
    Assert-Equal @(Get-ChildItem -LiteralPath $otherPaths.Directory -Filter '*.bak').Count 0
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' 'shared config 已引用时可原路径升级不删除目录且 config hash 不变' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('shared-model')
    $null = Set-OfficialTemplateTestPlaceholder $paths
    $config = Join-Path $script:RTCaseDirectory 'isolated-home\config.toml'
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($config))
    [IO.File]::WriteAllText($config, "# fixture shared config`r`nmodel = 'previous'`r`n", (New-Object Text.UTF8Encoding($true)))
    $plan = New-RelaySharedConfigPlan -Provider $p -Model 'shared-model' -ConfigPath $config -CatalogPath $paths.ModelsPath -AuthConfig (Get-RelayCredentialConfig $p)
    $null = Invoke-RelaySharedConfigPlan $plan
    Assert-Equal (Test-RelayProviderSharedReference $p) $true
    $before = Get-OfficialTemplateTestBytes $config
    $hashBefore = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
    $configBefore = Get-OfficialTemplateTestBytes $paths.ConfigPath
    $result = Update-RelayCatalogOfficialTemplates -Provider $p
    Assert-OfficialTemplateTestPaths $result $paths
    Assert-Equal (Get-OfficialTemplateTestBytes $config) $before
    Assert-Equal (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash $hashBefore
    Assert-Equal (Get-OfficialTemplateTestBytes $paths.ConfigPath) $configBefore
    Assert-Equal (Test-RelayProviderSharedReference $p) $true
    Assert-True ([IO.File]::Exists($paths.ModelsPath))
    Assert-Equal @(Get-RelayCatalogModels $p) @('shared-model')
    Assert-Match ([IO.File]::ReadAllText($config)) ([regex]::Escape((ConvertTo-TomlString $paths.ModelsPath)))
    Assert-Equal (Read-RelayJson $paths.ModelsPath).models[0].shell_type 'shell_command'
    Assert-Equal @(Get-MockRequests).Count 0
}

Add-RelayTest 'OfficialTemplates' '升级复用 StoreLock 和 WriteJSON 且注入写失败保留原文件与逐字节备份' {
    $p = New-TestProvider
    $paths = Add-RelayCodexModels $p @('old')
    $null = Set-OfficialTemplateTestPlaceholder $paths
    $before = Get-OfficialTemplateTestBytes $paths.ModelsPath
    $originalLock = ${function:Invoke-RelayStoreLock}
    $originalWrite = ${function:Write-RelayJson}
    $state = [pscustomobject]@{ Locks = 0; Writes = 0; InLock = $false; Action = $null }
    try {
        function Invoke-RelayStoreLock {
            param([scriptblock]$Action)
            $state.Locks++
            # The real lock also has an $Action parameter; use shared fixture state to avoid dynamic-scope recursion.
            $state.Action = $Action
            & $originalLock { $state.InLock = $true; try { & $state.Action } finally { $state.InLock = $false } }
        }
        function Write-RelayJson {
            param($Path, $Value)
            Assert-True $state.InLock 'Official template write occurred outside Invoke-RelayStoreLock'
            $state.Writes++
            throw 'INJECTED_OFFICIAL_TEMPLATE_WRITE_FAILURE'
        }
        Assert-Throws { Update-RelayCatalogOfficialTemplates -Provider $p } 'INJECTED_OFFICIAL_TEMPLATE_WRITE_FAILURE' | Out-Null
        Assert-Equal $state.Locks 1
        Assert-Equal $state.Writes 1
    } finally {
        Set-Item Function:Invoke-RelayStoreLock $originalLock
        Set-Item Function:Write-RelayJson $originalWrite
    }
    Assert-Equal (Get-OfficialTemplateTestBytes $paths.ModelsPath) $before
    $backups = @(Get-ChildItem -LiteralPath $paths.Directory -Filter 'models.json.*.bak')
    Assert-Equal $backups.Count 1
    Assert-Equal (Get-OfficialTemplateTestBytes $backups[0].FullName) $before
    Assert-Equal @(Get-ChildItem -LiteralPath $paths.Directory -Filter '*.tmp' -Force).Count 0
    Assert-Equal @(Get-MockRequests).Count 0
}
