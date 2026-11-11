# SharedConfig contract suite. Every config access uses an explicit isolated fixture path.
function New-TestSharedFixture {
    param([AllowEmptyString()][string]$Text = '', [switch]$Absent, [switch]$Bom)
    $p = [pscustomobject]@{ Id=('relay_'+[guid]::NewGuid().ToString('N')); Name='fixture "name"'; BaseUrl='https://example.invalid/v1' }
    $path = Join-Path $script:RTCaseDirectory 'fixture-home\config.toml'
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    if (-not $Absent) { [IO.File]::WriteAllText($path,$Text,(New-Object Text.UTF8Encoding([bool]$Bom))) }
    $auth = [pscustomobject]@{ Command='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Args=@('-NoProfile','C:\fixture helper\helper.ps1',$p.Id); TimeoutMs=5000; RefreshIntervalMs=30000; Cwd='C:\fixture helper' }
    return [pscustomobject]@{ Provider=$p; ConfigPath=$path; CatalogPath=(Join-Path $script:RTCaseDirectory 'models.json'); AuthConfig=$auth }
}
function New-TestSharedPlan {
    param($Fixture, [string]$Model='fixture-model')
    New-RelaySharedConfigPlan -Provider $Fixture.Provider -Model $Model -ConfigPath $Fixture.ConfigPath -CatalogPath $Fixture.CatalogPath -AuthConfig $Fixture.AuthConfig
}
function Assert-TestSharedBytes {
    param([byte[]]$Actual,[byte[]]$Expected)
    Assert-Equal ([Convert]::ToBase64String($Actual)) ([Convert]::ToBase64String($Expected)) 'Bytes must match exactly'
}

Add-RelayTest 'SharedConfig' '显式路径优先与CODEX_HOME解析不创建文件' {
    $f=New-TestSharedFixture -Absent
    $old=$env:CODEX_HOME
    try {
        $env:CODEX_HOME=Join-Path $script:RTCaseDirectory 'another-home'
        Assert-Equal (Get-RelaySharedConfigPath) (Join-Path $env:CODEX_HOME 'config.toml')
        Assert-Equal (Get-RelaySharedConfigPath $f.ConfigPath) $f.ConfigPath
        Assert-True (-not [IO.Directory]::Exists($env:CODEX_HOME))
    } finally { $env:CODEX_HOME=$old }
}
Add-RelayTest 'SharedConfig' '无历史引用检查不读取CODEX_HOME' {
    $f=New-TestSharedFixture -Absent
    $old=$env:CODEX_HOME
    try { $env:CODEX_HOME='::invalid-fixture-home::'; Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $false }
    finally { $env:CODEX_HOME=$old }
}
Add-RelayTest 'SharedConfig' '空配置计划不落盘并生成nested auth' {
    $f=New-TestSharedFixture -Absent
    $plan=New-TestSharedPlan $f
    Assert-Equal $plan.OriginalExists $false
    Assert-Equal $plan.OriginalHash '<absent>'
    Assert-Equal $plan.ProviderId $f.Provider.Id
    Assert-True ($plan.Content.Contains('[model_providers.'+$f.Provider.Id+'.auth]'))
    Assert-True ($plan.Content.Contains('refresh_interval_ms = 30000'))
    Assert-True (-not $plan.Content.Contains('env_key'))
    Assert-True (-not [IO.File]::Exists($f.ConfigPath))
    Assert-True (-not [IO.Directory]::Exists((Get-RelaySharedRoot)))
}
Add-RelayTest 'SharedConfig' '保留未知表注释数组quoted dotted与multiline所有字符' {
    $text=@'
# keep root comment
model = 'old' # untouched suffix
model_reasoning_effort = "high"
custom = ["hash # [table]", { a = 1, b = [true, false] }]
"quoted.root".leaf = "untouched"
[profiles.work]
model = "profile-keep"
[mcp_servers."a.b"]
args = [
  "--one", # comment
  "--two",
]
[features]
instructions = """
model = "not-root"
[model_providers.fake]
# not a comment
"""
literal = '''
more [literal] # text
'''
'@
    $f=New-TestSharedFixture $text
    $plan=New-TestSharedPlan $f
    Assert-True ($plan.Content.Contains($text.Substring($text.IndexOf('model_reasoning_effort'))))
    Assert-True ($plan.Content.Contains(' # untouched suffix'))
    Assert-Equal ([IO.File]::ReadAllText($f.ConfigPath)) $text
}
Add-RelayTest 'SharedConfig' 'BOM CRLF备份逐bytes恢复并限制ACL' {
    $text="# secret fixture-local-token`r`nmodel = 'old' # keep`r`n[mcp_servers.x]`r`ncommand = 'node'`r`n"
    $f=New-TestSharedFixture $text -Bom
    $before=[IO.File]::ReadAllBytes($f.ConfigPath)
    $plan=New-TestSharedPlan $f; $r=Invoke-RelaySharedConfigPlan $plan
    Assert-Equal $r.Status 'Applied'
    Assert-True (-not ((ConvertTo-Json $r -Depth 30).Contains('fixture-local-token')))
    Assert-TestSharedBytes ([IO.File]::ReadAllBytes((Join-Path (Get-RelaySharedRoot) $r.BackupFile))) $before
    $acl=Get-Acl -LiteralPath (Get-RelaySharedRoot)
    Assert-True $acl.AreAccessRulesProtected
    $acl=Get-Acl -LiteralPath (Join-Path (Get-RelaySharedRoot) $r.BackupFile)
    Assert-True $acl.AreAccessRulesProtected
    $bytes=[IO.File]::ReadAllBytes($f.ConfigPath)
    Assert-Equal @($bytes[0],$bytes[1],$bytes[2]) @(239,187,191)
    Assert-True (-not $plan.Content.Replace("`r`n",'').Contains("`n"))
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $true
    $restore=Restore-RelaySharedConfig -TransactionId $r.TransactionId
    Assert-Equal $restore.Status 'Restored'
    Assert-TestSharedBytes ([IO.File]::ReadAllBytes($f.ConfigPath)) $before
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $false
}
Add-RelayTest 'SharedConfig' '恢复原本不存在配置并保留manifest历史' {
    $f=New-TestSharedFixture -Absent
    $r=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    Assert-True ([IO.File]::Exists($f.ConfigPath))
    $restore=Restore-RelaySharedConfig -TransactionId latest -ConfigPath $f.ConfigPath
    Assert-Equal $restore.TransactionId $r.TransactionId
    Assert-True (-not [IO.File]::Exists($f.ConfigPath))
    Assert-Equal @(Get-RelaySharedConfigHistory -ConfigPath $f.ConfigPath).Count 1
}
Add-RelayTest 'SharedConfig' '外部编辑使提交和恢复拒写且引用保守保护' {
    $f=New-TestSharedFixture "model='old'`n"
    $plan=New-TestSharedPlan $f
    [IO.File]::AppendAllText($f.ConfigPath,"# external`n")
    Assert-Throws { Invoke-RelaySharedConfigPlan $plan } 'fingerprint' | Out-Null
    $r=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    [IO.File]::AppendAllText($f.ConfigPath,"# external-after`n")
    $edited=[IO.File]::ReadAllBytes($f.ConfigPath)
    Assert-Throws { Restore-RelaySharedConfig $r.TransactionId } 'fingerprint' | Out-Null
    Assert-TestSharedBytes ([IO.File]::ReadAllBytes($f.ConfigPath)) $edited
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $true
    Assert-Throws { Assert-RelayNoSharedReference $f.Provider } 'referenced' | Out-Null
    [IO.File]::WriteAllText($f.ConfigPath,'broken = [')
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $true
}
Add-RelayTest 'SharedConfig' '手动解除所有引用后允许编辑但仅catalog引用仍保护' {
    $f=New-TestSharedFixture -Absent
    $null=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    [IO.File]::WriteAllText($f.ConfigPath,('model_catalog_json = '+(ConvertTo-TomlString $f.CatalogPath)))
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $true
    [IO.File]::WriteAllText($f.ConfigPath,'model = "unrelated"')
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $false
}
Add-RelayTest 'SharedConfig' '重复接入owned auth无重复表且额外headers原文保留' {
    $f=New-TestSharedFixture -Absent
    $r=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    $extra="`n[model_providers.$($f.Provider.Id).http_headers]`nX-Custom = 'keep # exact'`n"
    [IO.File]::AppendAllText($f.ConfigPath,$extra)
    $plan=New-TestSharedPlan $f -Model 'second'
    Assert-True ($plan.Content.Contains($extra))
    $r2=Invoke-RelaySharedConfigPlan $plan
    Assert-Equal $r2.Status 'Applied'
    $again=New-TestSharedPlan $f -Model 'second'
    Assert-TestSharedBytes $again.NewBytes ([IO.File]::ReadAllBytes($f.ConfigPath))
}
Add-RelayTest 'SharedConfig' '已有provider非auth字段安全合并保留额外设置' {
    $f=New-TestSharedFixture -Absent
    $text="[model_providers.$($f.Provider.Id)]`nname = $(ConvertTo-TomlString $f.Provider.Name) # preserve`nbase_url = '$($f.Provider.BaseUrl)'`ncustom = [1,2,3]`n[model_providers.$($f.Provider.Id).http_headers]`nX-Test = 'keep'`n"
    [IO.File]::WriteAllText($f.ConfigPath,$text)
    $plan=New-TestSharedPlan $f
    Assert-True ($plan.Content.Contains("custom = [1,2,3]`n"))
    Assert-True ($plan.Content.Contains("X-Test = 'keep'`n"))
    Assert-True ($plan.Content.Contains(' # preserve'))
}
Add-RelayTest 'SharedConfig' '激活冲突逐个拒绝不改原文' {
    foreach ($key in @('profile','oss_provider','openai_base_url','forced_login_method')) {
        $text=$key+' = "chatgpt"'
        $f=New-TestSharedFixture $text
        Assert-Throws { New-TestSharedPlan $f } 'conflict' | Out-Null
        Assert-Equal ([IO.File]::ReadAllText($f.ConfigPath)) $text
    }
}
Add-RelayTest 'SharedConfig' '外部拥有auth env token不接管且诊断不泄露内容' {
    foreach ($field in @('env_key = "fixture-secret"','experimental_bearer_token = "fixture-secret"','auth.command = "fixture-secret"')) {
        $f=New-TestSharedFixture -Absent
        $text='[model_providers.'+$f.Provider.Id+"]`n"+$field
        [IO.File]::WriteAllText($f.ConfigPath,$text)
        $e=Assert-Throws { New-TestSharedPlan $f } 'owned|unsupported' 
        Assert-True (-not ([string]$e).Contains('fixture-secret'))
        Assert-Equal ([IO.File]::ReadAllText($f.ConfigPath)) $text
    }
}
Add-RelayTest 'SharedConfig' 'owned auth被手改后拒绝再次接入' {
    $f=New-TestSharedFixture -Absent
    $null=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    $text=[IO.File]::ReadAllText($f.ConfigPath).Replace('timeout_ms = 5000','timeout_ms = 7000')
    [IO.File]::WriteAllText($f.ConfigPath,$text)
    Assert-Throws { New-TestSharedPlan $f } 'owned|externally' | Out-Null
}
Add-RelayTest 'SharedConfig' '重复非法及复杂目标语法failclosed不落盘' {
    $cases=@('model="a"'+"`n"+'model="b"', 'model = "unfinished', 'a = tru', 'a = [1 2]', 'a = {x=1,x=2}', '[x]'+"`n"+'[x]', 'model.foo="x"', 'model_providers = {}', 'model_provider.name="x"', 'a = "bad\q"')
    foreach ($text in $cases) {
        $f=New-TestSharedFixture $text
        Assert-Throws { New-TestSharedPlan $f } 'TOML|unsupported|Complex' | Out-Null
        Assert-Equal ([IO.File]::ReadAllText($f.ConfigPath)) $text
    }
}
Add-RelayTest 'SharedConfig' 'quoted root keys可编辑而dotted目标明确拒绝' {
    $f=New-TestSharedFixture '"model" = "old" # exact'
    $plan=New-TestSharedPlan $f
    Assert-True ($plan.Content.Contains('"model" = "fixture-model" # exact'))
    $f=New-TestSharedFixture -Absent
    [IO.File]::WriteAllText($f.ConfigPath,('model_providers.'+$f.Provider.Id+'.name = "old"'))
    Assert-Throws { New-TestSharedPlan $f } 'Complex|owned' | Out-Null
}
Add-RelayTest 'SharedConfig' 'UTF16及损坏UTF8拒绝且不改bytes' {
    $f=New-TestSharedFixture -Absent
    foreach ($bytes in @(([Text.Encoding]::Unicode.GetPreamble()+[Text.Encoding]::Unicode.GetBytes('model="x"')), ([byte[]]@(255,255,255)))) {
        [IO.File]::WriteAllBytes($f.ConfigPath,$bytes)
        Assert-Throws { New-TestSharedPlan $f } 'UTF-8' | Out-Null
        Assert-TestSharedBytes ([IO.File]::ReadAllBytes($f.ConfigPath)) $bytes
    }
}
Add-RelayTest 'SharedConfig' '同路径不同DataDirectory计划防止stale覆盖' {
    $f=New-TestSharedFixture -Absent
    $plan1=New-TestSharedPlan $f
    $data1=$script:RelayDataDirectory
    $data2=Join-Path $script:RTCaseDirectory 'second-manager'
    try {
        $script:RelayDataDirectory=$data2
        $plan2=New-TestSharedPlan $f -Model 'other'
        $null=Invoke-RelaySharedConfigPlan $plan2
        $script:RelayDataDirectory=$data1
        Assert-Throws { Invoke-RelaySharedConfigPlan $plan1 } 'fingerprint' | Out-Null
    } finally { $script:RelayDataDirectory=$data1 }
}
Add-RelayTest 'SharedConfig' 'owned非auth受管字段手改后拒绝覆盖' {
    $f=New-TestSharedFixture -Absent
    $null=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    $text=[IO.File]::ReadAllText($f.ConfigPath).Replace('wire_api = "responses"','wire_api = "chat"')
    [IO.File]::WriteAllText($f.ConfigPath,$text)
    Assert-Throws { New-TestSharedPlan $f } 'externally edited' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($f.ConfigPath)) $text
}
Add-RelayTest 'SharedConfig' '未拥有同ID身份冲突不接管' {
    $f=New-TestSharedFixture -Absent
    $text='[model_providers.'+$f.Provider.Id+"]`nname = 'other-owner'`nbase_url = 'https://other.invalid'`n"
    [IO.File]::WriteAllText($f.ConfigPath,$text)
    Assert-Throws { New-TestSharedPlan $f } 'owned|takeover' | Out-Null
    Assert-Equal ([IO.File]::ReadAllText($f.ConfigPath)) $text
}
Add-RelayTest 'SharedConfig' 'TOML键严格区分大小写并验证新增字段真实section' {
    $f=New-TestSharedFixture "MODEL = 'untouched'`nPROFILE = 'not-active-profile'`n"
    [IO.File]::AppendAllText($f.ConfigPath,('[model_providers.'+$f.Provider.Id+']'))
    $plan=New-TestSharedPlan $f
    Assert-True ($plan.Content.Contains("MODEL = 'untouched'"))
    Assert-True ($plan.Content.Contains("PROFILE = 'not-active-profile'"))
    $doc=[RelaySharedToml.Document]::Parse($plan.Content)
    $sep=[string][char]31
    $providerPrefix='model_providers'+$sep+$f.Provider.Id+$sep
    $byPath=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach($e in $doc.Entries){$byPath.Add($e.Path,$e)}
    foreach($field in @('name','base_url','wire_api','requires_openai_auth')) { Assert-True ($byPath.ContainsKey($providerPrefix+$field)) }
    foreach($field in @('command','args','timeout_ms','refresh_interval_ms','cwd')) { Assert-True ($byPath.ContainsKey($providerPrefix+'auth'+$sep+$field)) }
    Assert-True ($byPath.ContainsKey('model'))
    Assert-True ($byPath.ContainsKey('MODEL'))
}
Add-RelayTest 'SharedConfig' '无效表ancestor覆盖拒绝' {
    $f=New-TestSharedFixture "[a.b]`nx=1`n[a]`nb={}"
    Assert-Throws { New-TestSharedPlan $f } 'TOML' | Out-Null
}
Add-RelayTest 'SharedConfig' 'Prepared潜在提交证据仍保护引用' {
    $f=New-TestSharedFixture -Absent
    $r=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    $r.Status='Prepared';$r.AppliedAtUtc=$null
    Write-RelayJson (Join-Path (Get-RelaySharedRoot) ($r.TransactionId+'.json')) $r
    Assert-Equal (Test-RelayProviderSharedReference $f.Provider) $true
}
Add-RelayTest 'SharedConfig' '备份被改拒绝恢复' {
    $f=New-TestSharedFixture 'model="old"'
    $r=Invoke-RelaySharedConfigPlan (New-TestSharedPlan $f)
    [IO.File]::WriteAllText((Join-Path (Get-RelaySharedRoot) $r.BackupFile),'tampered')
    Assert-Throws { Restore-RelaySharedConfig $r.TransactionId } 'backup fingerprint' | Out-Null
}
