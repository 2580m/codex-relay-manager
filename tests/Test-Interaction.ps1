#requires -Version 5.1
# Keep the real selectors and Confirm-RelayAction: drive their Read-Host calls instead.
function Invoke-InteractionScenario {
    param(
        [string[]]$Answers = @(),
        [Parameter(Mandatory)][scriptblock]$Body,
        [string[]]$Models = @('model-one', 'model-two', 'model-three'),
        [object[]]$Records = @(),
        [string]$ResponseStatus = 'COMPATIBLE',
        [object[]]$History = @(),
        [string]$PreviewError = '',
        [string]$RestoreError = '',
        [object[]]$EffortSettings = @(),
        [string]$EffortError = ''
    )
    $state = [pscustomobject]@{
        Provider = [pscustomobject]@{ Id = 'interaction-only'; Name = '交互测试'; BaseUrl = 'https://interaction.invalid/v1' }
        Models = $Models
        Records = $Records
        ResponseStatus = $ResponseStatus
        Queue = (New-Object Collections.Queue)
        Prompts = (New-Object Collections.ArrayList)
        Output = (New-Object Collections.ArrayList)
        Calls = (New-Object Collections.ArrayList)
        Imports = (New-Object Collections.ArrayList)
        Previews = (New-Object Collections.ArrayList)
        EffortPreviews = (New-Object Collections.ArrayList)
        EffortSettings = $EffortSettings
        EffortError = $EffortError
        Restores = (New-Object Collections.ArrayList)
        Events = (New-Object Collections.ArrayList)
        History = $History
        PreviewError = $PreviewError
        RestoreError = $RestoreError
        # These objects are memory-only contracts, never actual config/credential paths.
        AuthConfig = [pscustomobject]@{ Command = 'interaction-only-helper'; Args = @('fixture'); TimeoutMs = 15000; RefreshIntervalMs = 300000; Cwd = 'interaction-only' }
        Plan = $null
        HistoryReads = 0
    }
    foreach ($answer in $Answers) { $state.Queue.Enqueue($answer) }
    # Main-library functions resolve commands dynamically in the runner's script scope.
    # A mock local only to this helper would not be visible to those functions.
    $mocks = @{
        'Read-Host' = {
            param([string]$Prompt)
            if (-not $script:RTInteractionState.Queue.Count) { throw ('Interaction input queue exhausted: ' + $Prompt) }
            $answer = [string]$script:RTInteractionState.Queue.Dequeue()
            [void]$script:RTInteractionState.Events.Add('Read')
            [void]$script:RTInteractionState.Prompts.Add([pscustomobject]@{
                Text = $Prompt; Answer = $answer; CallsBefore = $script:RTInteractionState.Calls.Count
                ImportsBefore = $script:RTInteractionState.Imports.Count
                RestoresBefore = $script:RTInteractionState.Restores.Count
                PreviewsBefore = $script:RTInteractionState.Previews.Count
                EffortPreviewsBefore = $script:RTInteractionState.EffortPreviews.Count
            })
            return $answer
        }
        'Write-RelaySafe' = {
            param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray)
            [void]$script:RTInteractionState.Output.Add([pscustomobject]@{ Text = $Text; Color = $Color })
        }
        'Write-Host' = { param($Object, $ForegroundColor, $BackgroundColor, [switch]$NoNewline, $Separator) }
        'Get-RelayModelCache' = {
            param($Provider)
            Assert-Equal $Provider.Id $script:RTInteractionState.Provider.Id 'Cache lookup received the wrong provider'
            return [pscustomobject]@{ Models = $script:RTInteractionState.Models }
        }
        'Get-RelayCompatibility' = {
            param($Provider)
            Assert-Equal $Provider.Id $script:RTInteractionState.Provider.Id 'History lookup received the wrong provider'
            return $script:RTInteractionState.Records
        }
        'Test-RelayResponse' = {
            param($Provider, [string]$Model)
            [void]$script:RTInteractionState.Calls.Add([pscustomobject]@{
                ProviderId = $Provider.Id; Model = $Model; ReadCount = $script:RTInteractionState.Prompts.Count
            })
            return [pscustomobject]@{ Status = $script:RTInteractionState.ResponseStatus; Message = '模拟结果'; Events = @() }
        }
        'Get-RelayCatalogPaths' = {
            param($Provider)
            Assert-Equal $Provider.Id $script:RTInteractionState.Provider.Id 'Catalog paths received the wrong provider'
            return [pscustomobject]@{ ModelsPath = 'interaction-only-models.json'; ConfigPath = 'interaction-only-config.toml' }
        }
        # Never enter the real effort UI or consume extra answers in legacy cases.
        'Select-RelayEffortSettingsUi' = {
            param($Provider, [string[]]$Models)
            Assert-True ([object]::ReferenceEquals($Provider, $script:RTInteractionState.Provider)) 'Effort preview received the wrong provider'
            [void]$script:RTInteractionState.Events.Add('EffortPreview')
            [void]$script:RTInteractionState.EffortPreviews.Add([pscustomobject]@{
                Provider = $Provider; Models = @($Models); Settings = $script:RTInteractionState.EffortSettings
                ReadCount = $script:RTInteractionState.Prompts.Count
            })
            if ($script:RTInteractionState.EffortError) { throw $script:RTInteractionState.EffortError }
            return $script:RTInteractionState.EffortSettings
        }
        'Get-RelayCredentialConfig' = {
            param($Provider)
            Assert-Equal $Provider.Id $script:RTInteractionState.Provider.Id 'Credential preview received the wrong provider'
            [void]$script:RTInteractionState.Events.Add('CredentialPreview')
            return $script:RTInteractionState.AuthConfig
        }
        'New-RelaySharedConfigPlan' = {
            param($Provider, [string]$Model, [string]$CatalogPath, $AuthConfig, $EffortSettings)
            Assert-Equal $Provider.Id $script:RTInteractionState.Provider.Id 'Shared preview received the wrong provider'
            Assert-Equal $CatalogPath 'interaction-only-models.json'
            Assert-True ([object]::ReferenceEquals($AuthConfig, $script:RTInteractionState.AuthConfig)) 'UI must pass the credential preview unchanged'
            [void]$script:RTInteractionState.Events.Add('SharedPreview')
            $plan = [pscustomobject]@{
                ProviderId = $Provider.Id; Model = $Model; CatalogPath = $CatalogPath
                AuthConfig = $AuthConfig; EffortSettings = $EffortSettings; ConfigPath = 'interaction-only-shared-config.toml'
            }
            $script:RTInteractionState.Plan = $plan
            [void]$script:RTInteractionState.Previews.Add([pscustomobject]@{
                Plan = $plan; ReadCount = $script:RTInteractionState.Prompts.Count
                ImportsBefore = $script:RTInteractionState.Imports.Count
            })
            if ($script:RTInteractionState.PreviewError) { throw $script:RTInteractionState.PreviewError }
            return $plan
        }
        'Publish-RelayCodexModels' = {
            param($Provider, [string[]]$Models, $Plan, $EffortSettings)
            Assert-True ([object]::ReferenceEquals($Plan, $script:RTInteractionState.Plan)) 'UI must publish the exact previewed plan'
            Assert-True ($Models -ccontains $Plan.Model) 'Default model must be one of the explicitly selected models'
            Assert-Equal $script:RTInteractionState.Prompts[-1].Answer 'YES' 'Publish requires final exact YES'
            [void]$script:RTInteractionState.Events.Add('Publish')
            [void]$script:RTInteractionState.Imports.Add([pscustomobject]@{
                ProviderId = $Provider.Id; Models = @($Models); Plan = $Plan; EffortSettings = $EffortSettings
                ReadCount = $script:RTInteractionState.Prompts.Count
            })
            return [pscustomobject]@{ MockOnly = $true; TransactionId = 'interaction-only-transaction' }
        }
        'Get-RelaySharedConfigHistory' = {
            $script:RTInteractionState.HistoryReads++
            [void]$script:RTInteractionState.Events.Add('History')
            return $script:RTInteractionState.History
        }
        'Restore-RelaySharedConfig' = {
            param([string]$TransactionId)
            Assert-Equal $script:RTInteractionState.Prompts[-1].Answer 'YES' 'Restore requires final exact YES'
            [void]$script:RTInteractionState.Events.Add('Restore')
            [void]$script:RTInteractionState.Restores.Add([pscustomobject]@{
                TransactionId = $TransactionId; ReadCount = $script:RTInteractionState.Prompts.Count
            })
            if ($script:RTInteractionState.RestoreError) { throw $script:RTInteractionState.RestoreError }
            return [pscustomobject]@{ MockOnly = $true }
        }
        # Fail closed if a UI regression attempts discovery, real HTTP, storage or CLI.
        'Add-RelayCodexModels' = { throw 'UI must publish the previewed shared plan, not import directly' }
        'Install-RelayCredentialHelper' = { throw 'Interaction tests must not install real credentials' }
        'Read-RelayCredentialProvider' = { throw 'Interaction tests must not read credential storage' }
        'Unprotect-RelayApiKey' = { throw 'Interaction tests must not decrypt real credentials' }
        'Read-RelaySecret' = { throw 'Interaction tests must not request real credentials' }
        'Invoke-RelaySharedConfigPlan' = { throw 'Interaction tests must not execute real shared plans' }
        'Read-RelayJson' = { throw 'Interaction tests must not read persistent configuration' }
        'Initialize-RelayStore' = { throw 'Interaction UI fixtures must stay in memory' }
        'Invoke-RelayStoreLock' = { throw 'Interaction tests must not enter real storage transactions' }
        'Invoke-WebRequest' = { throw 'Interaction tests must not send HTTP requests' }
        'Invoke-RestMethod' = { throw 'Interaction tests must not send HTTP requests' }
        'Get-RelayModels' = { throw 'Interaction tests must not discover real models' }
        'New-RelayHttpClient' = { throw 'Interaction tests must not create an HTTP client' }
        'Write-RelayJson' = { throw 'Interaction tests must not write persistent configuration' }
        'Start-RelayCodex' = { throw 'Interaction tests must not launch the CLI' }
        'Get-RelayCodexInfo' = { throw 'Interaction tests must not invoke the CLI' }
    }
    $savedFunctions = @{}
    $installed = New-Object Collections.ArrayList
    $savedVariables = @{}
    foreach ($name in @('RTInteractionState', 'RelaySelectedModel')) {
        $variable = Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue
        $savedVariables[$name] = @{ Exists = ($null -ne $variable); Value = $null }
        if ($null -ne $variable) { $savedVariables[$name].Value = $variable.Value }
    }
    try {
        $script:RTInteractionState = $state
        foreach ($name in $mocks.Keys) {
            $original = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
            $savedFunctions[$name] = $null
            if ($null -ne $original) { $savedFunctions[$name] = $original.ScriptBlock }
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $mocks[$name]
            [void]$installed.Add($name)
        }
        $result = @(& $Body $state.Provider)
        Assert-Equal $state.Queue.Count 0 'UI returned before consuming the expected input sequence'
        return [pscustomobject]@{
            Result = $result; Output = @($state.Output.ToArray()); Prompts = @($state.Prompts.ToArray())
            Calls = @($state.Calls.ToArray()); Imports = @($state.Imports.ToArray()); Provider = $state.Provider
            Previews = @($state.Previews.ToArray()); Restores = @($state.Restores.ToArray())
            EffortPreviews = @($state.EffortPreviews.ToArray())
            Events = @($state.Events.ToArray()); HistoryReads = $state.HistoryReads
        }
    } finally {
        foreach ($name in $installed) {
            if ($null -ne $savedFunctions[$name]) {
                Set-Item -LiteralPath ('Function:script:' + $name) -Value $savedFunctions[$name]
            } else {
                # Function:script:name is usable for Set-Item, not for Remove-Item.
                Remove-Item -LiteralPath ('Function:' + $name) -Force
            }
        }
        foreach ($name in $savedVariables.Keys) {
            if ($savedVariables[$name].Exists) {
                Set-Variable -Name $name -Scope Script -Value $savedVariables[$name].Value
            } else { Remove-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue }
        }
    }
}

function Assert-InteractionConfirmedCalls {
    param($Session, [string[]]$Models, [int]$ConfirmationCount)
    Assert-Equal @($Session.Calls | ForEach-Object { $_.Model }) @($Models) 'Wrong models/order or duplicate calls'
    $confirmations = @($Session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' })
    Assert-Equal $confirmations.Count $ConfirmationCount 'Wrong number of real confirmation prompts'
    foreach ($prompt in $confirmations) { Assert-Equal $prompt.Answer 'YES' 'Calls require exact YES confirmation' }
    foreach ($prompt in $Session.Prompts) { Assert-Equal $prompt.CallsBefore 0 'A model was called before input/confirmation completed' }
    foreach ($call in $Session.Calls) {
        Assert-Equal $call.ProviderId $Session.Provider.Id 'Probe received the wrong provider'
        Assert-Equal $call.ReadCount $Session.Prompts.Count 'All confirmations must precede every model call'
    }
    Assert-Equal $Session.Result.Count 0 'UI must not leak mock objects to the success stream'
}

Add-RelayTest 'Interaction' 'Status colors distinguish untested, compatible, unavailable and transient errors' {
    foreach ($entry in @(
        @('NO_TESTED', 'White'), @('NOT_TESTED', 'White'), @('COMPATIBLE', 'Green'),
        @('INCOMPATIBLE', 'Red'), @('MODEL_UNAVAILABLE', 'Red'),
        @('NETWORK_ERROR', 'Yellow'), @('RATE_LIMITED', 'Yellow'), @('UNKNOWN', 'Yellow')
    )) {
        $color = Get-RelayStatusColor $entry[0]
        Assert-True ($color -is [ConsoleColor]) ('Expected ConsoleColor for ' + $entry[0])
        Assert-Equal $color ([ConsoleColor]$entry[1]) ('Wrong color for ' + $entry[0])
    }
}

Add-RelayTest 'Interaction' 'Model list passes the right color and normalized status to Write-RelaySafe' {
    $records = @(
        [pscustomobject]@{ Model = 'old-untested'; Status = 'NOT_TESTED' },
        [pscustomobject]@{ Model = 'new-untested'; Status = 'NO_TESTED' },
        [pscustomobject]@{ Model = 'working'; Status = 'COMPATIBLE' },
        [pscustomobject]@{ Model = 'protocol'; Status = 'INCOMPATIBLE' },
        [pscustomobject]@{ Model = 'unavailable'; Status = 'MODEL_UNAVAILABLE' },
        [pscustomobject]@{ Model = 'network'; Status = 'NETWORK_ERROR' },
        [pscustomobject]@{ Model = 'rate'; Status = 'RATE_LIMITED' }
    )
    $session = Invoke-InteractionScenario -Records $records -Body {
        param($Provider)
        Show-RelayModelList -Provider $Provider -Models @('fresh', 'old-untested', 'new-untested', 'working', 'protocol', 'unavailable', 'network', 'rate') -Selected @('working')
    }
    $rows = @($session.Output | Where-Object { $_.Text -match '^\[\d+\]' })
    Assert-Equal $rows.Count 8 'Every model must be displayed exactly once'
    $ids = @('fresh', 'old-untested', 'new-untested', 'working', 'protocol', 'unavailable', 'network', 'rate')
    $statuses = @('NO_TESTED', 'NO_TESTED', 'NO_TESTED', 'COMPATIBLE', 'INCOMPATIBLE', 'MODEL_UNAVAILABLE', 'NETWORK_ERROR', 'RATE_LIMITED')
    $colors = @('White', 'White', 'White', 'Green', 'Red', 'Red', 'Yellow', 'Yellow')
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $marker = ' '; if ($i -eq 3) { $marker = '*' }
        Assert-Equal $rows[$i].Text ('[{0}] {1} {2}  [{3}]' -f ($i + 1), $marker, $ids[$i], $statuses[$i]) 'Wrong model/status/selection marker'
        Assert-Equal $rows[$i].Color ([ConsoleColor]$colors[$i]) ('Wrong displayed color for ' + $ids[$i])
    }
    Assert-Equal $session.Result.Count 0
    Assert-Equal $session.Calls.Count 0
}

Add-RelayTest 'Interaction' 'Batch accepts 1,3 then 2 then 00 in selection order' {
    $session = Invoke-InteractionScenario -Answers @('1,3', '2', '00') -Body { param($Provider) Select-RelayModelsBatch $Provider }
    Assert-Equal $session.Result @('model-one', 'model-three', 'model-two')
    Assert-Equal $session.Calls.Count 0 'Selecting models must not call them'
}

Add-RelayTest 'Interaction' 'Batch deduplicates within and across lines without reordering' {
    $session = Invoke-InteractionScenario -Answers @('1,3,1', '2', '3,2,1', '00') -Body { param($Provider) Select-RelayModelsBatch $Provider }
    Assert-Equal $session.Result @('model-one', 'model-three', 'model-two')
}

Add-RelayTest 'Interaction' 'Batch 0 discards all selections and returns no items' {
    foreach ($answers in @(@('0'), @('1,3', '2', '0'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Select-RelayModelsBatch $Provider }
        Assert-Equal $session.Result @() 'Cancellation must not return earlier selections'
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Output | Where-Object { $_.Text -match '已取消' -and $_.Color -eq [ConsoleColor]::Yellow }).Count 1
    }
}

Add-RelayTest 'Interaction' 'Empty 00 does not finish and permits subsequent selection' {
    $session = Invoke-InteractionScenario -Answers @('00', '00', '2', '00') -Body { param($Provider) Select-RelayModelsBatch $Provider }
    Assert-Equal $session.Result @('model-two')
    Assert-Equal @($session.Output | Where-Object { $_.Text -match '尚未选择模型' }).Count 2
}

Add-RelayTest 'Interaction' 'Invalid batch lines are atomic including mixed 0 and 00 tokens' {
    foreach ($line in @('1,99', '1,0', '0,1', '1,00', '00,1', '1,0,3', '1,00,3', '1，99', '1，0', '1，00', '1,nope', '1,,3', '-1', '2147483648', '')) {
        $session = Invoke-InteractionScenario -Answers @($line, '2', '00') -Body { param($Provider) Select-RelayModelsBatch $Provider }
        Assert-Equal $session.Result @('model-two') ('Invalid line partially added models or ended selection: ' + $line)
        Assert-Equal @($session.Output | Where-Object { $_.Text -match '整行未添加' -and $_.Color -eq [ConsoleColor]::Yellow }).Count 1 ('Missing invalid-line warning: ' + $line)
    }
}

Add-RelayTest 'Interaction' 'An invalid batch line preserves earlier valid selections only' {
    $session = Invoke-InteractionScenario -Answers @('3', '1,99', '2', '00') -Body { param($Provider) Select-RelayModelsBatch $Provider }
    Assert-Equal $session.Result @('model-three', 'model-two')
}

Add-RelayTest 'Interaction' 'Batch supports Chinese commas and surrounding whitespace' {
    $session = Invoke-InteractionScenario -Answers @(' 1， 3 ', ' 2，1 ', ' 00 ') -Body { param($Provider) Select-RelayModelsBatch $Provider }
    Assert-Equal $session.Result @('model-one', 'model-three', 'model-two')
}

Add-RelayTest 'Interaction' 'Menu 2 probes only selected models after two YES confirmations' {
    $session = Invoke-InteractionScenario -Answers @('2', '1,3', '3,1', '00', 'YES', 'YES') -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
    Assert-InteractionConfirmedCalls $session @('model-one', 'model-three') 2
    $confirmations = @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' })
    Assert-Match $confirmations[0].Text '2 个模型' 'First confirmation must describe the selected count, not all cached models'
    Assert-Match $confirmations[1].Text '再次确认' 'Batch calls need a distinct second confirmation'
    Assert-Equal @($session.Output | Where-Object { $_.Text -eq ('最终请求地址：' + $session.Provider.BaseUrl + '/responses') }).Count 1
}

Add-RelayTest 'Interaction' 'Menu 2 cancellation never probes or asks for billing confirmation' {
    foreach ($answers in @(@('2', '0'), @('2', '1,3', '0'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count 0
    }
}

Add-RelayTest 'Interaction' 'Menu 2 declining either confirmation prevents every probe' {
    foreach ($decline in @('NO', '', 'yes', '0', ' YES ')) {
        foreach ($stage in @(1, 2)) {
            $answers = @('2', '1,3', '00')
            if ($stage -eq 2) { $answers += 'YES' }
            $answers += $decline
            $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
            Assert-Equal $session.Calls.Count 0 ('Menu 2 called a model despite declining confirmation ' + $stage)
            Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count $stage
        }
    }
}

Add-RelayTest 'Interaction' 'Menu 3 probes all cached models in cache order after two confirmations' {
    $session = Invoke-InteractionScenario -Answers @('3', 'YES', 'YES') -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
    Assert-InteractionConfirmedCalls $session @('model-one', 'model-two', 'model-three') 2
    Assert-Match $session.Prompts[1].Text '3 个模型'
}

Add-RelayTest 'Interaction' 'Menu 3 declining either confirmation prevents every probe' {
    foreach ($answers in @(@('3', 'NO'), @('3', 'YES', 'NO'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
        Assert-Equal $session.Calls.Count 0
    }
}

Add-RelayTest 'Interaction' 'Menu 1 preserves single-model selection and one YES confirmation' {
    $session = Invoke-InteractionScenario -Answers @('1', '2', 'YES') -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
    Assert-InteractionConfirmedCalls $session @('model-two') 1
    Assert-Match $session.Prompts[2].Text 'model-two' 'Single confirmation must name the selected model'
}

Add-RelayTest 'Interaction' 'Menu 1 cancellation or declined confirmation does not probe' {
    foreach ($answers in @(@('1', '0'), @('1', '2', 'NO'), @('1', '2', 'yes'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
        Assert-Equal $session.Calls.Count 0
        $expected = 1; if ($answers.Count -eq 2) { $expected = 0 }
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count $expected
    }
}

Add-RelayTest 'Interaction' 'Compatibility menu return or invalid choice makes no calls' {
    foreach ($answer in @('0', 'cancel', '99', '')) {
        $session = Invoke-InteractionScenario -Answers @($answer) -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
        Assert-Equal $session.Calls.Count 0
        Assert-Equal $session.Prompts.Count 1
    }
}

Add-RelayTest 'Interaction' 'Compatibility UI colors probe results through the real status mapper' {
    foreach ($entry in @(@('COMPATIBLE', 'Green'), @('INCOMPATIBLE', 'Red'), @('MODEL_UNAVAILABLE', 'Red'), @('NETWORK_ERROR', 'Yellow'), @('RATE_LIMITED', 'Yellow'))) {
        $session = Invoke-InteractionScenario -ResponseStatus $entry[0] -Answers @('1', '2', 'YES') -Body { param($Provider) Test-RelayCompatibilityUi $Provider }
        Assert-InteractionConfirmedCalls $session @('model-two') 1
        $rows = @($session.Output | Where-Object { $_.Text -like 'model-two: *' })
        Assert-Equal $rows.Count 1
        Assert-Match $rows[0].Text ([regex]::Escape($entry[0]))
        Assert-Equal $rows[0].Color ([ConsoleColor]$entry[1])
    }
}

function Assert-InteractionImportedModels {
    param($Session, [string[]]$Models, [string]$DefaultModel)
    Assert-Equal $Session.EffortPreviews.Count 1 'Catalog UI must collect effort settings exactly once'
    Assert-Equal $Session.EffortPreviews[0].Models @($Models) 'Effort UI must receive only the selected models in selection order'
    $defaultPrompts = @($Session.Prompts | Where-Object { $_.Text -match '默认模型序号' })
    Assert-True ($defaultPrompts.Count -gt 0) 'Default model must be explicitly selected after effort settings'
    foreach ($prompt in $defaultPrompts) { Assert-Equal $prompt.EffortPreviewsBefore 1 'Effort settings must precede every default-model prompt' }
    Assert-Equal @($Session.Events | Where-Object { $_ -in @('EffortPreview', 'CredentialPreview', 'SharedPreview', 'Publish') }) @('EffortPreview', 'CredentialPreview', 'SharedPreview', 'Publish') 'Effort/credential/shared preview/publish order changed'
    Assert-Equal $Session.Previews.Count 1 'Shared UI must preview exactly one plan'
    Assert-Equal $Session.Previews[0].ImportsBefore 0 'Preview must not publish anything'
    Assert-Equal $Session.Previews[0].Plan.Model $DefaultModel 'Wrong explicitly selected default model'
    Assert-Equal $Session.Imports.Count 1 'Catalog UI must make exactly one stub publish'
    Assert-Equal $Session.Imports[0].Models @($Models) 'Catalog UI changed selection order or duplicates'
    Assert-Equal $Session.Imports[0].ProviderId $Session.Provider.Id
    Assert-Equal $Session.Imports[0].ReadCount $Session.Prompts.Count 'Catalog import happened before confirmation'
    foreach ($prompt in $Session.Prompts) { Assert-Equal $prompt.ImportsBefore 0 'Catalog was written before confirmation completed' }
    $confirmations = @($Session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' })
    Assert-Equal $confirmations.Count 1 'Catalog UI needs one file-write confirmation'
    Assert-Equal $confirmations[0].Answer 'YES'
    Assert-Match $confirmations[0].Text ('接入 ' + $Models.Count + ' 个模型')
    Assert-Equal $confirmations[0].PreviewsBefore 1 'Final confirmation must follow the completed preview'
    Assert-Equal $Session.Previews[0].ReadCount ($Session.Prompts.Count - 1) 'Preview must follow explicit default selection and precede final confirmation'
    Assert-Equal @($Session.Events | Select-Object -Last 4) @('CredentialPreview', 'SharedPreview', 'Read', 'Publish') 'Preview/confirmation/publish order changed'
    Assert-Equal $Session.Restores.Count 0
    Assert-Equal $Session.Calls.Count 0 'Catalog UI must never probe model compatibility'
    Assert-Equal $Session.Result.Count 0 'Catalog UI leaked the import return value'
}

Add-RelayTest 'Interaction' 'Catalog menu 2 shares comma selection, repeated lines and 00 completion' {
    $session = Invoke-InteractionScenario -Answers @('2', '1,3', '2', '3,1', '00', '2', 'YES') -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
    Assert-InteractionImportedModels $session @('model-one', 'model-three', 'model-two') 'model-three'
    Assert-Equal @($session.Output | Where-Object { $_.Text -eq '模型目录文件：interaction-only-models.json' }).Count 1
    Assert-Equal @($session.Output | Where-Object { $_.Text -eq '共用配置文件：interaction-only-shared-config.toml' }).Count 1
    Assert-Equal @($session.Output | Where-Object { $_.Text -eq ('默认 Provider / 模型：' + $session.Provider.Name + ' / model-three') }).Count 1
}

Add-RelayTest 'Interaction' 'Catalog batch empty 00 continues and invalid lines remain atomic' {
    $session = Invoke-InteractionScenario -Answers @('2', '00', '1,99', '1，00', ' 3，1 ', '2', '00', '3', 'YES') -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
    Assert-InteractionImportedModels $session @('model-three', 'model-one', 'model-two') 'model-two'
    Assert-Equal @($session.Output | Where-Object { $_.Text -match '尚未选择模型' }).Count 1
    Assert-Equal @($session.Output | Where-Object { $_.Text -match '整行未添加' }).Count 2
}

Add-RelayTest 'Interaction' 'Catalog batch 0 discards prior choices without an import or confirmation' {
    foreach ($answers in @(@('2', '0'), @('2', '1,3', '2', '0'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
        Assert-Equal $session.Imports.Count 0
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count 0
    }
}

Add-RelayTest 'Interaction' 'Catalog declines file writes unless the answer is exactly YES' {
    foreach ($decline in @('NO', '', 'yes', '0', ' YES ')) {
        $session = Invoke-InteractionScenario -Answers @('2', '1,3', '00', '2', $decline) -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
        Assert-Equal $session.Imports.Count 0 'Catalog publish must not run after a declined confirmation'
        Assert-Equal $session.Previews.Count 1 'Declining final confirmation must still permit a read-only preview'
        Assert-Equal $session.Previews[0].Plan.Model 'model-three'
        Assert-Equal @($session.Events | Select-Object -Last 3) @('CredentialPreview', 'SharedPreview', 'Read')
        Assert-Equal $session.Restores.Count 0
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count 1
    }
}

Add-RelayTest 'Interaction' 'Catalog menu 1 imports only the chosen model and menu 3 imports the cache' {
    $single = Invoke-InteractionScenario -Answers @('1', '2', '1', 'YES') -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
    Assert-InteractionImportedModels $single @('model-two') 'model-two'
    $all = Invoke-InteractionScenario -Answers @('3', '2', 'YES') -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
    Assert-InteractionImportedModels $all @('model-one', 'model-two', 'model-three') 'model-two'
}

Add-RelayTest 'Interaction' 'Selected models reach effort UI and settings pass unchanged to plan and publish' {
    $settings = @(
        [pscustomobject]@{ Model = 'model-three'; SupportedLevels = @('low', 'high'); DefaultLevel = 'high'; Source = 'API_ACCEPTED' },
        [pscustomobject]@{ Model = 'model-one'; SupportedLevels = @('medium'); DefaultLevel = 'medium'; Source = 'API_ACCEPTED' }
    )
    $session = Invoke-InteractionScenario -EffortSettings $settings -Answers @('2', '3,1,3', '00', '2', 'YES') -Body {
        param($Provider)
        Add-RelayCodexModelsUi $Provider
    }
    Assert-InteractionImportedModels $session @('model-three', 'model-one') 'model-one'
    $effort = $session.EffortPreviews[0]
    Assert-True ([object]::ReferenceEquals($effort.Provider, $session.Provider)) 'Effort UI must receive the selected provider object'
    Assert-Equal $effort.ReadCount 3 'Effort settings must be collected immediately after model selection, before default selection'
    $planned = $session.Previews[0].Plan.EffortSettings
    $published = $session.Imports[0].EffortSettings
    Assert-Equal @($planned) $settings 'Plan must receive all returned effort settings in order'
    Assert-True ([object]::ReferenceEquals($planned, $published)) 'Plan and publish must receive the same effort settings array'
    for ($i = 0; $i -lt $settings.Count; $i++) {
        Assert-True ([object]::ReferenceEquals($effort.Settings[$i], $settings[$i])) 'Effort stub must retain the supplied settings object'
        Assert-True ([object]::ReferenceEquals($planned[$i], $settings[$i])) 'Plan must receive the exact returned settings object'
        Assert-True ([object]::ReferenceEquals($published[$i], $settings[$i])) 'Publish must receive the exact returned settings object'
    }
}

Add-RelayTest 'Interaction' 'Effort settings failure aborts before default, credential preview and publish' {
    foreach ($answers in @(@('1', '2'), @('2', '3,1', '00'), @('3'))) {
        $session = Invoke-InteractionScenario -EffortError 'fixture effort settings failure' -Answers $answers -Body {
            param($Provider)
            [void](Assert-Throws { Add-RelayCodexModelsUi $Provider } 'fixture effort settings failure')
        }
        Assert-Equal $session.EffortPreviews.Count 1
        Assert-Equal $session.EffortPreviews[0].ReadCount $session.Prompts.Count
        Assert-Equal @($session.Events | Select-Object -Last 1) @('EffortPreview')
        Assert-Equal @($session.Events | Where-Object { $_ -in @('CredentialPreview', 'SharedPreview', 'Publish') }).Count 0
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '默认模型序号|输入 YES 确认' }).Count 0
        Assert-Equal $session.Previews.Count 0
        Assert-Equal $session.Imports.Count 0 'Effort settings failure must never publish'
        Assert-Equal $session.Restores.Count 0
        Assert-Equal $session.Calls.Count 0 'Only the effort stub may run; no API probes'
        Assert-Equal $session.Result.Count 0
        Assert-Equal @($session.Output | Where-Object { $_.Text -match '配置已写入' }).Count 0
    }
}

Add-RelayTest 'Interaction' 'Shared preview conflicts abort before confirmation and perform zero writes' {
    foreach ($conflict in @('conflict: model_provider override', 'conflict: model_catalog_json override', 'conflict: profile override')) {
        $session = Invoke-InteractionScenario -PreviewError $conflict -Answers @('3', '2') -Body {
            param($Provider)
            [void](Assert-Throws { Add-RelayCodexModelsUi $Provider } 'conflict:')
        }
        Assert-Equal $session.Previews.Count 1
        Assert-Equal $session.Previews[0].Plan.Model 'model-two'
        Assert-Equal $session.Imports.Count 0 'A preview conflict must never publish'
        Assert-Equal $session.Restores.Count 0
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count 0
        Assert-Equal @($session.Events | Select-Object -Last 2) @('CredentialPreview', 'SharedPreview')
        Assert-Equal @($session.Output | Where-Object { $_.Text -match '配置已写入' }).Count 0
    }
}

Add-RelayTest 'Interaction' 'Default selection rejects implicit and invalid choices before selecting a nonfirst model' {
    foreach ($invalid in @('', 'YES', '00', '4', '-1', '1,2', '2147483648')) {
        $session = Invoke-InteractionScenario -Answers @('3', $invalid, '3', 'YES') -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
        Assert-InteractionImportedModels $session @('model-one', 'model-two', 'model-three') 'model-three'
        $prompts = @($session.Prompts | Where-Object { $_.Text -match '默认模型序号' })
        Assert-Equal $prompts.Count 2 'Invalid default input must not silently choose the first model'
        foreach ($prompt in $prompts) { Assert-Equal $prompt.PreviewsBefore 0 'Default selection must finish before preview' }
        Assert-Equal @($session.Output | Where-Object { $_.Text -eq '请输入有效模型序号。' -and $_.Color -eq [ConsoleColor]::Yellow }).Count 1
    }
}

Add-RelayTest 'Interaction' 'Default 0 cancels every catalog mode before credential or shared previews' {
    foreach ($answers in @(@('1', '2', '0'), @('2', '3,1', '00', '0'), @('3', '0'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
        Assert-Equal $session.Imports.Count 0
        Assert-Equal $session.Previews.Count 0
        Assert-Equal $session.Restores.Count 0
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Events | Where-Object { $_ -in @('CredentialPreview', 'SharedPreview', 'Publish') }).Count 0
        Assert-Equal @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' }).Count 0
    }
}

Add-RelayTest 'Interaction' 'Catalog menu cancellation and invalid choices never preview or publish' {
    foreach ($answers in @(@('0'), @('99'), @(''), @('1', '0'))) {
        $session = Invoke-InteractionScenario -Answers $answers -Body { param($Provider) Add-RelayCodexModelsUi $Provider }
        Assert-Equal $session.Previews.Count 0
        Assert-Equal $session.Imports.Count 0
        Assert-Equal $session.Calls.Count 0
    }
}

Add-RelayTest 'Interaction' 'Restore UI empty history returns without prompts or writes' {
    $session = Invoke-InteractionScenario -Body { Show-RelaySharedConfigUi }
    Assert-Equal $session.HistoryReads 1
    Assert-Equal $session.Prompts.Count 0
    Assert-Equal $session.Restores.Count 0
    Assert-Equal $session.Imports.Count 0
    Assert-Equal @($session.Output | Where-Object { $_.Text -eq '尚无共享配置接入记录。' -and $_.Color -eq [ConsoleColor]::Yellow }).Count 1
}

Add-RelayTest 'Interaction' 'Restore UI uses the selected history transaction only after exact YES' {
    $history = @(
        [pscustomobject]@{ TransactionId = 'fixture-first'; ConfigPath = 'fixture-first.toml' },
        [pscustomobject]@{ TransactionId = 'fixture-second'; ConfigPath = 'fixture-second.toml' }
    )
    $session = Invoke-InteractionScenario -History $history -Answers @('', '99', '1,2', '2', 'YES') -Body { Show-RelaySharedConfigUi }
    Assert-Equal $session.HistoryReads 1
    Assert-Equal $session.Restores.Count 1
    Assert-Equal $session.Restores[0].TransactionId 'fixture-second'
    Assert-Equal $session.Restores[0].ReadCount $session.Prompts.Count
    foreach ($prompt in $session.Prompts) { Assert-Equal $prompt.RestoresBefore 0 'Restore ran before confirmation' }
    $confirmations = @($session.Prompts | Where-Object { $_.Text -match '输入 YES 确认' })
    Assert-Equal $confirmations.Count 1
    Assert-Equal $confirmations[0].Answer 'YES'
    Assert-Equal @($session.Events | Select-Object -Last 2) @('Read', 'Restore')
    Assert-Equal @($session.Output | Where-Object { $_.Text -match '^\[2\] fixture-second  fixture-second.toml$' }).Count 1
    Assert-Equal $session.Imports.Count 0
    Assert-Equal $session.Previews.Count 0
    Assert-Equal $session.Calls.Count 0
    Assert-Equal $session.Result.Count 0 'Restore mock result must not leak'
}

Add-RelayTest 'Interaction' 'Restore UI cancellation and inexact confirmation never restore' {
    $history = @([pscustomobject]@{ TransactionId = 'fixture-cancel'; ConfigPath = 'fixture-cancel.toml' })
    foreach ($answers in @(@('0'), @('99', '0'), @('1', 'NO'), @('1', ''), @('1', 'yes'), @('1', '0'), @('1', ' YES '))) {
        $session = Invoke-InteractionScenario -History $history -Answers $answers -Body { Show-RelaySharedConfigUi }
        Assert-Equal $session.HistoryReads 1
        Assert-Equal $session.Restores.Count 0
        Assert-Equal $session.Imports.Count 0
        Assert-Equal $session.Previews.Count 0
        Assert-Equal $session.Calls.Count 0
        Assert-Equal @($session.Output | Where-Object { $_.Text -match '共享配置已恢复' }).Count 0
    }
}

Add-RelayTest 'Interaction' 'Restore UI conflict propagates without claiming a successful restore' {
    $history = @([pscustomobject]@{ TransactionId = 'fixture-conflict'; ConfigPath = 'fixture-conflict.toml' })
    $session = Invoke-InteractionScenario -History $history -RestoreError 'fixture fingerprint conflict' -Answers @('1', 'YES') -Body {
        [void](Assert-Throws { Show-RelaySharedConfigUi } 'fixture fingerprint conflict')
    }
    Assert-Equal $session.Restores.Count 1 'Only the in-memory restore stub may run'
    Assert-Equal $session.Restores[0].TransactionId 'fixture-conflict'
    Assert-Equal @($session.Output | Where-Object { $_.Text -match '共享配置已恢复' }).Count 0
    Assert-Equal $session.Imports.Count 0
    Assert-Equal $session.Calls.Count 0
}

Add-RelayTest 'Interaction' 'Mocks and selection state are restored even when a scenario throws' {
    $names = @('Read-Host', 'Write-Host', 'Write-RelaySafe', 'Get-RelayModelCache', 'Get-RelayCompatibility', 'Test-RelayResponse', 'Get-RelayModels', 'New-RelayHttpClient', 'Write-RelayJson', 'Start-RelayCodex', 'Get-RelayCodexInfo', 'Get-RelayCatalogPaths', 'Add-RelayCodexModels', 'Select-RelayEffortSettingsUi', 'Get-RelayCredentialConfig', 'New-RelaySharedConfigPlan', 'Publish-RelayCodexModels', 'Get-RelaySharedConfigHistory', 'Restore-RelaySharedConfig', 'Install-RelayCredentialHelper', 'Read-RelayCredentialProvider', 'Unprotect-RelayApiKey', 'Read-RelaySecret', 'Invoke-RelaySharedConfigPlan', 'Read-RelayJson', 'Initialize-RelayStore', 'Invoke-RelayStoreLock', 'Invoke-WebRequest', 'Invoke-RestMethod')
    $before = @{}
    foreach ($name in $names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        $before[$name] = $null
        if ($null -ne $command) { $before[$name] = @{ Type = $command.CommandType; Definition = $command.Definition } }
    }
    $selectedBefore = $script:RelaySelectedModel
    $stateBefore = Get-Variable RTInteractionState -Scope Script -ErrorAction SilentlyContinue
    [void](Assert-Throws {
        Invoke-InteractionScenario -Answers @('2') -Body {
            param($Provider)
            [void](Select-RelayModel $Provider)
            throw 'intentional-interaction-failure'
        }
    } 'intentional-interaction-failure')
    Assert-Equal $script:RelaySelectedModel $selectedBefore 'Single-model selector state leaked after a failing test'
    foreach ($name in $names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -eq $before[$name]) {
            Assert-True ($null -eq $command) ('New mock function leaked: ' + $name)
        } else {
            Assert-True ($null -ne $command) ('Original command was removed: ' + $name)
            Assert-Equal $command.CommandType $before[$name].Type ('Mock command type leaked: ' + $name)
            Assert-Equal $command.Definition $before[$name].Definition ('Mock function leaked: ' + $name)
        }
    }
    $stateAfter = Get-Variable RTInteractionState -Scope Script -ErrorAction SilentlyContinue
    Assert-Equal ($null -eq $stateAfter) ($null -eq $stateBefore) 'Mock state variable lifetime changed'
    if ($null -ne $stateBefore) { Assert-True ([object]::ReferenceEquals($stateAfter.Value, $stateBefore.Value)) 'Previous mock state was not restored' }
}
