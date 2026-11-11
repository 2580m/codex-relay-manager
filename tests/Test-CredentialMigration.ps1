# Real ACL/DPAPI fixtures; all files live under the test's private disposable parent.
function Invoke-LegacyCredentialScenario {
    param([scriptblock]$Body)
    $oldData = $script:RelayDataDirectory
    $oldPrivate = $script:RelayCredentialBaseDirectory
    try {
        $data = Join-Path $oldPrivate 'legacy-data'
        $script:RelayCredentialBaseDirectory = Join-Path $oldPrivate 'new-private'
        Initialize-RelayStore -Path $data | Out-Null
        $p = New-TestProvider -Name 'Legacy one'
        $p2 = New-TestProvider -Name 'Legacy two'
        $private = Get-RelayPrivatePaths
        $catalog = Add-RelayCodexModels $p @('legacy-model')
        $cfg = Join-Path $data 'isolated-config.toml'
        $helper = Join-Path $data 'credentials\credential-helper.ps1'
        [void][IO.Directory]::CreateDirectory((Split-Path $helper -Parent))
        $fixture = Join-Path $PSScriptRoot 'fixtures\credential-helper-v2.txt'
        [IO.File]::WriteAllBytes($helper, [IO.File]::ReadAllBytes($fixture))
        foreach ($provider in @($p, $p2)) {
            $auth = Get-RelayCredentialConfig $provider
            $auth.Args = [string[]]@('-NoProfile', '-NonInteractive', '-File', $helper, '-DataDirectory', $data, '-ProviderId', $provider.Id)
            $auth.Cwd = $data
            $plan = New-RelaySharedConfigPlan -Provider $provider -Model 'legacy-model' -ConfigPath $cfg -CatalogPath $catalog.ModelsPath -AuthConfig $auth
            Invoke-RelaySharedConfigPlan $plan | Out-Null
        }
        # Turn the newly-created fixture into the legacy on-disk layout.
        $legacy = Join-Path $data 'providers.json'
        [IO.File]::Move($private.Providers, $legacy)
        & $Body ([pscustomobject]@{ Data=$data; Private=$private; Provider=$p; Other=$p2; Config=$cfg; Legacy=$legacy; Helper=$helper; Catalog=$catalog.ModelsPath })
    } finally {
        $script:RelayDataDirectory = $oldData
        $script:RelayCredentialBaseDirectory = $oldPrivate
    }
}

Add-RelayTest 'CredentialMigration' 'Explicit migration moves exact ciphertext and both owned auth entries without changing active settings or catalog' {
    Invoke-LegacyCredentialScenario {
        param($f)
        $bytes = [IO.File]::ReadAllBytes($f.Legacy)
        $catalog = [IO.File]::ReadAllBytes($f.Catalog)
        $originalConfig = [IO.File]::ReadAllText($f.Config)
        [IO.File]::WriteAllText($f.Config, ('profile = "keep-profile"' + "`n" + $originalConfig))
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data } 'MigrateLegacyCredentials')
        [void](Assert-Throws { Get-RelayProviders } 'migration is incomplete')
        Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config | Out-Null
        Assert-Equal ([IO.File]::ReadAllBytes($f.Private.Providers)) $bytes
        Assert-Equal ([IO.File]::ReadAllBytes($f.Catalog)) $catalog
        Assert-True (-not [IO.File]::Exists($f.Legacy))
        Assert-True (-not [IO.File]::Exists($f.Helper))
        Assert-Equal @(Get-RelayProviders).Count 2
        $after = [IO.File]::ReadAllText($f.Config)
        Assert-Match $after '^profile = "keep-profile"'
        Assert-Match $after ('model_provider = "' + $f.Other.Id + '"')
        Assert-True (-not $after.Contains((ConvertTo-TomlString $f.Helper)))
        foreach ($provider in @($f.Provider, $f.Other)) {
            $auth = Get-RelayCredentialConfig $provider
            Assert-True $after.Contains((ConvertTo-TomlString $auth.Args[-1]))
            Assert-True $after.Contains((ConvertTo-TomlString $auth.Cwd))
            $result = Invoke-CredentialTestHelper $auth
            Assert-Equal $result.ExitCode 0
            Assert-Equal $result.Stderr ''
            Assert-Equal $result.Stdout (Get-TestProviderKey $provider)
        }
        $backups = @(Get-ChildItem -LiteralPath $f.Private.Root -Filter 'legacy-providers.*.bak')
        Assert-Equal $backups.Count 1
        Assert-Equal ([IO.File]::ReadAllBytes($backups[0].FullName)) $bytes
        [void](Assert-Throws { Restore-RelaySharedConfig -ConfigPath $f.Config } 'retired credential helper')
        Assert-Equal ([IO.File]::ReadAllText($f.Config)) $after
        Initialize-RelayStore -Path $f.Data | Out-Null
    }
}

Add-RelayTest 'CredentialMigration' 'Modified legacy helper or externally edited auth prevents config migration and preserves the source' {
    Invoke-LegacyCredentialScenario {
        param($f)
        $helper = [IO.File]::ReadAllBytes($f.Helper)
        $config = [IO.File]::ReadAllBytes($f.Config)
        $source = [IO.File]::ReadAllBytes($f.Legacy)
        [IO.File]::AppendAllText($f.Helper, '# tampered')
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'modified')
        Assert-Equal ([IO.File]::ReadAllBytes($f.Config)) $config
        Assert-Equal ([IO.File]::ReadAllBytes($f.Legacy)) $source
        [IO.File]::WriteAllBytes($f.Helper, $helper)
        $text = [IO.File]::ReadAllText($f.Config).Replace('timeout_ms = 15000', 'timeout_ms = 16000')
        [IO.File]::WriteAllText($f.Config, $text)
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'not owned|edited')
        Assert-Equal ([IO.File]::ReadAllText($f.Config)) $text
        Assert-Equal ([IO.File]::ReadAllBytes($f.Legacy)) $source
    }
}

Add-RelayTest 'CredentialMigration' 'A later auth commit failure rolls back earlier commits and can be retried' {
    Invoke-LegacyCredentialScenario {
        param($f)
        $before = [IO.File]::ReadAllBytes($f.Config)
        $original = (Get-Command Invoke-RelaySharedConfigPlan).ScriptBlock
        $script:RTMigrationCalls = 0
        try {
            Set-Item Function:script:Invoke-RelaySharedConfigPlan -Value {
                param($Plan)
                $script:RTMigrationCalls++
                if ($script:RTMigrationCalls -eq 2) { throw 'fixture later commit failure' }
                & $original $Plan
            }
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'fixture later commit failure')
        } finally {
            Set-Item Function:script:Invoke-RelaySharedConfigPlan -Value $original
            Remove-Variable RTMigrationCalls -Scope Script
        }
        Assert-Equal ([IO.File]::ReadAllBytes($f.Config)) $before
        Assert-True ([IO.File]::Exists($f.Legacy))
        Assert-True ([IO.File]::Exists($f.Helper))
        Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config | Out-Null
        Assert-True (-not [IO.File]::Exists($f.Legacy))
    }
}

Add-RelayTest 'CredentialMigration' 'Unknown config references and conflicting private data are not overwritten' {
    Invoke-LegacyCredentialScenario {
        param($f)
        $text = [IO.File]::ReadAllText($f.Config) + "`n[unmanaged]`nhelper = " + (ConvertTo-TomlString $f.Helper) + "`n"
        [IO.File]::WriteAllText($f.Config, $text)
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'Unmanaged legacy')
        Assert-Equal ([IO.File]::ReadAllText($f.Config)) $text
        Write-RelayJson -Path $f.Private.Providers -Value @()
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'stores differ')
        Assert-True ([IO.File]::Exists($f.Legacy))
    }
}

Add-RelayTest 'CredentialMigration' 'Only the known legacy helper source and its line-ending variants are upgradeable' {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\credential-helper-v2.txt'))
    foreach ($text in @($source.Replace("`r`n", "`n"), $source.Replace("`r`n", "`n").Replace("`n", "`r`n"))) {
        Assert-True (Test-RelayLegacyHelperBytes ([Text.Encoding]::UTF8.GetBytes($text)))
    }
    Assert-True (-not (Test-RelayLegacyHelperBytes ([Text.Encoding]::UTF8.GetBytes($source + '# changed'))))
}
