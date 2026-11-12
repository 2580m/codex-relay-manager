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

function Set-MigrationTestAcl {
    param([string]$Path, $Acl)
    $dacl = New-Object Security.AccessControl.DirectorySecurity
    $dacl.SetSecurityDescriptorSddlForm($Acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access), [Security.AccessControl.AccessControlSections]::Access)
    if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.Directory]::SetAccessControl($Path, $dacl) }
    else { [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.DirectoryInfo($Path)), $dacl) }
}

function Invoke-PreviousPrivateCredentialScenario {
    param([scriptblock]$Body)
    $oldData = $script:RelayDataDirectory
    $oldPrivate = $script:RelayCredentialBaseDirectory
    $oldLegacyBase = $script:RelayLegacyCredentialBaseDirectory
    try {
        $data = Join-Path $oldPrivate 'state3-data'
        $prevBase = Join-Path $oldPrivate 'prev-private'
        $newBase = Join-Path $oldPrivate 'new-private'
        $script:RelayCredentialBaseDirectory = $prevBase
        $script:RelayLegacyCredentialBaseDirectory = Join-Path $oldPrivate 'unused-legacy-private'
        Initialize-RelayStore -Path $data | Out-Null
        $p = New-TestProvider -Name 'State3 one'
        $p2 = New-TestProvider -Name 'State3 two'
        $oldPriv = Get-RelayPrivatePaths
        $oldHelper = (Install-RelayCredentialHelper $p).HelperPath
        $null = Install-RelayCredentialHelper $p2
        $catalog = Add-RelayCodexModels $p @('state3-model')
        $cfg = Join-Path $data 'isolated-config.toml'
        foreach ($provider in @($p, $p2)) {
            $auth = Get-RelayCredentialConfig $provider
            $plan = New-RelaySharedConfigPlan -Provider $provider -Model 'state3-model' -ConfigPath $cfg -CatalogPath $catalog.ModelsPath -AuthConfig $auth
            Invoke-RelaySharedConfigPlan $plan | Out-Null
        }
        # Point active vault at new base while leaving State 3 files under $prevBase.
        $script:RelayLegacyCredentialBaseDirectory = $prevBase
        $script:RelayCredentialBaseDirectory = $newBase
        $newPriv = Get-RelayPrivatePaths
        & $Body ([pscustomobject]@{
            Data=$data
            OldBase=$prevBase
            OldPrivate=([pscustomobject]@{ Base=$oldPriv.Base; Root=$oldPriv.Root; Providers=$oldPriv.Providers; Helper=$oldHelper })
            NewPrivate=$newPriv
            Provider=$p
            Other=$p2
            Config=$cfg
            Catalog=$catalog.ModelsPath
        })
    } finally {
        $script:RelayDataDirectory = $oldData
        $script:RelayCredentialBaseDirectory = $oldPrivate
        $script:RelayLegacyCredentialBaseDirectory = $oldLegacyBase
    }
}

Add-RelayTest 'CredentialMigration' 'Relocation migration moves previous private vault with sandbox Modify ACEs and updates EncodedCommand configs' {
    Invoke-PreviousPrivateCredentialScenario {
        param($f)
        $bytes = [IO.File]::ReadAllBytes($f.OldPrivate.Providers)
        $originalConfig = [IO.File]::ReadAllText($f.Config)
        [IO.File]::WriteAllText($f.Config, ('profile = "state3-profile"' + "`n" + $originalConfig))

        $prevAcl = Get-Acl -LiteralPath $f.OldBase
        $ephemeralSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-3090728700-3916954156-3934331587-1471338943')
        [void]$prevAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ephemeralSid, 'Modify', 'None', 'None', 'Allow')))
        $sandboxSid = Get-RelayCodexSandboxSid
        if ($sandboxSid) {
            [void]$prevAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sandboxSid)), 'Modify', 'None', 'None', 'Allow')))
        }
        Set-MigrationTestAcl $f.OldBase $prevAcl
        [void](Assert-Throws { Assert-RelayCredentialParents $f.OldPrivate.Root } 'ancestor ACL')

        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data } 'MigrateLegacyCredentials')
        [void](Assert-Throws { Get-RelayProviders } 'migration is incomplete')

        Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config | Out-Null
        Assert-Equal ([IO.File]::ReadAllBytes($f.NewPrivate.Providers)) $bytes
        Assert-True (-not [IO.File]::Exists($f.OldPrivate.Providers))
        Assert-True (-not [IO.File]::Exists($f.OldPrivate.Helper))

        $after = [IO.File]::ReadAllText($f.Config)
        Assert-Match $after '^profile = "state3-profile"'
        foreach ($provider in @($f.Provider, $f.Other)) {
            $auth = Get-RelayCredentialConfig $provider
            Assert-True $after.Contains((ConvertTo-TomlString $auth.Args[-1]))
            $result = Invoke-CredentialTestHelper $auth
            Assert-Equal $result.ExitCode 0
            Assert-Equal $result.Stderr ''
            Assert-Equal $result.Stdout (Get-TestProviderKey $provider)
        }
        $backups = @(Get-ChildItem -LiteralPath $f.NewPrivate.Root -Filter 'legacy-providers.*.bak')
        Assert-Equal $backups.Count 1
        Assert-Equal ([IO.File]::ReadAllBytes($backups[0].FullName)) $bytes
        [void](Assert-Throws { Restore-RelaySharedConfig -ConfigPath $f.Config } 'retired credential helper')
        Assert-Equal ([IO.File]::ReadAllText($f.Config)) $after
        Initialize-RelayStore -Path $f.Data | Out-Null
    }
}

Add-RelayTest 'CredentialMigration' 'Relocation migration rejects unsafe non-sandbox ACEs, tampered helpers, and unmanaged EncodedCommand references' {
    Invoke-PreviousPrivateCredentialScenario {
        param($f)
        $cleanBaseAcl = Get-Acl -LiteralPath $f.OldBase
        $cleanRootAcl = Get-Acl -LiteralPath $f.OldPrivate.Root
        $sourceBytes = [IO.File]::ReadAllBytes($f.OldPrivate.Providers)
        $helperBytes = [IO.File]::ReadAllBytes($f.OldPrivate.Helper)
        $configText = [IO.File]::ReadAllText($f.Config)

        try {
            $badEveryone = Get-Acl -LiteralPath $f.OldBase
            [void]$badEveryone.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'Modify', 'None', 'None', 'Allow')))
            Set-MigrationTestAcl $f.OldBase $badEveryone
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'ancestor ACL')
            Assert-True ([IO.File]::Exists($f.OldPrivate.Providers))

            Set-MigrationTestAcl $f.OldBase $cleanBaseAcl
            $domainPrefix = [Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value
            $localOtherSid = New-Object Security.Principal.SecurityIdentifier($domainPrefix + '-19999')
            $badLocal = Get-Acl -LiteralPath $f.OldBase
            [void]$badLocal.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($localOtherSid, 'Modify', 'None', 'None', 'Allow')))
            Set-MigrationTestAcl $f.OldBase $badLocal
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'ancestor ACL')

            Set-MigrationTestAcl $f.OldBase $cleanBaseAcl
            $ephemeralFull = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-3090728700-3916954156-3934331587-1471338943')
            $badCapFull = Get-Acl -LiteralPath $f.OldBase
            [void]$badCapFull.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ephemeralFull, 'FullControl', 'None', 'None', 'Allow')))
            Set-MigrationTestAcl $f.OldBase $badCapFull
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'ancestor ACL')

            Set-MigrationTestAcl $f.OldBase $cleanBaseAcl
            $badRoot = Get-Acl -LiteralPath $f.OldPrivate.Root
            [void]$badRoot.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'ReadAndExecute', 'None', 'None', 'Allow')))
            Set-MigrationTestAcl $f.OldPrivate.Root $badRoot
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'another identity')
        } finally {
            Set-MigrationTestAcl $f.OldPrivate.Root $cleanRootAcl
            Set-MigrationTestAcl $f.OldBase $cleanBaseAcl
        }

        [IO.File]::AppendAllText($f.OldPrivate.Helper, '# tampered')
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'modified')
        [IO.File]::WriteAllBytes($f.OldPrivate.Helper, $helperBytes)

        $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('& ''' + $f.OldPrivate.Helper.Replace("'", "''") + ''''))
        [IO.File]::WriteAllText($f.Config, ($configText + "`n[unmanaged]`nargs = [" + (ConvertTo-TomlString $encodedPayload) + "]`n"))
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'Unmanaged legacy')
        Assert-Equal ([IO.File]::ReadAllBytes($f.OldPrivate.Providers)) $sourceBytes
    }
}

Add-RelayTest 'CredentialMigration' 'Relocation migration rollback restores pre-migration EncodedCommand configs and completes on retry' {
    Invoke-PreviousPrivateCredentialScenario {
        param($f)
        $before = [IO.File]::ReadAllBytes($f.Config)
        $original = (Get-Command Invoke-RelaySharedConfigPlan).ScriptBlock
        $script:RTMigrationCalls = 0
        try {
            Set-Item Function:script:Invoke-RelaySharedConfigPlan -Value {
                param($Plan)
                $script:RTMigrationCalls++
                if ($script:RTMigrationCalls -eq 2) { throw 'fixture state3 later failure' }
                & $original $Plan
            }
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'fixture state3 later failure')
        } finally {
            Set-Item Function:script:Invoke-RelaySharedConfigPlan -Value $original
            Remove-Variable RTMigrationCalls -Scope Script
        }
        Assert-Equal ([IO.File]::ReadAllBytes($f.Config)) $before
        Assert-True ([IO.File]::Exists($f.OldPrivate.Providers))
        Assert-True ([IO.File]::Exists($f.OldPrivate.Helper))
        Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config | Out-Null
        Assert-True (-not [IO.File]::Exists($f.OldPrivate.Providers))
    }
}

Add-RelayTest 'CredentialMigration' 'Relocation migration rejects untrusted helper directory, forward-slash unmanaged refs, and differing dual stores' {
    Invoke-PreviousPrivateCredentialScenario {
        param($f)
        $sourceBytes = [IO.File]::ReadAllBytes($f.OldPrivate.Providers)
        $configText = [IO.File]::ReadAllText($f.Config)
        $credDir = [IO.Path]::GetDirectoryName($f.OldPrivate.Helper)
        $cleanCredAcl = New-Object Security.AccessControl.DirectorySecurity
        $cleanCredAcl.SetAccessRuleProtection($false, $false)
        try {
            $badProtectedCredAcl = New-Object Security.AccessControl.DirectorySecurity
            $badProtectedCredAcl.SetAccessRuleProtection($true, $false)
            $cur = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $sys = [Security.Principal.SecurityIdentifier]'S-1-5-18'
            foreach ($s in @($cur, $sys)) {
                [void]$badProtectedCredAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($s, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            }
            if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.Directory]::SetAccessControl($credDir, $badProtectedCredAcl) }
            else { [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.DirectoryInfo($credDir)), $badProtectedCredAcl) }
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'inherit the protected root ACL')

            $badExtraCredAcl = New-Object Security.AccessControl.DirectorySecurity
            $badExtraCredAcl.SetAccessRuleProtection($false, $false)
            [void]$badExtraCredAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'Modify', 'None', 'None', 'Allow')))
            if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.Directory]::SetAccessControl($credDir, $badExtraCredAcl) }
            else { [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.DirectoryInfo($credDir)), $badExtraCredAcl) }
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'another identity')
        } finally {
            if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.Directory]::SetAccessControl($credDir, $cleanCredAcl) }
            else { [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.DirectoryInfo($credDir)), $cleanCredAcl) }
        }

        try {
            $slashRef = $f.OldPrivate.Helper.Replace('\', '/')
            [IO.File]::WriteAllText($f.Config, ($configText + "`n[unmanaged]`nscript = " + (ConvertTo-TomlString $slashRef) + "`n"))
            [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'Unmanaged legacy')
        } finally {
            [IO.File]::WriteAllText($f.Config, $configText)
        }

        $legacyProviders = Join-Path $f.Data 'providers.json'
        $different = @((Read-RelayJson -Path $f.OldPrivate.Providers) | ForEach-Object { $_ })
        $different[0].Name = 'Conflict Name'
        Write-RelayJson -Path $legacyProviders -Value @($different)
        [void](Assert-Throws { Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config } 'differ')

        [IO.File]::WriteAllBytes($legacyProviders, $sourceBytes)
        Initialize-RelayStore -Path $f.Data -MigrateLegacy -ConfigPath $f.Config | Out-Null
        Assert-True (-not [IO.File]::Exists($legacyProviders))
        Assert-True (-not [IO.File]::Exists($f.OldPrivate.Providers))
        Assert-True (-not [IO.File]::Exists($f.OldPrivate.Helper))
        Assert-True ([IO.File]::Exists($f.NewPrivate.Providers))
        Assert-Equal ([IO.File]::ReadAllBytes($f.NewPrivate.Providers)) $sourceBytes
    }
}
