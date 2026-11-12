Add-RelayTest 'SandboxCredentialAcl' 'Local CodexSandboxUsers read execute is accepted but write access fails closed' {
    $sandbox = Get-RelayCodexSandboxSid
    if (-not $sandbox) { Assert-Equal (Get-RelayCodexSandboxSid) $null; return }
    Assert-Equal $sandbox ((New-Object Security.Principal.NTAccount([Environment]::MachineName, 'CodexSandboxUsers')).Translate([Security.Principal.SecurityIdentifier]).Value)
    $p = New-TestProvider
    $auth = Install-RelayCredentialHelper $p
    $result = Invoke-CredentialTestHelper $auth
    Assert-Equal $result.ExitCode 0
    Assert-Equal $result.Stdout (Get-TestProviderKey $p)
    Assert-Equal $result.Stderr ''
    $root = (Get-RelayPrivatePaths).Root
    $original = Get-Acl -LiteralPath $root
    $changed = Get-Acl -LiteralPath $root
    $sid = New-Object Security.Principal.SecurityIdentifier($sandbox)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$changed.AddAccessRule($rule)
    try {
        Set-CredentialTestAcl $root $changed
        $failure = Invoke-CredentialTestHelper $auth
        Assert-CredentialFailure $failure -Stage ROOT_ACL -Reason 'CodexSandboxUsers may only have read and execute access, not write or administrative permissions.' -Secrets @((Get-TestProviderKey $p), $p.EncryptedApiKey)
    } finally { Set-CredentialTestAcl $root $original }
}

Add-RelayTest 'SandboxCredentialAcl' 'Store initialization preserves project ACL and existing sandbox Modify permission' {
    $sandbox = Get-RelayCodexSandboxSid
    $workspace = Join-Path $script:RTCaseDirectory 'project-workspace'
    [void][IO.Directory]::CreateDirectory($workspace)
    if ($sandbox) {
        $acl = Get-Acl -LiteralPath $workspace
        $sid = New-Object Security.Principal.SecurityIdentifier($sandbox)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.SetAccessRule($rule)
        Set-CredentialTestAcl $workspace $acl
    }
    $before = (Get-Acl -LiteralPath $workspace).Sddl
    $dedicatedStore = Join-Path $script:RTCaseDirectory 'separate-relay-store'
    $oldData = $script:RelayDataDirectory
    try {
        Initialize-RelayStore -Path $dedicatedStore | Out-Null
        Assert-Equal (Get-Acl -LiteralPath $workspace).Sddl $before 'Initializing a credential store changed the project ACL'
        $source = Join-Path $workspace 'working-file.txt'
        [IO.File]::WriteAllText($source, 'initial')
        [IO.File]::AppendAllText($source, '-updated')
        Assert-Equal ([IO.File]::ReadAllText($source)) 'initial-updated'
        if ($sandbox) {
            $rules = (Get-Acl -LiteralPath $workspace).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
            $sandboxRules = @($rules | Where-Object { $_.IdentityReference.Value -eq $sandbox -and $_.AccessControlType -eq 'Allow' })
            Assert-True (@($sandboxRules | Where-Object { ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq [Security.AccessControl.FileSystemRights]::Modify }).Count -gt 0) 'Project sandbox Modify permission was removed'
        }
    } finally { $script:RelayDataDirectory = $oldData }
}

Add-RelayTest 'SandboxCredentialAcl' 'Sandbox read exception does not permit a different Windows identity' {
    $p = New-TestProvider
    $auth = Install-RelayCredentialHelper $p
    $root = (Get-RelayPrivatePaths).Root
    $original = Get-Acl -LiteralPath $root
    $changed = Get-Acl -LiteralPath $root
    $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($everyone, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$changed.AddAccessRule($rule)
    try {
        Set-CredentialTestAcl $root $changed
        $failure = Invoke-CredentialTestHelper $auth
        Assert-CredentialFailure $failure -Stage ROOT_ACL -Reason 'Credential path ACL grants access to another identity.' -Secrets @((Get-TestProviderKey $p), $p.EncryptedApiKey)
    } finally { Set-CredentialTestAcl $root $original }
}

Add-RelayTest 'SandboxCredentialAcl' 'Writable runtime and catalog roots do not grant access to private helper or ciphertext' {
    $p = New-TestProvider
    $auth = Install-RelayCredentialHelper $p
    $private = Get-RelayPrivatePaths
    Assert-True (-not $private.Root.StartsWith($script:RTCaseDirectory + '\', [StringComparison]::OrdinalIgnoreCase))
    Assert-True (-not $auth.HelperPath.StartsWith($auth.Cwd + '\', [StringComparison]::OrdinalIgnoreCase))
    Assert-True (-not [IO.File]::Exists((Join-Path $script:RTCaseDirectory 'providers.json')))
    Assert-True (Test-Path -LiteralPath $private.Providers)
    $rootAcl = Get-Acl -LiteralPath $script:RTCaseDirectory
    $privateAcl = (Get-Acl -LiteralPath $private.Root).Sddl
    $helperHash = (Get-FileHash -LiteralPath $auth.HelperPath).Hash
    $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $changed = Get-Acl -LiteralPath $script:RTCaseDirectory
    [void]$changed.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($everyone, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    try {
        Set-CredentialTestAcl $script:RTCaseDirectory $changed
        $result = Invoke-CredentialTestHelper $auth
        Assert-Equal $result.ExitCode 0
        Assert-Equal $result.Stderr ''
        Assert-Equal $result.Stdout (Get-TestProviderKey $p)
        Assert-Equal (Get-Acl -LiteralPath $private.Root).Sddl $privateAcl
        Assert-Equal (Get-FileHash -LiteralPath $auth.HelperPath).Hash $helperHash
        Assert-Equal @(Get-RelayProviders).Count 1
    } finally { Set-CredentialTestAcl $script:RTCaseDirectory $rootAcl }
}

Add-RelayTest 'SandboxCredentialAcl' 'Parent delete-child rename and ACL takeover rights are refused even with a protected vault' {
    $p = New-TestProvider
    $auth = Install-RelayCredentialHelper $p
    $private = Get-RelayPrivatePaths
    $before = (Get-Acl -LiteralPath $private.Root).Sddl
    $original = Get-Acl -LiteralPath $private.Base
    foreach ($rights in @('DeleteSubdirectoriesAndFiles', 'Delete', 'ChangePermissions', 'TakeOwnership')) {
        $changed = Get-Acl -LiteralPath $private.Base
        $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
        [void]$changed.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($everyone, $rights, 'Allow')))
        try {
            Set-CredentialTestAcl $private.Base $changed
            $result = Invoke-CredentialTestHelper $auth
            Assert-CredentialFailure $result -Stage PARENT_ACL -Reason 'Credential ancestor ACL permits replacement by another identity.' -Secrets @((Get-TestProviderKey $p), $p.EncryptedApiKey)
            [void](Assert-Throws { Install-RelayCredentialHelper $p } 'ancestor ACL')
            Assert-Equal (Get-Acl -LiteralPath $private.Root).Sddl $before
        } finally { Set-CredentialTestAcl $private.Base $original }
    }
}

Add-RelayTest 'SandboxCredentialAcl' 'Private storage inside or above the runtime data tree is rejected' {
    $saved = $script:RelayCredentialBaseDirectory
    try {
        foreach ($base in @($script:RTCaseDirectory, (Join-Path $script:RTCaseDirectory 'private'), (Split-Path $script:RTCaseDirectory -Parent))) {
            $script:RelayCredentialBaseDirectory = $base
            [void](Assert-Throws { Get-RelayPrivatePaths } 'separate')
        }
    } finally { $script:RelayCredentialBaseDirectory = $saved }
}

Add-RelayTest 'SandboxCredentialAcl' 'Default credential base directory lives outside UserProfile under CommonApplicationData with safe ancestors' {
    $defaultBase = Get-RelayDefaultCredentialBaseDirectory
    $userProfile = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile')).TrimEnd('\')
    $commonData = [IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    Assert-Equal ([IO.Path]::GetDirectoryName($defaultBase)) $commonData
    Assert-Equal ([IO.Path]::GetFileName($defaultBase)) ('codex-relay-private-' + $userSid)
    Assert-True (-not $defaultBase.Equals($userProfile, [StringComparison]::OrdinalIgnoreCase))
    Assert-True (-not $defaultBase.StartsWith($userProfile + '\', [StringComparison]::OrdinalIgnoreCase))
    Assert-RelayCredentialPath $defaultBase
    Assert-RelayCredentialParents $defaultBase

    $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'codex-relay.ps1'
    $cmd = "& { . '" + $scriptPath.Replace("'", "''") + "' -LibraryOnly; Write-Output `$script:RelayCredentialBaseDirectory }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $psExe = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System), 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    $bound = (& $psExe -NoProfile -NonInteractive -EncodedCommand $encoded) -join ''
    Assert-Equal $LASTEXITCODE 0
    Assert-Equal $bound.Trim() $defaultBase
}

Add-RelayTest 'SandboxCredentialAcl' 'Empty or whitespace CredentialBaseDirectory fails cleanly with Invalid credential data path' {
    $saved = $script:RelayCredentialBaseDirectory
    try {
        foreach ($bad in @('', '   ')) {
            $script:RelayCredentialBaseDirectory = $bad
            [void](Assert-Throws { Get-RelayPrivatePaths } 'Invalid credential data path')
        }
    } finally { $script:RelayCredentialBaseDirectory = $saved }
}
