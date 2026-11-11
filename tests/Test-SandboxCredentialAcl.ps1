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
    $root = $script:RTCaseDirectory
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
    $root = $script:RTCaseDirectory
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
