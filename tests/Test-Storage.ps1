Add-RelayTest 'Storage' 'Store initialization is idempotent and an empty provider list is empty' {
    Assert-True (Test-Path -LiteralPath $script:RTCaseDirectory -PathType Container)
    Assert-Equal @(Get-RelayProviders).Count 0
    Assert-Equal (Initialize-RelayStore -Path $script:RTCaseDirectory) $script:RTCaseDirectory
    Assert-Equal @(Get-RelayProviders).Count 0
}
Add-RelayTest 'Storage' 'JSON Unicode, nested values and arrays round-trip' {
    $path = Join-Path $script:RTCaseDirectory '中文 store.json'
    $value = [pscustomobject]@{ Name = '中文 relay'; Models = @('one', 'two'); Nested = @{ Enabled = $true; Number = 7 }; Empty = @() }
    Write-RelayJson -Path $path -Value $value | Out-Null
    Assert-True (Test-Path -LiteralPath $path) 'Write-RelayJson did not create its parent directory/file'
    $read = Read-RelayJson -Path $path -Default $null
    Assert-Equal $read.Name $value.Name
    Assert-Equal @($read.Models) @('one', 'two')
    Assert-Equal $read.Nested.Enabled $true
    Assert-Equal $read.Nested.Number 7
    Assert-Equal @($read.Empty).Count 0
    Write-RelayJson -Path $path -Value @{ Changed = 'replacement' } | Out-Null
    Assert-Equal (Read-RelayJson -Path $path -Default $null).Changed 'replacement'
}
Add-RelayTest 'Storage' 'Missing JSON returns default; corrupt JSON never executes or overwrites data' {
    $default = [pscustomobject]@{ Marker = 'fallback'; Values = @('x') }
    $path = Join-Path $script:RTCaseDirectory 'unreadable.json'
    Assert-Equal (Read-RelayJson -Path $path -Default $default) $default
    foreach ($content in @('', '   ', '{ broken json', '$(throw "must never execute")')) {
        [IO.File]::WriteAllText($path, $content, (New-Object Text.UTF8Encoding($false)))
        try { Read-RelayJson -Path $path -Default $default | Out-Null } catch {
            Assert-Match ([string]$_) '(?i)json|empty|invalid|format|空|损坏|格式|解析|读取'
        }
        Assert-Equal ([IO.File]::ReadAllText($path)) $content 'Reading malformed JSON must not rewrite the original data'
    }
}
Add-RelayTest 'Storage' 'JSON empty and singleton arrays preserve their structure on disk' {
    $path = Join-Path $script:RTCaseDirectory 'arrays.json'
    Write-RelayJson -Path $path -Value @() | Out-Null
    Assert-Match ([IO.File]::ReadAllText($path)) '^\s*\[\s*\]\s*$'
    Write-RelayJson -Path $path -Value @([pscustomobject]@{ Id = 'only' }) | Out-Null
    Assert-Match ([IO.File]::ReadAllText($path)) '^\s*\[' 'Singleton arrays must not serialize as an object'
    Assert-Equal @((Read-RelayJson -Path $path -Default @())).Count 1
}
Add-RelayTest 'Storage' 'DPAPI ciphertext round-trips for the current Windows account and is randomized' {
    Add-Type -AssemblyName System.Security
    $key = 'sk-测试-sensitive-' + [guid]::NewGuid().ToString('N')
    $a = Protect-RelayApiKey -ApiKey $key
    $b = Protect-RelayApiKey -ApiKey $key
    Assert-True ($a -is [string] -and $a.Length -gt 0) 'Protect must return a non-empty ciphertext string'
    Assert-True (-not $a.Contains($key)) 'Ciphertext contains plaintext'
    Assert-True ($a -cne $b) 'DPAPI encryption should use randomized protection'
    Assert-Equal (Unprotect-RelayApiKey -CipherText $a) $key
    Assert-Equal (Unprotect-RelayApiKey -CipherText $b) $key
    # Accept the standard ConvertFrom-SecureString representation or raw base64 DPAPI.
    if ($a -match '^[0-9a-fA-F]+$' -and ($a.Length % 2 -eq 0)) {
        $bytes = New-Object byte[] ($a.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($a.Substring($i * 2, 2), 16) }
    } else { $bytes = [Convert]::FromBase64String($a) }
    $clear = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $utf8 = [Text.Encoding]::UTF8.GetString($clear)
    $utf16 = [Text.Encoding]::Unicode.GetString($clear)
    Assert-True ($utf8 -ceq $key -or $utf16 -ceq $key) 'Ciphertext is not independently decryptable as CurrentUser DPAPI without hidden machine secrets'
}
Add-RelayTest 'Storage' 'Malformed/tampered ciphertext fails readably rather than yielding a key' {
    foreach ($cipher in @('not-dpapi', 'AQIDBA==', ('0' * 64))) {
        Assert-Throws { Unprotect-RelayApiKey -CipherText $cipher } | Out-Null
    }
    $valid = Protect-RelayApiKey -ApiKey 'tamper-key'
    $index = [Math]::Max(1, [int]($valid.Length / 2))
    $replacement = 'A'
    if ($valid[$index] -eq 'A') { $replacement = 'B' }
    $tampered = $valid.Substring(0, $index) + $replacement + $valid.Substring($index + 1)
    Assert-Throws { Unprotect-RelayApiKey -CipherText $tampered } | Out-Null
}
Add-RelayTest 'Storage' 'Providers persist, update by ID without duplication and delete independently' {
    $a = New-TestProvider -Name 'Same display name'
    $b = New-TestProvider -Name 'Same display name'
    Assert-True ($a.Id -ne $b.Id) 'Provider identity must not derive solely from the display name'
    Assert-Equal @(Get-RelayProviders).Count 2
    $a.Name = '重命名 provider'
    Save-RelayProvider -Provider $a | Out-Null
    Initialize-RelayStore -Path $script:RTCaseDirectory | Out-Null
    $all = @(Get-RelayProviders)
    Assert-Equal $all.Count 2
    Assert-Equal @($all | Where-Object { $_.Id -eq $a.Id })[0].Name '重命名 provider'
    # IDs are strict lowercase storage/cache keys, not case-insensitive aliases.
    $uppercase = $a | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $uppercase.Id = $a.Id.ToUpperInvariant()
    Assert-Throws { Save-RelayProvider -Provider $uppercase } '(?i)id|标识|格式|无效' | Out-Null
    Assert-Throws { Remove-RelayProvider -Provider $uppercase } '(?i)id|标识|格式|无效' | Out-Null
    Assert-Throws { Get-RelayModelCache -Provider $uppercase } '(?i)id|标识|格式|无效' | Out-Null
    Assert-Equal (ConvertTo-Json -InputObject @(Get-RelayProviders) -Depth 20 -Compress) (ConvertTo-Json -InputObject $all -Depth 20 -Compress) 'Invalid uppercase ID changed persisted providers'
    Remove-RelayProvider -Provider $a | Out-Null
    $remaining = @(Get-RelayProviders)
    Assert-Equal $remaining.Count 1
    Assert-Equal $remaining[0].Id $b.Id
    Assert-Equal (Get-TestProviderKey $remaining[0]) (Get-TestProviderKey $b)
    Assert-NoSecretInStore (Get-TestProviderKey $a)
    Assert-NoSecretInStore (Get-TestProviderKey $b)
}
Add-RelayTest 'Storage' 'Provider stores remain independent across data directories' {
    $a = New-TestProvider -Name 'Original store'
    $other = New-RelayTestDirectory
    try {
        Initialize-RelayStore -Path $other | Out-Null
        Assert-Equal @(Get-RelayProviders).Count 0
        New-TestProvider -Name 'Other store' | Out-Null
        Assert-Equal @(Get-RelayProviders).Count 1
        Initialize-RelayStore -Path $script:RTCaseDirectory | Out-Null
        $providers = @(Get-RelayProviders)
        Assert-Equal $providers.Count 1
        Assert-Equal $providers[0].Id $a.Id
    } finally { Initialize-RelayStore -Path $script:RTCaseDirectory | Out-Null; Remove-Item -LiteralPath $other -Recurse -Force }
}
Add-RelayTest 'Storage' 'Stored model and compatibility data do not leak across same-name providers' {
    $a = New-TestProvider -Name 'Same' -Fixture 'models-basic'
    $b = New-TestProvider -Name 'Same' -Fixture 'models-b'
    Get-RelayModels -Provider $a | Out-Null
    Get-RelayModels -Provider $b | Out-Null
    Set-MockFixture (Get-TestProviderKey $a) 'sse-valid'
    Test-RelayResponse -Provider $a -Model 'private-a' -TimeoutSeconds 8 | Out-Null
    Assert-Equal @((Get-RelayModelCache -Provider $b).Models) @('provider-b-only')
    Assert-Equal @(Get-RelayCompatibility -Provider $b).Count 0
}
