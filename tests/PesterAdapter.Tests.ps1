#requires -Version 5.1
# Optional Pester 3.4+ adapter. Prefer Run-Tests.ps1 -UsePester, or Invoke-Pester
# -Script @{Path='...\PesterAdapter.Tests.ps1';Parameters=@{ScriptPath='...\codex-relay.ps1'}}
param(
    [string]$ScriptPath = '',
    [string[]]$Suite = @()
)
. (Join-Path $PSScriptRoot 'Run-Tests.ps1') -ScriptPath $ScriptPath -Suite $Suite -AdapterMode
try {
    foreach ($suiteName in @($script:RTSelected | Select-Object -ExpandProperty Suite -Unique)) {
        Describe ('Relay ' + $suiteName) {
            foreach ($relayTest in @($script:RTSelected | Where-Object { $_.Suite -eq $suiteName })) {
                It $relayTest.Name {
                    Invoke-RelayTestCase $relayTest
                }
            }
        }
    }
} finally {
    Stop-RelayMockServer
    Remove-TestRecorder
    if ($script:RTImportDirectory -and (Test-Path -LiteralPath $script:RTImportDirectory)) { Remove-Item -LiteralPath $script:RTImportDirectory -Force -Recurse }
    Assert-RelayConfigUnchanged $script:RTBeforeConfig
}
