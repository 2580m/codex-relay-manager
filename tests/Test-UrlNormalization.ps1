Add-RelayTest 'UrlNormalization' 'Root, v1 and endpoint suffixes normalize without duplication' {
    $cases = @(
        @('https://example.invalid', 'https://example.invalid/v1'),
        @('https://example.invalid/', 'https://example.invalid/v1'),
        @('https://example.invalid/v1', 'https://example.invalid/v1'),
        @('https://example.invalid/v1/', 'https://example.invalid/v1'),
        @('https://example.invalid/models', 'https://example.invalid/v1'),
        @('https://example.invalid/responses', 'https://example.invalid/v1'),
        @('https://example.invalid/v1/models', 'https://example.invalid/v1'),
        @('https://example.invalid/v1/responses/', 'https://example.invalid/v1'),
        @($script:RTBaseUrl, ($script:RTBaseUrl + '/v1'))
    )
    foreach ($case in $cases) {
        $actual = Normalize-RelayBaseUrl -Url $case[0]
        Assert-Equal $actual $case[1] ('Unexpected normalization of ' + $case[0])
        Assert-Equal (Normalize-RelayBaseUrl -Url $actual) $actual 'Normalization must be idempotent'
    }
}
Add-RelayTest 'UrlNormalization' 'Unknown custom paths require an explicit choice' {
    foreach ($path in @('/gateway', '/openai/api', '/tenant/v2')) {
        $url = 'https://example.invalid' + $path
        Assert-Throws { Normalize-RelayBaseUrl -Url $url } | Out-Null
        Assert-Equal (Normalize-RelayBaseUrl -Url ($url + '/') -CustomPathMode Preserve) $url
        Assert-Equal (Normalize-RelayBaseUrl -Url ($url + '/') -CustomPathMode AppendV1) ($url + '/v1')
    }
}
Add-RelayTest 'UrlNormalization' 'Custom API roots with recognized v1/endpoints preserve their prefix' {
    foreach ($suffix in @('/v1', '/v1/', '/v1/models', '/v1/responses/')) {
        Assert-Equal (Normalize-RelayBaseUrl -Url ('https://example.invalid/gateway' + $suffix)) 'https://example.invalid/gateway/v1'
    }
}
Add-RelayTest 'UrlNormalization' 'Invalid or unsafe base URLs are rejected' {
    foreach ($url in @('', '   ', 'not a url', 'ftp://example.invalid', 'file:///C:/secret', 'https://', 'https://user:password@example.invalid/v1', 'https://example.invalid/v1?api_key=secret', 'https://example.invalid/v1#fragment')) {
        Assert-Throws { Normalize-RelayBaseUrl -Url $url } | Out-Null
    }
}
Add-RelayTest 'UrlNormalization' 'Normalization performs no HTTP requests' {
    $before = @(Get-MockRequests).Count
    Normalize-RelayBaseUrl -Url ($script:RTBaseUrl + '/models') | Out-Null
    Assert-Equal @(Get-MockRequests).Count $before
}
