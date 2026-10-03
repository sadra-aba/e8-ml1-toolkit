<#
    E8Toolkit.Tests.ps1
    Unit tests for the pure logic and the evidence-render pipeline. No live Microsoft
    Graph connection is required. Written for Pester 5/6 (dashed assertion syntax).

    Run:  Invoke-Pester -Path .\tests\E8Toolkit.Tests.ps1
#>

BeforeAll {
    $here       = Split-Path -Parent $PSCommandPath
    $root       = Split-Path -Parent $here
    $script:ToolkitRoot = $root
    $script:ModulePath  = Join-Path $root 'src\Common\E8Toolkit.psm1'
    $script:PackScript  = Join-Path $root 'src\Evidence\New-EvidencePack.ps1'
    $script:Fixtures    = Join-Path $here 'fixtures'
    Import-Module $script:ModulePath -Force

    function New-MockCaPolicy ($State, $Apps, $Controls) {
        [pscustomobject]@{
            State = $State
            Conditions = [pscustomobject]@{ Applications = [pscustomobject]@{ IncludeApplications = $Apps } }
            GrantControls = [pscustomobject]@{ BuiltInControls = $Controls }
        }
    }
    function New-MockUsersPolicy ($Inc, $IncG, $Exc, $ExcG) {
        [pscustomobject]@{ Conditions = [pscustomobject]@{ Users = [pscustomobject]@{
            IncludeUsers=$Inc; IncludeGroups=$IncG; ExcludeUsers=$Exc; ExcludeGroups=$ExcG } } }
    }
}

Describe 'New-E8Verdict (verdict contract)' {
    It 'produces every contract field' {
        $v = New-E8Verdict -ControlId 'E8-ML1-MFA' -Strategy 'Multi-factor authentication' `
            -Verdict 'Compliant' -Automatability 'Automated' -VerdictReason 'ok' -TenantDomain 'x.onmicrosoft.com'
        $v.controlId      | Should -Be 'E8-ML1-MFA'
        $v.maturityLevel  | Should -Be 1
        $v.verdict        | Should -Be 'Compliant'
        $v.automatability | Should -Be 'Automated'
        $v.collectedUtc   | Should -Not -BeNullOrEmpty
        ($v.coverage -is [hashtable]) | Should -Be $true
        ($v.PSObject.Properties.Name -contains 'evidence') | Should -Be $true
    }
    It 'rejects an invalid verdict value' {
        { New-E8Verdict -ControlId 'x' -Strategy 'y' -Verdict 'Nope' -Automatability 'Automated' -VerdictReason 'r' } | Should -Throw
    }
    It 'rejects an invalid automatability value' {
        { New-E8Verdict -ControlId 'x' -Strategy 'y' -Verdict 'Compliant' -Automatability 'Magic' -VerdictReason 'r' } | Should -Throw
    }
}

Describe 'Get-E8ControlRegister' {
    It 'contains all eight strategies' {
        @(Get-E8ControlRegister).Count | Should -Be 8
    }
    It 'references a collector file that exists for each entry' {
        foreach ($e in Get-E8ControlRegister) {
            $p = Join-Path $ToolkitRoot ("src\Collectors\{0}.ps1" -f $e.Collector)
            Test-Path $p | Should -Be $true
        }
    }
}

Describe 'Test-E8CaPolicyRequiresMfa' {
    It 'is true for enabled + all apps + mfa' {
        Test-E8CaPolicyRequiresMfa -Policy (New-MockCaPolicy 'enabled' @('All') @('mfa')) | Should -Be $true
    }
    It 'is false when disabled' {
        Test-E8CaPolicyRequiresMfa -Policy (New-MockCaPolicy 'disabled' @('All') @('mfa')) | Should -Be $false
    }
    It 'is false when not targeting all apps' {
        Test-E8CaPolicyRequiresMfa -Policy (New-MockCaPolicy 'enabled' @('SomeApp') @('mfa')) | Should -Be $false
    }
    It 'is false without the mfa grant control' {
        Test-E8CaPolicyRequiresMfa -Policy (New-MockCaPolicy 'enabled' @('All') @('compliantDevice')) | Should -Be $false
    }
}

Describe 'Resolve-E8CaCoveredUserIds' {
    BeforeAll {
        $script:Users = @(
            [pscustomobject]@{ Id='u1' }, [pscustomobject]@{ Id='u2' }, [pscustomobject]@{ Id='u3' }
        )
    }
    It 'covers all assessable users with IncludeUsers=All' {
        $r = Resolve-E8CaCoveredUserIds -Policy (New-MockUsersPolicy @('All') @() @() @()) -AssessableUsers $Users
        @($r.CoveredIds).Count | Should -Be 3
    }
    It 'honours an excluded user' {
        $r = Resolve-E8CaCoveredUserIds -Policy (New-MockUsersPolicy @('All') @() @('u2') @()) -AssessableUsers $Users
        @($r.CoveredIds).Count | Should -Be 2
        $r.CoveredIds -contains 'u2' | Should -Be $false
    }
    It 'covers only named included users' {
        $r = Resolve-E8CaCoveredUserIds -Policy (New-MockUsersPolicy @('u1') @() @() @()) -AssessableUsers $Users
        @($r.CoveredIds).Count | Should -Be 1
        $r.CoveredIds -contains 'u1' | Should -Be $true
    }
}

Describe 'New-E8SyntheticPassword' {
    It 'returns a complex password of expected length' {
        $p = New-E8SyntheticPassword
        $p.Length | Should -Be 28
        $p.StartsWith('Aa1!') | Should -Be $true
    }
    It 'returns a different value each call' {
        (New-E8SyntheticPassword) | Should -Not -Be (New-E8SyntheticPassword)
    }
}

Describe 'Get-E8Config placeholder guard' {
    It 'throws while REPLACE_ME remains' {
        $bad = Join-Path $TestDrive 'bad.json'
        '{ "output": { "directory": "./output" }, "x": "REPLACE_ME" }' | Set-Content -LiteralPath $bad -Encoding UTF8
        { Get-E8Config -Path $bad } | Should -Throw
    }
    It 'loads a clean config' {
        $good = Join-Path $TestDrive 'good.json'
        '{ "output": { "directory": "./output" } }' | Set-Content -LiteralPath $good -Encoding UTF8
        (Get-E8Config -Path $good).output.resolvedDirectory | Should -Not -BeNullOrEmpty
    }
}

Describe 'Wait-E8Condition' {
    It 'returns true quickly when the condition is already met' {
        Wait-E8Condition -Condition { $true } -TimeoutSeconds 5 -PollSeconds 1 | Should -Be $true
    }
    It 'returns false on timeout' {
        Wait-E8Condition -Condition { $false } -TimeoutSeconds 1 -PollSeconds 1 | Should -Be $false
    }
}

Describe 'Scope lists' {
    It 'delegated scopes include ReadWrite' {
        (Get-E8ScopeList) -match 'ReadWrite' | Should -Not -BeNullOrEmpty
    }
    It 'read-only scopes exclude ReadWrite' {
        @((Get-E8ReadOnlyScopeList) | Where-Object { $_ -match 'ReadWrite' }).Count | Should -Be 0
    }
}

Describe 'New-EvidencePack rendering' {
    It 'renders the known-good fixture with a Compliant badge and no placeholders' {
        $out = Join-Path $TestDrive 'good.html'
        & $PackScript -RunJsonPath (Join-Path $Fixtures 'run-known-good.json') -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match '<!doctype'
        $html | Should -Match 'Compliant'
        $html | Should -Not -Match 'REPLACE_ME'
    }
    It 'renders the known-bad fixture with NonCompliant, Blocked and attestation states' {
        $out = Join-Path $TestDrive 'bad.html'
        & $PackScript -RunJsonPath (Join-Path $Fixtures 'run-known-bad.json') -OutputPath $out | Out-Null
        $html = Get-Content $out -Raw
        $html | Should -Match 'NonCompliant'
        $html | Should -Match 'LicensingBlocked'
        $html | Should -Match 'NotAssessed'
    }
}
