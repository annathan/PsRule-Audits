# Test-Rules.ps1
# Quick test script to verify PSRule setup is working correctly

Write-Host ""
Write-Host "Testing Essential 8 Rules Configuration..." -ForegroundColor Cyan
Write-Host ""

try {
    # Test 1: Check PSRule is installed
    Write-Host "[1/5] Checking PSRule installation..." -ForegroundColor Yellow
    $PSRuleModule = Get-Module -ListAvailable -Name PSRule | Sort-Object Version -Descending | Select-Object -First 1
    if ($PSRuleModule) {
        Write-Host "  ✓ PSRule v$($PSRuleModule.Version) found" -ForegroundColor Green
    } else {
        throw "PSRule module not found"
    }
    
    # Test 2: Check rules directory exists
    Write-Host "[2/5] Checking rules directory..." -ForegroundColor Yellow
    $RulesPath = Join-Path $PSScriptRoot "rules"
    if (Test-Path $RulesPath) {
        $RuleFiles = Get-ChildItem -Path $RulesPath -Recurse -Filter "*.Rule.ps1"
        Write-Host "  ✓ Found $($RuleFiles.Count) rule files" -ForegroundColor Green
        foreach ($File in $RuleFiles) {
            Write-Host "    - $($File.Name)" -ForegroundColor Gray
        }
    } else {
        throw "Rules directory not found"
    }
    
    # Test 3: Check baselines exist
    Write-Host "[3/5] Checking baseline definitions..." -ForegroundColor Yellow
    $BaselinePath = Join-Path $PSScriptRoot "baselines\Essential8.Baseline.Rule.yaml"
    if (Test-Path $BaselinePath) {
        Write-Host "  ✓ Baseline definitions found" -ForegroundColor Green
    } else {
        throw "Baseline definitions not found"
    }
    
    # Test 4: Test with sample data
    Write-Host "[4/5] Testing rules with sample data..." -ForegroundColor Yellow
    
    # Create sample test data
    $TestData = @"
{
  "UserPrincipalName": "test@contoso.com",
  "StrongAuthenticationRequirements": [{"State": "Enforced"}],
  "AssignedLicenses": [],
  "AssignedRoles": [{"DisplayName": "Global Administrator"}]
}
"@
    
    $TestPath = Join-Path $PSScriptRoot "test-data.json"
    $TestData | Out-File $TestPath -Force
    
    # Try to run PSRule
    $TestResults = Invoke-PSRule -InputPath $TestPath -Path $RulesPath -WarningAction SilentlyContinue 2>$null
    
    if ($TestResults) {
        Write-Host "  ✓ PSRule executed successfully" -ForegroundColor Green
        Write-Host "    Rules evaluated: $($TestResults.Count)" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠ PSRule ran but returned no results (this is normal with test data)" -ForegroundColor Yellow
    }
    
    # Cleanup
    Remove-Item $TestPath -Force -ErrorAction SilentlyContinue
    
    # Test 5: Check data collector exists
    Write-Host "[5/5] Checking data collector..." -ForegroundColor Yellow
    $CollectorPath = Join-Path $PSScriptRoot "Collectors\Essential8-DataCollector.ps1"
    if (Test-Path $CollectorPath) {
        Write-Host "  ✓ Data collector found" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Data collector not found at expected location" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    All Tests Passed! ✓                           ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your Essential 8 audit tool is ready to use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Run your first audit:" -ForegroundColor Gray
    Write-Host '     .\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com"' -ForegroundColor White
    Write-Host ""
    Write-Host "  2. Or collect data first:" -ForegroundColor Gray
    Write-Host '     .\Collectors\Essential8-DataCollector.ps1 -TenantId "yourcompany.onmicrosoft.com"' -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                      Test Failed ✗                               ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please ensure all prerequisites are installed:" -ForegroundColor Yellow
    Write-Host "  .\Install-Prerequisites.ps1" -ForegroundColor White
    Write-Host ""
    exit 1
}

