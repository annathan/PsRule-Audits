# Quick-Test.ps1
# Simple test to verify Essential 8 rules are working with your data

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    Essential 8 Quick Test                        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Test with your existing data
$DataPath = "Essential8-Data"
$RulesPath = "rules"

Write-Host "Testing Essential 8 rules against your collected data..." -ForegroundColor Yellow
Write-Host ""

# Run PSRule analysis
$Results = Invoke-PSRule -InputPath $DataPath -Path $RulesPath

if ($Results) {
    Write-Host "✓ PSRule analysis completed successfully!" -ForegroundColor Green
    Write-Host ""
    
    # Show summary
    $TotalRules = $Results.Count
    $PassedRules = ($Results | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $FailedRules = ($Results | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $WarningRules = ($Results | Where-Object { $_.Outcome -eq 'Warning' }).Count
    $ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }
    
    Write-Host "Results Summary:" -ForegroundColor Cyan
    Write-Host "  Total Rules: $TotalRules" -ForegroundColor Gray
    Write-Host "  Passed: $PassedRules" -ForegroundColor Green
    Write-Host "  Failed: $FailedRules" -ForegroundColor Red
    Write-Host "  Warnings: $WarningRules" -ForegroundColor Yellow
    Write-Host "  Compliance Score: $ComplianceScore%" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    # Show some example results
    Write-Host "Sample Results:" -ForegroundColor Cyan
    $Results | Select-Object -First 10 | Format-Table RuleName, Outcome, Recommendation -AutoSize
    
    Write-Host ""
    Write-Host "✓ Your Essential 8 audit tool is working correctly!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Fix any authentication issues for data collection" -ForegroundColor Gray
    Write-Host "  2. Run full audit: .\Run-Essential8Audit.ps1 -TenantId 'yourtenant.onmicrosoft.com'" -ForegroundColor Gray
    Write-Host "  3. Generate HTML report for detailed analysis" -ForegroundColor Gray
    
} else {
    Write-Host "✗ No results returned from PSRule analysis" -ForegroundColor Red
    Write-Host ""
    Write-Host "This might indicate:" -ForegroundColor Yellow
    Write-Host "  - No data files found in Essential8-Data directory" -ForegroundColor Gray
    Write-Host "  - Data files are empty or invalid JSON" -ForegroundColor Gray
    Write-Host "  - Rules are not binding to the data correctly" -ForegroundColor Gray
}

Write-Host ""
