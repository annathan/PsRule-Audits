# Demo-With-Your-Data.ps1
# Demonstrates Essential 8 rules working with your actual collected data

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Essential 8 Demo - Your Data                        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Test with your actual data files
$DataFiles = @(
    "Essential8-Data/aad.users.json",
    "Essential8-Data/aad.user.enforced.json", 
    "Essential8-Data/aad.serviceprincipals.json"
)

$RulesPath = "rules"

Write-Host "Testing Essential 8 rules against your collected data..." -ForegroundColor Yellow
Write-Host ""

$AllResults = @()

foreach ($DataFile in $DataFiles) {
    if (Test-Path $DataFile) {
        Write-Host "Testing: $DataFile" -ForegroundColor Gray
        
        $Results = Invoke-PSRule -InputPath $DataFile -Path $RulesPath
        if ($Results) {
            $AllResults += $Results
            Write-Host "  ✓ Found $($Results.Count) results" -ForegroundColor Green
        } else {
            Write-Host "  - No matching rules" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ✗ File not found: $DataFile" -ForegroundColor Red
    }
}

Write-Host ""

if ($AllResults) {
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    Analysis Complete! ✓                         ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    # Show summary
    $TotalRules = $AllResults.Count
    $PassedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $FailedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $WarningRules = ($AllResults | Where-Object { $_.Outcome -eq 'Warning' }).Count
    $ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }
    
    Write-Host "📊 Compliance Summary:" -ForegroundColor Cyan
    Write-Host "  Total Rules Evaluated: $TotalRules" -ForegroundColor White
    Write-Host "  Passed: $PassedRules" -ForegroundColor Green
    Write-Host "  Failed: $FailedRules" -ForegroundColor Red
    Write-Host "  Warnings: $WarningRules" -ForegroundColor Yellow
    Write-Host "  Compliance Score: $ComplianceScore%" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    # Show detailed results
    Write-Host "📋 Detailed Results:" -ForegroundColor Cyan
    $AllResults | Format-Table RuleName, Outcome, Recommendation -AutoSize
    
    Write-Host ""
    Write-Host "🎯 What This Means:" -ForegroundColor Yellow
    Write-Host "  • Your Essential 8 audit tool is working correctly!" -ForegroundColor Green
    Write-Host "  • Rules are evaluating your actual tenant data" -ForegroundColor Green
    Write-Host "  • You can now run full audits against any tenant" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "🚀 Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Fix authentication issues for fresh data collection" -ForegroundColor Gray
    Write-Host "  2. Run against customer tenants: .\Run-Essential8Audit.ps1 -TenantId 'customer.onmicrosoft.com'" -ForegroundColor Gray
    Write-Host "  3. Generate HTML reports for professional presentation" -ForegroundColor Gray
    
} else {
    Write-Host "⚠ No results found. This could mean:" -ForegroundColor Yellow
    Write-Host "  • Data files are empty or invalid" -ForegroundColor Gray
    Write-Host "  • Rules need adjustment for your data structure" -ForegroundColor Gray
    Write-Host "  • Authentication issues prevented proper data collection" -ForegroundColor Gray
}

Write-Host ""
Write-Host "✅ Demo completed!" -ForegroundColor Green
Write-Host ""
