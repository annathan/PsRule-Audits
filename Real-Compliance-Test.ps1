# Real-Compliance-Test.ps1
# Shows the REAL Essential 8 compliance results (not just test rules)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              REAL Essential 8 Compliance Results                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$DataFiles = @(
    "Essential8-Data/aad.users.json",
    "Essential8-Data/aad.user.enforced.json", 
    "Essential8-Data/aad.serviceprincipals.json"
)

$RulesPath = "rules"
$AllResults = @()

Write-Host "Running REAL Essential 8 compliance checks..." -ForegroundColor Yellow
Write-Host ""

foreach ($DataFile in $DataFiles) {
    if (Test-Path $DataFile) {
        Write-Host "Analyzing: $DataFile" -ForegroundColor Gray
        
        $Results = Invoke-PSRule -InputPath $DataFile -Path $RulesPath
        if ($Results) {
            # Filter out test rules to show only real compliance rules
            $RealResults = $Results | Where-Object { $_.RuleName -ne 'Essential8.Test.Simple' }
            if ($RealResults) {
                $AllResults += $RealResults
                Write-Host "  ✓ Found $($RealResults.Count) compliance rules" -ForegroundColor Green
            } else {
                Write-Host "  - No compliance rules matched this data" -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""

if ($AllResults) {
    # Calculate REAL compliance statistics
    $TotalRules = $AllResults.Count
    $PassedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $FailedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $WarningRules = ($AllResults | Where-Object { $_.Outcome -eq 'Warning' }).Count
    $ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }
    
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host "║                    REAL Compliance Results                       ║" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    Write-Host "📊 REAL Compliance Summary:" -ForegroundColor Cyan
    Write-Host "  Total Essential 8 Rules: $TotalRules" -ForegroundColor White
    Write-Host "  Passed: $PassedRules" -ForegroundColor Green
    Write-Host "  Failed: $FailedRules" -ForegroundColor Red
    Write-Host "  Warnings: $WarningRules" -ForegroundColor Yellow
    Write-Host "  Compliance Score: $ComplianceScore%" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    # Show detailed results
    Write-Host "📋 Detailed Compliance Results:" -ForegroundColor Cyan
    $AllResults | Format-Table RuleName, Outcome, Recommendation -AutoSize
    
    Write-Host ""
    Write-Host "🎯 What This Means:" -ForegroundColor Yellow
    if ($FailedRules -gt 0) {
        Write-Host "  • You have $FailedRules Essential 8 compliance issues to fix" -ForegroundColor Red
        Write-Host "  • This is NORMAL for most organizations" -ForegroundColor Yellow
        Write-Host "  • The tool is working correctly - it found real problems!" -ForegroundColor Green
    } else {
        Write-Host "  • All Essential 8 rules passed - excellent security posture!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "🚀 Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Review failed rules and implement recommendations" -ForegroundColor Gray
    Write-Host "  2. Run regular audits to track progress" -ForegroundColor Gray
    Write-Host "  3. Use this tool with customer tenants" -ForegroundColor Gray
    
} else {
    Write-Host "⚠ No Essential 8 compliance rules matched your data" -ForegroundColor Yellow
    Write-Host "  This might mean:" -ForegroundColor Gray
    Write-Host "  • Data structure needs adjustment" -ForegroundColor Gray
    Write-Host "  • Rules need to be updated for your data format" -ForegroundColor Gray
}

Write-Host ""
Write-Host "✅ Real compliance test completed!" -ForegroundColor Green
Write-Host ""
