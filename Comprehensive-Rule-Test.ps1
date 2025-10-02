# Comprehensive-Rule-Test.ps1
# Shows ALL rules and explains why some aren't running

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Comprehensive Essential 8 Rule Analysis            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check what data we have
Write-Host "📊 Data Collection Status:" -ForegroundColor Yellow
$DataFiles = Get-ChildItem 'Essential8-Data' -Recurse -Filter '*.json'
foreach ($File in $DataFiles) {
    $Status = if ($File.Length -gt 0) { "✅ $($File.Length) bytes" } else { "❌ Empty (0 bytes)" }
    Write-Host "  $($File.Name): $Status" -ForegroundColor $(if($File.Length -gt 0){'Green'}else{'Red'})
}

Write-Host ""

# Run ALL rules to see what's available
Write-Host "🔍 Running ALL Essential 8 rules..." -ForegroundColor Yellow
$AllResults = Invoke-PSRule -InputPath 'Essential8-Data' -Path 'rules'

if ($AllResults) {
    Write-Host "✓ Found $($AllResults.Count) total rule evaluations" -ForegroundColor Green
    Write-Host ""
    
    # Group by rule name to see what's running
    $RuleGroups = $AllResults | Group-Object RuleName | Sort-Object Count -Descending
    
    Write-Host "📋 Rules That Are Running:" -ForegroundColor Green
    foreach ($Group in $RuleGroups) {
        $Outcomes = $Group.Group | Group-Object Outcome
        $PassCount = ($Outcomes | Where-Object { $_.Name -eq 'Pass' }).Count
        $FailCount = ($Outcomes | Where-Object { $_.Name -eq 'Fail' }).Count
        $WarnCount = ($Outcomes | Where-Object { $_.Name -eq 'Warning' }).Count
        
        $OutcomeSummary = @()
        if ($PassCount -gt 0) { $OutcomeSummary += "✅$PassCount" }
        if ($FailCount -gt 0) { $OutcomeSummary += "❌$FailCount" }
        if ($WarnCount -gt 0) { $OutcomeSummary += "⚠️$WarnCount" }
        
        Write-Host "  $($Group.Name): $($Group.Count) evaluations ($($OutcomeSummary -join ' '))" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Show what's missing
    Write-Host "❌ Rules That Are NOT Running (Missing Data):" -ForegroundColor Red
    Write-Host "  • Exchange Online rules (need Exchange data)" -ForegroundColor Gray
    Write-Host "  • SharePoint rules (need SharePoint data)" -ForegroundColor Gray
    Write-Host "  • Security & Compliance rules (need Security data)" -ForegroundColor Gray
    Write-Host "  • Patch Management rules (need system data)" -ForegroundColor Gray
    Write-Host "  • Application Control rules (need app data)" -ForegroundColor Gray
    Write-Host "  • User Hardening rules (need browser data)" -ForegroundColor Gray
    Write-Host "  • Backup rules (need backup data)" -ForegroundColor Gray
    
    Write-Host ""
    
    # Calculate real compliance score (excluding test rules)
    $RealResults = $AllResults | Where-Object { $_.RuleName -ne 'Essential8.Test.Simple' }
    if ($RealResults) {
        $TotalRules = $RealResults.Count
        $PassedRules = ($RealResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
        $FailedRules = ($RealResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
        $ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }
        
        Write-Host "📊 Current Compliance (Based on Available Data):" -ForegroundColor Cyan
        Write-Host "  Total Rules: $TotalRules" -ForegroundColor White
        Write-Host "  Passed: $PassedRules" -ForegroundColor Green
        Write-Host "  Failed: $FailedRules" -ForegroundColor Red
        Write-Host "  Compliance Score: $ComplianceScore%" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    }
    
    Write-Host ""
    Write-Host "🎯 What This Means:" -ForegroundColor Yellow
    Write-Host "  • Only MFA and Admin Privilege rules are running" -ForegroundColor Gray
    Write-Host "  • Other Essential 8 strategies need additional data collection" -ForegroundColor Gray
    Write-Host "  • This is normal for a partial data collection" -ForegroundColor Gray
    Write-Host "  • Full audits require complete data from all services" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "🚀 To Get Complete Coverage:" -ForegroundColor Cyan
    Write-Host "  1. Fix authentication issues for data collection" -ForegroundColor Gray
    Write-Host "  2. Run: .\Collectors\Essential8-DataCollector.ps1 -TenantId 'yourtenant.onmicrosoft.com'" -ForegroundColor Gray
    Write-Host "  3. Ensure all services are accessible" -ForegroundColor Gray
    Write-Host "  4. Re-run audit for complete Essential 8 assessment" -ForegroundColor Gray
    
} else {
    Write-Host "❌ No rules are running at all" -ForegroundColor Red
    Write-Host "  This indicates a fundamental issue with rule binding" -ForegroundColor Gray
}

Write-Host ""
Write-Host "✅ Comprehensive analysis completed!" -ForegroundColor Green
Write-Host ""
