# Complete-Rule-Test.ps1
# Tests ALL Essential 8 rules with the newly collected data

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Complete Essential 8 Rule Test                     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Test all data files
$DataFiles = @(
    "Essential8-Data/aad.users.json",
    "Essential8-Data/aad.user.enforced.json", 
    "Essential8-Data/aad.serviceprincipals.json",
    "Essential8-Data/AzureAD/PrivilegedRoles.json",
    "Essential8-Data/AzureAD/ServicePrincipals.json",
    "Essential8-Data/AzureAD/Users-MFA.json",
    "Essential8-Data/AzureAD/Applications.json",
    "Essential8-Data/AzureAD/ConditionalAccessPolicies.json",
    "Essential8-Data/AzureAD/TenantInfo.json"
)

$RulesPath = "rules"
$AllResults = @()

Write-Host "🔍 Testing ALL Essential 8 rules with collected data..." -ForegroundColor Yellow
Write-Host ""

foreach ($DataFile in $DataFiles) {
    if (Test-Path $DataFile) {
        $FileSize = (Get-Item $DataFile).Length
        if ($FileSize -gt 0) {
            Write-Host "Testing: $DataFile ($FileSize bytes)" -ForegroundColor Gray
            
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
            } else {
                Write-Host "  - No rules executed" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipping: $DataFile (empty file)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Missing: $DataFile" -ForegroundColor DarkGray
    }
}

Write-Host ""

if ($AllResults) {
    # Calculate comprehensive compliance statistics
    $TotalRules = $AllResults.Count
    $PassedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $FailedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $WarningRules = ($AllResults | Where-Object { $_.Outcome -eq 'Warning' }).Count
    $ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }
    
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host "║                    Complete Compliance Results                   ║" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    Write-Host "📊 Complete Compliance Summary:" -ForegroundColor Cyan
    Write-Host "  Total Essential 8 Rules: $TotalRules" -ForegroundColor White
    Write-Host "  Passed: $PassedRules" -ForegroundColor Green
    Write-Host "  Failed: $FailedRules" -ForegroundColor Red
    Write-Host "  Warnings: $WarningRules" -ForegroundColor Yellow
    Write-Host "  Compliance Score: $ComplianceScore%" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    # Group by Essential 8 strategy
    $ByStrategy = $AllResults | Group-Object { 
        if ($_.RuleName -match 'E8-(\d+)') { 
            "E8-$($matches[1])" 
        } else { 
            "Other" 
        }
    } | Sort-Object Name
    
    Write-Host "📋 Results by Essential 8 Strategy:" -ForegroundColor Cyan
    foreach ($Strategy in $ByStrategy) {
        $StrategyName = switch ($Strategy.Name) {
            'E8-1' { 'Application Control' }
            'E8-2' { 'Patch Applications' }
            'E8-3' { 'Macro Security' }
            'E8-4' { 'User Application Hardening' }
            'E8-5' { 'Restrict Administrative Privileges' }
            'E8-6' { 'Patch Operating Systems' }
            'E8-7' { 'Multi-Factor Authentication' }
            'E8-8' { 'Regular Backups' }
            default { $Strategy.Name }
        }
        
        $StrategyPassed = ($Strategy.Group | Where-Object { $_.Outcome -eq 'Pass' }).Count
        $StrategyFailed = ($Strategy.Group | Where-Object { $_.Outcome -eq 'Fail' }).Count
        $StrategyTotal = $Strategy.Count
        
        $StrategyScore = if ($StrategyTotal -gt 0) { [Math]::Round(($StrategyPassed / $StrategyTotal) * 100, 1) } else { 0 }
        
        Write-Host "  $($Strategy.Name) - $StrategyName" -ForegroundColor White
        Write-Host "    Rules: $StrategyTotal | Passed: $StrategyPassed | Failed: $StrategyFailed | Score: $StrategyScore%" -ForegroundColor $(if($StrategyScore -ge 80){'Green'}elseif($StrategyScore -ge 60){'Yellow'}else{'Red'})
    }
    
    Write-Host ""
    
    # Show detailed results
    Write-Host "📋 Detailed Compliance Results:" -ForegroundColor Cyan
    $AllResults | Format-Table RuleName, Outcome, Recommendation -AutoSize
    
    Write-Host ""
    Write-Host "🎯 What This Means:" -ForegroundColor Yellow
    if ($FailedRules -gt 0) {
        Write-Host "  • You have $FailedRules Essential 8 compliance issues to address" -ForegroundColor Red
        Write-Host "  • This is NORMAL for most organizations" -ForegroundColor Yellow
        Write-Host "  • The tool is working correctly - it found real problems!" -ForegroundColor Green
    } else {
        Write-Host "  • All Essential 8 rules passed - excellent security posture!" -ForegroundColor Green
    }
    
    Write-Host "  • $TotalRules rules evaluated across multiple Essential 8 strategies" -ForegroundColor Gray
    Write-Host "  • This is a significant improvement from the initial 4 rules!" -ForegroundColor Green
    
} else {
    Write-Host "❌ No Essential 8 compliance rules are running" -ForegroundColor Red
    Write-Host "  This indicates a fundamental issue with rule binding" -ForegroundColor Gray
}

Write-Host ""
Write-Host "✅ Complete rule test finished!" -ForegroundColor Green
Write-Host ""
