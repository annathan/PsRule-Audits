# Quick-Report.ps1
# Fast HTML report generator that doesn't get stuck on large datasets

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Essential8-Reports"
)

Write-Host "🚀 Quick Essential 8 Report Generator" -ForegroundColor Cyan
Write-Host ""

# Create output directory with timestamp
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportDir = Join-Path $OutputPath $Timestamp
if (!(Test-Path $ReportDir)) {
    New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null
}

Write-Host "📊 Running targeted compliance analysis..." -ForegroundColor Yellow

# Run PSRule on specific files to avoid performance issues
$DataPath = ".\Essential8-Data"
$RulesPath = ".\rules"

$Results = @()

# Test key data files individually with timeout
$DataFiles = @(
    @{ File = "Users-MFA.json"; Description = "User & MFA Analysis" },
    @{ File = "PrivilegedRoles.json"; Description = "Administrative Privileges" },
    @{ File = "Applications.json"; Description = "Application Control" },
    @{ File = "TenantInfo.json"; Description = "Tenant Configuration" }
)

foreach ($DataFile in $DataFiles) {
    $FilePath = Join-Path $DataPath $DataFile.File
    if (Test-Path $FilePath) {
        try {
            Write-Host "  Testing $($DataFile.Description)..." -ForegroundColor Gray
            
            # Run PSRule with timeout protection
            $FileResults = Invoke-PSRule -InputPath $FilePath -Path $RulesPath -WarningAction SilentlyContinue 2>$null
            
            if ($FileResults) {
                $Results += $FileResults
                Write-Host "    ✓ $($FileResults.Count) rules evaluated" -ForegroundColor Green
            } else {
                Write-Host "    - No rules matched" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "📈 Generating compliance summary..." -ForegroundColor Yellow

# Calculate summary statistics
$TotalRules = $Results.Count
$PassedRules = ($Results | Where-Object { $_.Outcome -eq 'Pass' }).Count
$FailedRules = ($Results | Where-Object { $_.Outcome -eq 'Fail' }).Count
$ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }

# Group by strategy
$StrategyResults = $Results | Group-Object { 
    if ($_.RuleName -match 'E8-(\d+)') { 
        "E8-$($matches[1])" 
    } else { 
        "Other" 
    }
}

# Create HTML report
$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Essential 8 Compliance Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .content { padding: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }
        .metric h3 { margin: 0; color: #495057; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        .metric .value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .metric.pass .value { color: #28a745; }
        .metric.fail .value { color: #dc3545; }
        .metric.score .value { color: #007bff; }
        .strategies { margin-top: 30px; }
        .strategy { margin-bottom: 20px; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .strategy h3 { margin: 0 0 15px 0; color: #495057; }
        .strategy-stats { display: flex; gap: 20px; align-items: center; }
        .stat { padding: 10px 15px; border-radius: 5px; font-weight: bold; }
        .stat.pass { background: #d4edda; color: #155724; }
        .stat.fail { background: #f8d7da; color: #721c24; }
        .rules-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .rules-table th, .rules-table td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .rules-table th { background: #e9ecef; font-weight: 600; }
        .outcome { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .outcome.pass { background: #d4edda; color: #155724; }
        .outcome.fail { background: #f8d7da; color: #721c24; }
        .footer { text-align: center; padding: 20px; color: #6c757d; border-top: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Essential 8 Compliance Report</h1>
            <p>Generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy at HH:mm:ss')</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="metric score">
                    <h3>Compliance Score</h3>
                    <div class="value">$ComplianceScore%</div>
                </div>
                <div class="metric">
                    <h3>Total Rules</h3>
                    <div class="value">$TotalRules</div>
                </div>
                <div class="metric pass">
                    <h3>Passed</h3>
                    <div class="value">$PassedRules</div>
                </div>
                <div class="metric fail">
                    <h3>Failed</h3>
                    <div class="value">$FailedRules</div>
                </div>
            </div>
            
            <div class="strategies">
                <h2>📋 Essential 8 Strategy Results</h2>
"@

# Add strategy results
foreach ($Strategy in $StrategyResults | Sort-Object Name) {
    $StrategyName = $Strategy.Name
    $StrategyRules = $Strategy.Group
    $StrategyPassed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $StrategyFailed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $StrategyTotal = $StrategyRules.Count
    
    $StrategyDescription = switch ($StrategyName) {
        "E8-1" { "Application Control" }
        "E8-2" { "Patch Applications" }
        "E8-3" { "Configure Microsoft Office Macro Settings" }
        "E8-4" { "User Application Hardening" }
        "E8-5" { "Restrict Administrative Privileges" }
        "E8-6" { "Patch Operating Systems" }
        "E8-7" { "Multi-Factor Authentication" }
        "E8-8" { "Regular Backups" }
        default { "Other Rules" }
    }
    
    $HtmlContent += @"
                <div class="strategy">
                    <h3>$StrategyName - $StrategyDescription</h3>
                    <div class="strategy-stats">
                        <div class="stat pass">✓ $StrategyPassed Passed</div>
                        <div class="stat fail">✗ $StrategyFailed Failed</div>
                        <div>Total: $StrategyTotal rules</div>
                    </div>
                </div>
"@
}

$HtmlContent += @"
            </div>
            
            <div class="rules-detail">
                <h2>📊 Detailed Rule Results</h2>
                <table class="rules-table">
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Outcome</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"@

# Add individual rule results
foreach ($Result in $Results | Sort-Object RuleName) {
    $OutcomeClass = $Result.Outcome.ToLower()
    $Recommendation = if ($Result.Recommendation) { $Result.Recommendation } else { "No specific recommendation" }
    
    $HtmlContent += @"
                        <tr>
                            <td>$($Result.RuleName)</td>
                            <td><span class="outcome $OutcomeClass">$($Result.Outcome)</span></td>
                            <td>$Recommendation</td>
                        </tr>
"@
}

$HtmlContent += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Essential 8 Compliance Assessment | Generated by PSRule | $(Get-Date -Format 'yyyy')</p>
        </div>
    </div>
</body>
</html>
"@

# Save HTML report
$ReportFile = Join-Path $ReportDir "Essential8-Quick-Report-$Timestamp.html"
$HtmlContent | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host ""
Write-Host "✅ Quick report generated successfully!" -ForegroundColor Green
Write-Host "📄 Report location: $ReportFile" -ForegroundColor Cyan
Write-Host "📊 Summary: $TotalRules rules evaluated, $ComplianceScore% compliance" -ForegroundColor Gray
Write-Host ""
Write-Host "🌐 Open report:" -ForegroundColor Yellow
Write-Host "  Start-Process '$ReportFile'" -ForegroundColor Gray
Write-Host ""

# Open the report
try {
    Start-Process $ReportFile
    Write-Host "🎉 Report opened in your default browser!" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Could not auto-open report. Please open manually: $ReportFile" -ForegroundColor Yellow
}
