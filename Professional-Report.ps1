# Professional-Report.ps1
# Comprehensive Essential 8 report with executive summary and full coverage

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Essential8-Reports"
)

Write-Host ""
Write-Host "🏢 Professional Essential 8 Compliance Report Generator" -ForegroundColor Cyan
Write-Host "   Comprehensive Microsoft 365 Security Assessment" -ForegroundColor Gray
Write-Host ""

# Create output directory with timestamp
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportDir = Join-Path $OutputPath $Timestamp
if (!(Test-Path $ReportDir)) {
    New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null
}

Write-Host "📊 Running comprehensive Essential 8 analysis..." -ForegroundColor Yellow

# Data collection summary
$DataPath = ".\Essential8-Data"
$RulesPath = ".\rules"

# Check what data we have
Write-Host "  Analyzing collected data..." -ForegroundColor Gray
$DataFiles = Get-ChildItem $DataPath -Filter "*.json" | Where-Object { $_.Length -gt 100 }
$DataSummary = @{}

foreach ($File in $DataFiles) {
    $Size = [Math]::Round($File.Length / 1KB, 1)
    $DataSummary[$File.Name] = $Size
    Write-Host "    $($File.Name): $Size KB" -ForegroundColor $(if($Size -gt 10){'Green'}else{'Yellow'})
}

Write-Host ""
Write-Host "🔍 Evaluating Essential 8 compliance rules..." -ForegroundColor Yellow

# Run comprehensive analysis on all data
$AllResults = @()
$DataCoverage = @{}

# Test each data file individually to get comprehensive coverage
$TestFiles = @(
    @{ File = "Users-MFA.json"; Category = "Identity & Access Management"; Strategy = "E8-5, E8-7" },
    @{ File = "PrivilegedRoles.json"; Category = "Administrative Privileges"; Strategy = "E8-5" },
    @{ File = "ServicePrincipals.json"; Category = "Application Security"; Strategy = "E8-1" },
    @{ File = "Applications.json"; Category = "Application Control"; Strategy = "E8-1" },
    @{ File = "TenantInfo.json"; Category = "Tenant Configuration"; Strategy = "E8-1, E8-5" },
    @{ File = "ConditionalAccessPolicies.json"; Category = "Access Controls"; Strategy = "E8-7" }
)

foreach ($TestFile in $TestFiles) {
    $FilePath = Join-Path $DataPath $TestFile.File
    if (Test-Path $FilePath) {
        try {
            Write-Host "  Analyzing $($TestFile.Category)..." -ForegroundColor Gray
            
            $FileResults = Invoke-PSRule -InputPath $FilePath -Path $RulesPath -WarningAction SilentlyContinue 2>$null
            
            if ($FileResults) {
                # Filter out test rules
                $ProductionResults = $FileResults | Where-Object { $_.RuleName -notlike "*Test*" -and $_.RuleName -notlike "*Simple*" }
                
                if ($ProductionResults) {
                    $AllResults += $ProductionResults
                    $DataCoverage[$TestFile.Category] = @{
                        Rules = $ProductionResults.Count
                        Passed = ($ProductionResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
                        Failed = ($ProductionResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
                        Strategy = $TestFile.Strategy
                    }
                    Write-Host "    ✓ $($ProductionResults.Count) production rules evaluated" -ForegroundColor Green
                } else {
                    Write-Host "    - No production rules matched" -ForegroundColor Yellow
                }
            } else {
                Write-Host "    - No rules bound to this data" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  Skipping $($TestFile.Category) - no data file" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "📈 Generating executive summary..." -ForegroundColor Yellow

# Calculate comprehensive statistics
$TotalRules = $AllResults.Count
$PassedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
$FailedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
$WarningRules = ($AllResults | Where-Object { $_.Outcome -eq 'Warning' }).Count
$ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }

# Determine compliance level
$ComplianceLevel = switch ($ComplianceScore) {
    { $_ -ge 90 } { @{ Level = "Excellent"; Color = "#28a745"; Description = "Strong security posture with minimal gaps" } }
    { $_ -ge 75 } { @{ Level = "Good"; Color = "#ffc107"; Description = "Solid security foundation with some areas for improvement" } }
    { $_ -ge 60 } { @{ Level = "Moderate"; Color = "#fd7e14"; Description = "Basic security measures in place, significant improvements needed" } }
    default { @{ Level = "Needs Improvement"; Color = "#dc3545"; Description = "Critical security gaps require immediate attention" } }
}

# Group by Essential 8 strategy
$StrategyResults = $AllResults | Group-Object { 
    if ($_.RuleName -match 'E8-(\d+)') { 
        switch ($matches[1]) {
            "1" { "E8-1: Application Control" }
            "2" { "E8-2: Patch Applications" }
            "3" { "E8-3: Configure Microsoft Office Macro Settings" }
            "4" { "E8-4: User Application Hardening" }
            "5" { "E8-5: Restrict Administrative Privileges" }
            "6" { "E8-6: Patch Operating Systems" }
            "7" { "E8-7: Multi-Factor Authentication" }
            "8" { "E8-8: Regular Backups" }
            default { "Other Essential 8 Rules" }
        }
    } else { 
        "Supporting Rules" 
    }
}

# Create comprehensive HTML report
$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Essential 8 Compliance Assessment - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 3em; margin-bottom: 10px; font-weight: 300; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; margin-bottom: 20px; }
        .header .meta { font-size: 0.9em; opacity: 0.8; }
        
        .executive-summary { padding: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .executive-summary h2 { font-size: 2.2em; margin-bottom: 20px; text-align: center; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .summary-card { background: rgba(255,255,255,0.1); padding: 25px; border-radius: 10px; text-align: center; backdrop-filter: blur(10px); }
        .summary-card h3 { font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; opacity: 0.8; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .summary-card .description { font-size: 0.9em; opacity: 0.9; }
        
        .compliance-level { text-align: center; padding: 30px; background: white; border-left: 5px solid $($ComplianceLevel.Color); margin: 20px; border-radius: 5px; }
        .compliance-level h3 { color: $($ComplianceLevel.Color); font-size: 1.8em; margin-bottom: 10px; }
        .compliance-level p { color: #666; font-size: 1.1em; }
        
        .content { padding: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; font-size: 1.8em; margin-bottom: 20px; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        
        .data-coverage { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .coverage-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; }
        .coverage-card h4 { color: #2c3e50; margin-bottom: 10px; }
        .coverage-stats { display: flex; gap: 15px; margin-top: 10px; }
        .stat { padding: 5px 10px; border-radius: 4px; font-size: 0.9em; font-weight: bold; }
        .stat.pass { background: #d4edda; color: #155724; }
        .stat.fail { background: #f8d7da; color: #721c24; }
        
        .strategies { margin-top: 30px; }
        .strategy { margin-bottom: 25px; padding: 25px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #e74c3c; }
        .strategy h3 { color: #2c3e50; margin-bottom: 15px; font-size: 1.3em; }
        .strategy-meta { display: flex; gap: 20px; align-items: center; margin-bottom: 15px; }
        .strategy-description { color: #666; font-style: italic; margin-bottom: 15px; }
        
        .rules-table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .rules-table th { background: #34495e; color: white; padding: 15px; text-align: left; font-weight: 600; }
        .rules-table td { padding: 12px 15px; border-bottom: 1px solid #ecf0f1; }
        .rules-table tr:hover { background: #f8f9fa; }
        .outcome { padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; }
        .outcome.pass { background: #d4edda; color: #155724; }
        .outcome.fail { background: #f8d7da; color: #721c24; }
        .outcome.warning { background: #fff3cd; color: #856404; }
        
        .footer { background: #2c3e50; color: white; text-align: center; padding: 30px; }
        .footer p { margin-bottom: 10px; }
        
        .key-findings { background: #e8f4f8; padding: 25px; border-radius: 8px; margin: 20px 0; }
        .key-findings h3 { color: #2c3e50; margin-bottom: 15px; }
        .findings-list { list-style: none; }
        .findings-list li { margin-bottom: 10px; padding-left: 20px; position: relative; }
        .findings-list li:before { content: "▶"; position: absolute; left: 0; color: #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Essential 8 Compliance Assessment</h1>
            <div class="subtitle">Microsoft 365 Security Framework Analysis</div>
            <div class="meta">Generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy at HH:mm:ss') | Tenant: $(if($env:USERDNSDOMAIN){$env:USERDNSDOMAIN}else{'Microsoft 365'})</div>
        </div>
        
        <div class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Overall Compliance Score</h3>
                    <div class="value" style="color: $($ComplianceLevel.Color);">$ComplianceScore%</div>
                    <div class="description">$($ComplianceLevel.Level)</div>
                </div>
                <div class="summary-card">
                    <h3>Total Rules Evaluated</h3>
                    <div class="value">$TotalRules</div>
                    <div class="description">Across all Essential 8 strategies</div>
                </div>
                <div class="summary-card">
                    <h3>Compliant Controls</h3>
                    <div class="value" style="color: #2ecc71;">$PassedRules</div>
                    <div class="description">Security controls in place</div>
                </div>
                <div class="summary-card">
                    <h3>Non-Compliant Controls</h3>
                    <div class="value" style="color: #e74c3c;">$FailedRules</div>
                    <div class="description">Require immediate attention</div>
                </div>
            </div>
        </div>
        
        <div class="compliance-level">
            <h3>Compliance Level: $($ComplianceLevel.Level)</h3>
            <p>$($ComplianceLevel.Description)</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>🔍 Data Coverage Analysis</h2>
                <div class="data-coverage">
"@

# Add data coverage cards
foreach ($Coverage in $DataCoverage.GetEnumerator()) {
    $Category = $Coverage.Key
    $Stats = $Coverage.Value
    $HtmlContent += @"
                    <div class="coverage-card">
                        <h4>$Category</h4>
                        <p><strong>Essential 8 Strategies:</strong> $($Stats.Strategy)</p>
                        <div class="coverage-stats">
                            <div class="stat pass">✓ $($Stats.Passed) Passed</div>
                            <div class="stat fail">✗ $($Stats.Failed) Failed</div>
                        </div>
                    </div>
"@
}

$HtmlContent += @"
                </div>
            </div>
            
            <div class="key-findings">
                <h3>🎯 Key Findings</h3>
                <ul class="findings-list">
                    <li><strong>Identity Security:</strong> $(if($DataCoverage.ContainsKey('Identity & Access Management')){"$($DataCoverage['Identity & Access Management'].Passed) of $($DataCoverage['Identity & Access Management'].Rules) identity controls are compliant"}else{"No identity data analyzed"})</li>
                    <li><strong>Application Security:</strong> $(if($DataCoverage.ContainsKey('Application Security')){"$($DataCoverage['Application Security'].Passed) of $($DataCoverage['Application Security'].Rules) application controls are compliant"}else{"No application data analyzed"})</li>
                    <li><strong>Administrative Privileges:</strong> $(if($DataCoverage.ContainsKey('Administrative Privileges')){"$($DataCoverage['Administrative Privileges'].Passed) of $($DataCoverage['Administrative Privileges'].Rules) admin controls are compliant"}else{"No admin privilege data analyzed"})</li>
                    <li><strong>Overall Risk Level:</strong> $($ComplianceLevel.Level) - $($ComplianceLevel.Description)</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>📋 Essential 8 Strategy Results</h2>
                <div class="strategies">
"@

# Add strategy results
foreach ($Strategy in $StrategyResults | Sort-Object Name) {
    $StrategyName = $Strategy.Name
    $StrategyRules = $Strategy.Group
    $StrategyPassed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $StrategyFailed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $StrategyTotal = $StrategyRules.Count
    $StrategyScore = if ($StrategyTotal -gt 0) { [Math]::Round(($StrategyPassed / $StrategyTotal) * 100, 1) } else { 0 }
    
    $StrategyDescription = switch -Regex ($StrategyName) {
        "E8-1" { "Prevent execution of unapproved/malicious programs including .exe, DLL, scripts, installers, compiled HTML, HTML applications and control panel applets." }
        "E8-2" { "Patch/mitigate security vulnerabilities in internet-facing services within 48 hours, and other applications within one month." }
        "E8-3" { "Configure Microsoft Office macro settings to block macros from the internet, and only allow vetted macros either in 'trusted locations' with limited write access or digitally signed with a trusted certificate." }
        "E8-4" { "Configure web browsers to block Flash (ideally uninstall it), ads and Java on the internet. Disable unneeded features." }
        "E8-5" { "Restrict administrative privileges to operating systems and applications based on user duties. Regularly validate the need for privileges." }
        "E8-6" { "Patch/mitigate security vulnerabilities in operating systems of internet-facing services within 48 hours, and other operating systems within one month." }
        "E8-7" { "Multi-factor authentication including for VPNs, RDP, SSH and other remote access, and for all users when they perform a privileged action or access an important (sensitive/high-availability) data repository." }
        "E8-8" { "Backup important new/changed data, software and configuration settings, preferably automatically and at least daily, and ensure backups are retained for at least three months." }
        default { "Supporting security controls and configurations." }
    }
    
    $HtmlContent += @"
                    <div class="strategy">
                        <h3>$StrategyName</h3>
                        <div class="strategy-description">$StrategyDescription</div>
                        <div class="strategy-meta">
                            <div class="stat pass">✓ $StrategyPassed Passed</div>
                            <div class="stat fail">✗ $StrategyFailed Failed</div>
                            <div><strong>Score:</strong> $StrategyScore%</div>
                        </div>
                    </div>
"@
}

$HtmlContent += @"
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Detailed Rule Results</h2>
                <table class="rules-table">
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Essential 8 Strategy</th>
                            <th>Outcome</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"@

# Add individual rule results (excluding test rules)
foreach ($Result in $AllResults | Sort-Object RuleName) {
    $OutcomeClass = $Result.Outcome.ToString().ToLower()
    $Recommendation = if ($Result.Recommendation) { $Result.Recommendation } else { "No specific recommendation available" }
    
    $Strategy = "Supporting Rule"
    if ($Result.RuleName -match 'E8-(\d+)') {
        $Strategy = "E8-$($matches[1])"
    }
    
    $HtmlContent += @"
                        <tr>
                            <td><strong>$($Result.RuleName)</strong></td>
                            <td>$Strategy</td>
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
            <p><strong>Essential 8 Compliance Assessment</strong> | Australian Cyber Security Centre Framework</p>
            <p>Generated by PSRule Essential 8 Compliance Tool | $(Get-Date -Format 'yyyy')</p>
            <p>This report provides a point-in-time assessment of your Microsoft 365 security posture against the Essential 8 framework.</p>
        </div>
    </div>
</body>
</html>
"@

# Save comprehensive HTML report
$ReportFile = Join-Path $ReportDir "Essential8-Professional-Report-$Timestamp.html"
$HtmlContent | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host ""
Write-Host "✅ Professional Essential 8 report generated!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Executive Summary:" -ForegroundColor Cyan
Write-Host "  Overall Compliance Score: $ComplianceScore% ($($ComplianceLevel.Level))" -ForegroundColor $(if($ComplianceScore -ge 75){'Green'}else{'Yellow'})
Write-Host "  Total Rules Evaluated: $TotalRules (excluding test rules)" -ForegroundColor Gray
Write-Host "  Data Categories Analyzed: $($DataCoverage.Count)" -ForegroundColor Gray
Write-Host "  Essential 8 Strategies Covered: $($StrategyResults.Count)" -ForegroundColor Gray
Write-Host ""
Write-Host "📄 Report Details:" -ForegroundColor Cyan
Write-Host "  Location: $ReportFile" -ForegroundColor Gray
Write-Host "  Size: $([Math]::Round((Get-Item $ReportFile).Length / 1KB, 1)) KB" -ForegroundColor Gray
Write-Host ""
Write-Host "🌐 Opening report in browser..." -ForegroundColor Yellow

# Open the report
try {
    Start-Process $ReportFile
    Write-Host "🎉 Professional Essential 8 report opened successfully!" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Could not auto-open report. Please open manually:" -ForegroundColor Yellow
    Write-Host "  $ReportFile" -ForegroundColor Gray
}

Write-Host ""
