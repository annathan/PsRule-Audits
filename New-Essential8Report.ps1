# New-Essential8Report.ps1
# Generates comprehensive HTML report with historical tracking

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResultsPath,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [string]$MaturityLevel,
    
    [Parameter(Mandatory = $false)]
    [string]$HistoryPath
)

# Load results
$Results = Get-Content $ResultsPath | ConvertFrom-Json

# Calculate statistics
$TotalRules = $Results.Count
$PassedRules = ($Results | Where-Object { $_.Outcome -eq 'Pass' }).Count
$FailedRules = ($Results | Where-Object { $_.Outcome -eq 'Fail' }).Count
$WarningRules = ($Results | Where-Object { $_.Outcome -eq 'Warning' }).Count
$ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }

# Group by Essential 8 strategy
$ByStrategy = $Results | Group-Object { $_.Tag.E8 } | Sort-Object Name

# Load historical data if available
$HistoricalData = @()
if ($HistoryPath -and (Test-Path $HistoryPath)) {
    $HistoricalData = Get-Content $HistoryPath | ConvertFrom-Json
}

# Generate HTML
$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Essential 8 Compliance Report - $TenantId</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5; 
            color: #333; 
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; }
        .header .meta { margin-top: 20px; display: flex; gap: 30px; flex-wrap: wrap; }
        .header .meta-item { background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 5px; }
        
        .score-card { 
            background: white; 
            padding: 40px; 
            border-radius: 10px; 
            text-align: center; 
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .score-circle {
            width: 200px;
            height: 200px;
            margin: 0 auto 20px;
            border-radius: 50%;
            background: conic-gradient(
                #4CAF50 0% $(if($ComplianceScore -ge 0){$ComplianceScore}else{0})%,
                #e0e0e0 $(if($ComplianceScore -ge 0){$ComplianceScore}else{0})% 100%
            );
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .score-circle::before {
            content: '';
            width: 160px;
            height: 160px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }
        .score-text {
            position: relative;
            z-index: 1;
            font-size: 3em;
            font-weight: bold;
            color: $(if($ComplianceScore -ge 80){'#4CAF50'}elseif($ComplianceScore -ge 60){'#FF9800'}else{'#f44336'});
        }
        
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .stat-card.passed { border-left-color: #4CAF50; }
        .stat-card.failed { border-left-color: #f44336; }
        .stat-card.warning { border-left-color: #FF9800; }
        .stat-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .stat-label { color: #666; text-transform: uppercase; font-size: 0.9em; }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 { 
            font-size: 1.8em; 
            margin-bottom: 20px; 
            padding-bottom: 10px; 
            border-bottom: 2px solid #667eea;
        }
        
        .strategy {
            margin-bottom: 30px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        .strategy-header {
            background: #f9f9f9;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        .strategy-header:hover { background: #f0f0f0; }
        .strategy-title { font-weight: bold; font-size: 1.2em; }
        .strategy-stats { display: flex; gap: 15px; }
        .strategy-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .badge-pass { background: #4CAF50; color: white; }
        .badge-fail { background: #f44336; color: white; }
        .badge-warn { background: #FF9800; color: white; }
        
        .strategy-content {
            padding: 20px;
            display: none;
        }
        .strategy.expanded .strategy-content { display: block; }
        
        .rule-item {
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #e0e0e0;
            border-radius: 4px;
            background: #fafafa;
        }
        .rule-item.pass { border-left-color: #4CAF50; background: #f1f8f4; }
        .rule-item.fail { border-left-color: #f44336; background: #fef1f1; }
        .rule-item.warning { border-left-color: #FF9800; background: #fff8e1; }
        
        .rule-name { font-weight: bold; margin-bottom: 5px; }
        .rule-outcome { 
            display: inline-block; 
            padding: 3px 10px; 
            border-radius: 3px; 
            font-size: 0.85em; 
            font-weight: bold;
            margin-left: 10px;
        }
        .outcome-pass { background: #4CAF50; color: white; }
        .outcome-fail { background: #f44336; color: white; }
        .outcome-warning { background: #FF9800; color: white; }
        
        .rule-reason { color: #666; margin-top: 8px; font-style: italic; }
        .rule-recommendation { color: #1976D2; margin-top: 8px; }
        
        .chart-container {
            margin: 30px 0;
            padding: 20px;
            background: white;
            border-radius: 8px;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }
        
        @media print {
            .strategy-content { display: block !important; }
            body { background: white; }
        }
    </style>
    <script>
        function toggleStrategy(id) {
            const strategy = document.getElementById('strategy-' + id);
            strategy.classList.toggle('expanded');
        }
        
        function expandAll() {
            document.querySelectorAll('.strategy').forEach(s => s.classList.add('expanded'));
        }
        
        function collapseAll() {
            document.querySelectorAll('.strategy').forEach(s => s.classList.remove('expanded'));
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Essential 8 Compliance Report</h1>
            <div class="subtitle">Australian Cyber Security Centre (ACSC) Framework</div>
            <div class="meta">
                <div class="meta-item"><strong>Tenant:</strong> $TenantId</div>
                <div class="meta-item"><strong>Maturity Level:</strong> $MaturityLevel</div>
                <div class="meta-item"><strong>Report Date:</strong> $(Get-Date -Format 'dd MMMM yyyy HH:mm')</div>
                <div class="meta-item"><strong>Total Rules:</strong> $TotalRules</div>
            </div>
        </div>
        
        <div class="score-card">
            <h2>Overall Compliance Score</h2>
            <div class="score-circle">
                <div class="score-text">$ComplianceScore%</div>
            </div>
            <p style="font-size: 1.2em; color: #666;">
                $PassedRules of $TotalRules rules passed
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card passed">
                <div class="stat-value" style="color: #4CAF50;">$PassedRules</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card failed">
                <div class="stat-value" style="color: #f44336;">$FailedRules</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-value" style="color: #FF9800;">$WarningRules</div>
                <div class="stat-label">Warnings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #667eea;">$TotalRules</div>
                <div class="stat-label">Total Rules</div>
            </div>
        </div>
        
"@

# Add historical trend if available
if ($HistoricalData.Count -gt 1) {
    $Html += @"
        <div class="section">
            <h2>Compliance Trend</h2>
            <p style="margin-bottom: 20px;">Tracking your progress over time:</p>
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: #f5f5f5; text-align: left;">
                        <th style="padding: 12px; border-bottom: 2px solid #ddd;">Date</th>
                        <th style="padding: 12px; border-bottom: 2px solid #ddd;">Score</th>
                        <th style="padding: 12px; border-bottom: 2px solid #ddd;">Passed</th>
                        <th style="padding: 12px; border-bottom: 2px solid #ddd;">Failed</th>
                        <th style="padding: 12px; border-bottom: 2px solid #ddd;">Change</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    $PreviousScore = $null
    foreach ($Record in ($HistoricalData | Sort-Object AuditDate -Descending | Select-Object -First 10)) {
        $RecordDate = [DateTime]$Record.AuditDate
        $ScoreChange = if ($PreviousScore) { 
            $Change = $Record.ComplianceScore - $PreviousScore
            $Arrow = if ($Change -gt 0) { "↑" } elseif ($Change -lt 0) { "↓" } else { "=" }
            $Color = if ($Change -gt 0) { "green" } elseif ($Change -lt 0) { "red" } else { "gray" }
            "<span style='color: $Color; font-weight: bold;'>$Arrow $([Math]::Abs($Change))%</span>"
        } else { 
            "-" 
        }
        
        $Html += @"
                    <tr>
                        <td style="padding: 12px; border-bottom: 1px solid #eee;">$($RecordDate.ToString('dd MMM yyyy HH:mm'))</td>
                        <td style="padding: 12px; border-bottom: 1px solid #eee;"><strong>$($Record.ComplianceScore)%</strong></td>
                        <td style="padding: 12px; border-bottom: 1px solid #eee; color: #4CAF50;">$($Record.Passed)</td>
                        <td style="padding: 12px; border-bottom: 1px solid #eee; color: #f44336;">$($Record.Failed)</td>
                        <td style="padding: 12px; border-bottom: 1px solid #eee;">$ScoreChange</td>
                    </tr>
"@
        $PreviousScore = $Record.ComplianceScore
    }
    
    $Html += @"
                </tbody>
            </table>
        </div>
"@
}

# Add detailed results by strategy
$Html += @"
        <div class="section">
            <h2>Detailed Results by Strategy</h2>
            <p style="margin-bottom: 20px;">
                Click on each strategy to view detailed rule results. 
                <a href="javascript:expandAll()" style="color: #667eea;">Expand All</a> | 
                <a href="javascript:collapseAll()" style="color: #667eea;">Collapse All</a>
            </p>
"@

$StrategyIndex = 0
foreach ($Strategy in $ByStrategy) {
    $StrategyName = $Strategy.Name
    $StrategyRules = $Strategy.Group
    $StrategyPassed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $StrategyFailed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $StrategyWarning = ($StrategyRules | Where-Object { $_.Outcome -eq 'Warning' }).Count
    
    $StrategyTitle = switch ($StrategyName) {
        'E8-1' { 'Application Control' }
        'E8-2' { 'Patch Applications' }
        'E8-3' { 'Configure Microsoft Office Macro Settings' }
        'E8-4' { 'User Application Hardening' }
        'E8-5' { 'Restrict Administrative Privileges' }
        'E8-6' { 'Patch Operating Systems' }
        'E8-7' { 'Multi-Factor Authentication' }
        'E8-8' { 'Regular Backups' }
        default { $StrategyName }
    }
    
    $Html += @"
            <div class="strategy" id="strategy-$StrategyIndex">
                <div class="strategy-header" onclick="toggleStrategy($StrategyIndex)">
                    <div class="strategy-title">$StrategyName - $StrategyTitle</div>
                    <div class="strategy-stats">
                        <span class="strategy-badge badge-pass">✓ $StrategyPassed</span>
                        <span class="strategy-badge badge-fail">✗ $StrategyFailed</span>
                        $(if($StrategyWarning -gt 0){"<span class='strategy-badge badge-warn'>⚠ $StrategyWarning</span>"})
                    </div>
                </div>
                <div class="strategy-content">
"@
    
    foreach ($Rule in $StrategyRules) {
        $OutcomeClass = $Rule.Outcome.ToLower()
        $OutcomeBadge = switch ($Rule.Outcome) {
            'Pass' { '<span class="rule-outcome outcome-pass">✓ PASS</span>' }
            'Fail' { '<span class="rule-outcome outcome-fail">✗ FAIL</span>' }
            'Warning' { '<span class="rule-outcome outcome-warning">⚠ WARNING</span>' }
            default { "<span class='rule-outcome'>$($Rule.Outcome)</span>" }
        }
        
        $Html += @"
                    <div class="rule-item $OutcomeClass">
                        <div class="rule-name">$($Rule.RuleName)$OutcomeBadge</div>
                        $(if($Rule.Reason){"<div class='rule-reason'>💡 $($Rule.Reason)</div>"})
                        $(if($Rule.Recommendation){"<div class='rule-recommendation'>📋 $($Rule.Recommendation)</div>"})
                    </div>
"@
    }
    
    $Html += @"
                </div>
            </div>
"@
    $StrategyIndex++
}

$Html += @"
        </div>
        
        <div class="footer">
            <p>This report was generated by the Essential 8 Compliance Audit Tool</p>
            <p>For more information about the Essential 8, visit: 
               <a href="https://www.cyber.gov.au/acsc/view-all-content/essential-eight">
               https://www.cyber.gov.au/acsc/view-all-content/essential-eight
               </a>
            </p>
        </div>
    </div>
</body>
</html>
"@

# Save HTML report
$ReportFile = Join-Path $OutputPath "Essential8-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
$Html | Out-File $ReportFile -Encoding UTF8

return $ReportFile

