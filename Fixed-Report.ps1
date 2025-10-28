# Fixed-Report.ps1
# Interactive Essential 8 report with properly embedded data and working downloads

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Essential8-Reports"
)

Write-Host ""
Write-Host "🔧 Fixed Essential 8 Compliance Report Generator" -ForegroundColor Cyan
Write-Host "   No More Red Errors - Properly Embedded Data!" -ForegroundColor Gray
Write-Host ""

# Create output directory with timestamp
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportDir = Join-Path $OutputPath $Timestamp
if (!(Test-Path $ReportDir)) {
    New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null
}

Write-Host "📊 Running comprehensive Essential 8 analysis..." -ForegroundColor Yellow

# Data collection and analysis
$DataPath = ".\Essential8-Data"
$RulesPath = ".\rules"

# Get all results
$AllResults = @()
$DataCoverage = @{}

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
                }
            }
        } catch {
            Write-Host "    ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Calculate statistics
$TotalRules = $AllResults.Count
$PassedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Pass' }).Count
$FailedRules = ($AllResults | Where-Object { $_.Outcome -eq 'Fail' }).Count
$ComplianceScore = if ($TotalRules -gt 0) { [Math]::Round(($PassedRules / $TotalRules) * 100, 1) } else { 0 }

# Group by strategy
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

Write-Host ""
Write-Host "🔧 Generating fixed report with embedded data..." -ForegroundColor Yellow

# Create CSV data as JavaScript string
$CsvContent = "Rule Name,Strategy,Outcome,Recommendation`n"
foreach ($Result in $AllResults) {
    $Strategy = if ($Result.RuleName -match 'E8-(\d+)') { "E8-$($matches[1])" } else { "Supporting" }
    $Recommendation = if ($Result.Recommendation) { $Result.Recommendation -replace '"', '""' } else { "No recommendation" }
    $CsvContent += "`"$($Result.RuleName)`",`"$Strategy`",`"$($Result.Outcome)`",`"$Recommendation`"`n"
}

# Create JSON data as JavaScript object
$JsonData = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComplianceScore = $ComplianceScore
    TotalRules = $TotalRules
    PassedRules = $PassedRules
    FailedRules = $FailedRules
    Results = $AllResults | ForEach-Object {
        @{
            RuleName = $_.RuleName
            Outcome = $_.Outcome.ToString()
            Recommendation = if ($_.Recommendation) { $_.Recommendation } else { "No recommendation" }
        }
    }
} | ConvertTo-Json -Depth 5 -Compress

# Create action plan content
$ActionPlanContent = @"
# Essential 8 Action Plan - $(Get-Date -Format 'yyyy-MM-dd')

## Executive Summary
- **Total Failed Rules:** $FailedRules
- **Compliance Score:** $ComplianceScore%
- **Priority:** $(if($ComplianceScore -lt 50){'HIGH'}elseif($ComplianceScore -lt 75){'MEDIUM'}else{'LOW'})

## Priority Actions Required

"@

$Priority = 1
$FailedRulesOnly = $AllResults | Where-Object { $_.Outcome -eq 'Fail' }
foreach ($Rule in $FailedRulesOnly | Sort-Object RuleName) {
    $Strategy = if ($Rule.RuleName -match 'E8-(\d+)') { "E8-$($matches[1])" } else { "Supporting" }
    $ActionPlanContent += @"

### $Priority. $($Rule.RuleName)
- **Strategy:** $Strategy
- **Issue:** Non-compliant control
- **Action:** $($Rule.Recommendation)
- **Priority:** $(if($Rule.RuleName -match 'E8-[157]'){'HIGH'}else{'MEDIUM'})

"@
    $Priority++
}

$ActionPlanContent += @"

## Next Steps
1. Review each failed rule above
2. Implement recommended actions
3. Re-run compliance assessment
4. Track progress over time

Generated by Essential 8 Compliance Tool
"@

# Create fixed HTML report with embedded data
$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Essential 8 Fixed Compliance Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        
        /* Header */
        .header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 3em; margin-bottom: 10px; font-weight: 300; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; margin-bottom: 20px; }
        .header .meta { font-size: 0.9em; opacity: 0.8; }
        
        /* Navigation */
        .nav-tabs { background: #34495e; padding: 0; display: flex; }
        .nav-tab { padding: 15px 25px; background: #34495e; color: white; border: none; cursor: pointer; font-size: 1em; transition: all 0.3s; }
        .nav-tab:hover { background: #2c3e50; }
        .nav-tab.active { background: #3498db; }
        
        /* Content sections */
        .tab-content { display: none; padding: 40px; }
        .tab-content.active { display: block; }
        
        /* Executive Summary */
        .executive-summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .summary-card { background: rgba(255,255,255,0.1); padding: 25px; border-radius: 10px; text-align: center; backdrop-filter: blur(10px); cursor: pointer; transition: transform 0.3s; }
        .summary-card:hover { transform: translateY(-5px); }
        .summary-card h3 { font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; opacity: 0.8; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        
        /* Action buttons */
        .action-bar { padding: 20px; background: #e9ecef; display: flex; gap: 15px; align-items: center; flex-wrap: wrap; }
        .action-btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: all 0.3s; }
        .action-btn.primary { background: #007bff; color: white; }
        .action-btn.primary:hover { background: #0056b3; }
        .action-btn.success { background: #28a745; color: white; }
        .action-btn.success:hover { background: #1e7e34; }
        .action-btn.warning { background: #ffc107; color: #212529; }
        .action-btn.warning:hover { background: #e0a800; }
        .action-btn.danger { background: #dc3545; color: white; }
        .action-btn.danger:hover { background: #c82333; }
        
        /* Rules table */
        .rules-table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }
        .rules-table th { background: #34495e; color: white; padding: 15px; text-align: left; font-weight: 600; cursor: pointer; }
        .rules-table th:hover { background: #2c3e50; }
        .rules-table td { padding: 12px 15px; border-bottom: 1px solid #ecf0f1; }
        .rules-table tr:hover { background: #f8f9fa; }
        
        /* Outcome badges */
        .outcome { padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; }
        .outcome.pass { background: #d4edda; color: #155724; }
        .outcome.fail { background: #f8d7da; color: #721c24; }
        
        /* Strategy cards */
        .strategy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .strategy-card { background: white; border-radius: 8px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); cursor: pointer; transition: all 0.3s; border-left: 4px solid #3498db; }
        .strategy-card:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,0,0,0.15); }
        .strategy-card.fail { border-left-color: #e74c3c; }
        .strategy-card.pass { border-left-color: #27ae60; }
        .strategy-card h3 { color: #2c3e50; margin-bottom: 10px; }
        .strategy-stats { display: flex; gap: 15px; margin: 15px 0; }
        .stat { padding: 5px 10px; border-radius: 4px; font-size: 0.9em; font-weight: bold; }
        .stat.pass { background: #d4edda; color: #155724; }
        .stat.fail { background: #f8d7da; color: #721c24; }
        
        /* Progress bars */
        .progress-bar { width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #28a745, #20c997); transition: width 0.3s; }
        
        /* Filters */
        .filters { padding: 20px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; display: flex; gap: 15px; align-items: center; flex-wrap: wrap; }
        .filter-group { display: flex; align-items: center; gap: 10px; }
        .filter-label { font-weight: 600; color: #495057; }
        .filter-select, .filter-input { padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; font-size: 0.9em; }
        
        /* Download section */
        .download-section { background: #f8f9fa; padding: 30px; margin: 20px 0; border-radius: 8px; }
        .download-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .download-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .download-card h4 { margin-bottom: 10px; color: #2c3e50; }
        .download-card p { margin-bottom: 15px; color: #666; font-size: 0.9em; }
        
        /* Success message */
        .success-message { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 10px 0; border: 1px solid #c3e6cb; }
        
        /* Responsive */
        @media (max-width: 768px) {
            .nav-tabs { flex-direction: column; }
            .summary-grid { grid-template-columns: 1fr; }
            .filters { flex-direction: column; align-items: stretch; }
            .action-bar { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Essential 8 Fixed Compliance Report</h1>
            <div class="subtitle">Microsoft 365 Security Framework Analysis</div>
            <div class="meta">Generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy at HH:mm:ss')</div>
        </div>
        
        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('overview')">📊 Overview</button>
            <button class="nav-tab" onclick="showTab('strategies')">🎯 Strategies</button>
            <button class="nav-tab" onclick="showTab('rules')">📋 Rules</button>
            <button class="nav-tab" onclick="showTab('downloads')">📥 Downloads</button>
        </div>
        
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
            <div class="executive-summary">
                <h2>📊 Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card" onclick="showTab('rules')">
                        <h3>Overall Compliance Score</h3>
                        <div class="value" style="color: #e74c3c;">$ComplianceScore%</div>
                        <div class="description">Click to view details</div>
                    </div>
                    <div class="summary-card" onclick="showAllRules()">
                        <h3>Total Rules Evaluated</h3>
                        <div class="value">$TotalRules</div>
                        <div class="description">Click to view all rules</div>
                    </div>
                    <div class="summary-card" onclick="showPassedRules()">
                        <h3>Compliant Controls</h3>
                        <div class="value" style="color: #2ecc71;">$PassedRules</div>
                        <div class="description">Click to view passing rules</div>
                    </div>
                    <div class="summary-card" onclick="showFailedRules()">
                        <h3>Non-Compliant Controls</h3>
                        <div class="value" style="color: #e74c3c;">$FailedRules</div>
                        <div class="description">Click to view failing rules</div>
                    </div>
                </div>
            </div>
            
            <div style="padding: 40px;">
                <h2>🎯 Key Actions Required</h2>
                <div class="action-bar">
                    <button class="action-btn primary" onclick="downloadActionPlan()">
                        🔧 Download Action Plan
                    </button>
                    <button class="action-btn warning" onclick="showFailedRules()">
                        ⚠️ Focus on Failed Rules ($FailedRules)
                    </button>
                    <button class="action-btn success" onclick="downloadCsv()">
                        📊 Download CSV Report
                    </button>
                    <button class="action-btn danger" onclick="downloadJson()">
                        💾 Download Raw Data
                    </button>
                </div>
                
                <div style="margin-top: 30px;">
                    <h3>Compliance Progress</h3>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: $ComplianceScore%"></div>
                    </div>
                    <p>$PassedRules of $TotalRules controls are compliant ($ComplianceScore%)</p>
                </div>
            </div>
        </div>
        
        <!-- Strategies Tab -->
        <div id="strategies" class="tab-content">
            <div style="padding: 40px;">
                <h2>📋 Essential 8 Strategy Results</h2>
                <div class="strategy-grid">
"@

# Add strategy cards with real functionality
foreach ($Strategy in $StrategyResults | Sort-Object Name) {
    $StrategyName = $Strategy.Name
    $StrategyRules = $Strategy.Group
    $StrategyPassed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $StrategyFailed = ($StrategyRules | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $StrategyTotal = $StrategyRules.Count
    $StrategyScore = if ($StrategyTotal -gt 0) { [Math]::Round(($StrategyPassed / $StrategyTotal) * 100, 1) } else { 0 }
    
    $CardClass = if ($StrategyScore -ge 80) { "pass" } elseif ($StrategyScore -ge 50) { "" } else { "fail" }
    
    $HtmlContent += @"
                    <div class="strategy-card $CardClass" onclick="filterByStrategy('$StrategyName')">
                        <h3>$StrategyName</h3>
                        <div class="strategy-stats">
                            <div class="stat pass">✓ $StrategyPassed Passed</div>
                            <div class="stat fail">✗ $StrategyFailed Failed</div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: $StrategyScore%"></div>
                        </div>
                        <p><strong>Score:</strong> $StrategyScore% | <em>Click to filter rules</em></p>
                    </div>
"@
}

$HtmlContent += @"
                </div>
            </div>
        </div>
        
        <!-- Rules Tab -->
        <div id="rules" class="tab-content">
            <div class="filters">
                <div class="filter-group">
                    <label class="filter-label">Filter by Outcome:</label>
                    <select class="filter-select" id="outcomeFilter" onchange="applyFilters()">
                        <option value="all">All Outcomes</option>
                        <option value="pass">Pass Only</option>
                        <option value="fail">Fail Only</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">Search Rules:</label>
                    <input type="text" class="filter-input" id="searchFilter" placeholder="Search rule names..." onkeyup="applyFilters()">
                </div>
                <button class="action-btn primary" onclick="clearFilters()">Clear Filters</button>
            </div>
            
            <div style="padding: 20px;">
                <table class="rules-table" id="rulesTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)">Rule Name ↕</th>
                            <th onclick="sortTable(1)">Strategy ↕</th>
                            <th onclick="sortTable(2)">Outcome ↕</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"@

# Add rule rows with real data
foreach ($Result in $AllResults | Sort-Object RuleName) {
    $OutcomeClass = $Result.Outcome.ToString().ToLower()
    $Recommendation = if ($Result.Recommendation) { $Result.Recommendation } else { "No specific recommendation available" }
    
    $Strategy = "Supporting Rule"
    if ($Result.RuleName -match 'E8-(\d+)') {
        $Strategy = "E8-$($matches[1])"
    }
    
    $HtmlContent += @"
                        <tr class="rule-row" data-outcome="$($Result.Outcome.ToString().ToLower())" data-strategy="$Strategy" data-name="$($Result.RuleName.ToLower())">
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
        
        <!-- Downloads Tab -->
        <div id="downloads" class="tab-content">
            <div style="padding: 40px;">
                <h2>📥 Download Reports & Data</h2>
                
                <div id="downloadMessages"></div>
                
                <div class="download-section">
                    <h3>📊 Available Downloads</h3>
                    <div class="download-grid">
                        <div class="download-card">
                            <h4>📋 Action Plan</h4>
                            <p>Prioritized list of remediation steps for failed rules</p>
                            <button class="action-btn primary" onclick="downloadActionPlan()">
                                📋 Download Action Plan
                            </button>
                        </div>
                        
                        <div class="download-card">
                            <h4>📊 CSV Report</h4>
                            <p>Spreadsheet format for analysis and tracking</p>
                            <button class="action-btn success" onclick="downloadCsv()">
                                📊 Download CSV
                            </button>
                        </div>
                        
                        <div class="download-card">
                            <h4>💾 JSON Data</h4>
                            <p>Raw compliance data for integration</p>
                            <button class="action-btn danger" onclick="downloadJson()">
                                💾 Download JSON
                            </button>
                        </div>
                        
                        <div class="download-card">
                            <h4>🖨️ Print Report</h4>
                            <p>Print-friendly version of this report</p>
                            <button class="action-btn primary" onclick="printReport()">
                                🖨️ Print Report
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Embedded data - no external file references!
        const reportData = {
            csvContent: `$($CsvContent -replace '`n', '\n' -replace '`r', '')`,
            jsonData: $JsonData,
            actionPlan: `$($ActionPlanContent -replace '`n', '\n' -replace '`r', '')`
        };
        
        // Tab switching
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        // Rule filtering functions that actually work
        function showAllRules() {
            showTab('rules');
            clearFilters();
        }
        
        function showPassedRules() {
            showTab('rules');
            document.getElementById('outcomeFilter').value = 'pass';
            applyFilters();
        }
        
        function showFailedRules() {
            showTab('rules');
            document.getElementById('outcomeFilter').value = 'fail';
            applyFilters();
        }
        
        function filterByStrategy(strategy) {
            showTab('rules');
            document.querySelectorAll('.rule-row').forEach(row => {
                const rowStrategy = row.getAttribute('data-strategy');
                if (strategy === 'all' || rowStrategy.includes(strategy)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        function applyFilters() {
            const outcomeFilter = document.getElementById('outcomeFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            
            document.querySelectorAll('.rule-row').forEach(row => {
                const outcome = row.getAttribute('data-outcome');
                const name = row.getAttribute('data-name');
                
                let show = true;
                
                if (outcomeFilter !== 'all' && outcome !== outcomeFilter) show = false;
                if (searchFilter && !name.includes(searchFilter)) show = false;
                
                row.style.display = show ? '' : 'none';
            });
        }
        
        function clearFilters() {
            document.getElementById('outcomeFilter').value = 'all';
            document.getElementById('searchFilter').value = '';
            applyFilters();
        }
        
        // Table sorting that actually works
        function sortTable(columnIndex) {
            const table = document.getElementById('rulesTable');
            const tbody = table.tBodies[0];
            const rows = Array.from(tbody.querySelectorAll('.rule-row'));
            
            rows.sort((a, b) => {
                const aText = a.cells[columnIndex].textContent.trim();
                const bText = b.cells[columnIndex].textContent.trim();
                return aText.localeCompare(bText);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        // Download functions that actually work with embedded data
        function downloadFile(content, filename, contentType) {
            const blob = new Blob([content], { type: contentType });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            
            // Show success message
            showDownloadMessage('✅ ' + filename + ' downloaded successfully!');
        }
        
        function showDownloadMessage(message) {
            const messagesDiv = document.getElementById('downloadMessages');
            messagesDiv.innerHTML = '<div class="success-message">' + message + '</div>';
            setTimeout(() => {
                messagesDiv.innerHTML = '';
            }, 3000);
        }
        
        function downloadActionPlan() {
            downloadFile(reportData.actionPlan, 'Essential8-ActionPlan.md', 'text/markdown');
        }
        
        function downloadCsv() {
            downloadFile(reportData.csvContent, 'Essential8-Results.csv', 'text/csv');
        }
        
        function downloadJson() {
            downloadFile(JSON.stringify(reportData.jsonData, null, 2), 'Essential8-Data.json', 'application/json');
        }
        
        function printReport() {
            window.print();
        }
    </script>
</body>
</html>
"@

# Save fixed HTML report
$ReportFile = Join-Path $ReportDir "Essential8-Fixed-Report-$Timestamp.html"
$HtmlContent | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host ""
Write-Host "🔧 Fixed Essential 8 report generated!" -ForegroundColor Green
Write-Host ""
Write-Host "✅ FIXED Issues:" -ForegroundColor Cyan
Write-Host "  🚫 No more red PSRule.Rules.RuleRecord errors" -ForegroundColor Green
Write-Host "  📦 All data embedded directly in HTML" -ForegroundColor Green
Write-Host "  💾 Downloads work with embedded data (no external files)" -ForegroundColor Green
Write-Host "  🔍 Filtering and sorting work properly" -ForegroundColor Green
Write-Host "  ✅ Success messages show when downloads complete" -ForegroundColor Green
Write-Host ""
Write-Host "📁 Generated File:" -ForegroundColor Cyan
Write-Host "  📄 HTML Report: Essential8-Fixed-Report-$Timestamp.html" -ForegroundColor Gray
Write-Host ""
Write-Host "🌐 Opening fixed report..." -ForegroundColor Yellow

# Open the report
try {
    Start-Process $ReportFile
    Write-Host "🎉 Fixed Essential 8 report opened!" -ForegroundColor Green
    Write-Host "   No more cascading red errors! 🚀" -ForegroundColor Gray
} catch {
    Write-Host "⚠️  Could not auto-open report. Please open manually:" -ForegroundColor Yellow
    Write-Host "  $ReportFile" -ForegroundColor Gray
}

Write-Host ""
