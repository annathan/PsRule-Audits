# Generate-Report.ps1
# Generates HTML report from current compliance results

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    Generating HTML Report                        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Create output directory
$OutputPath = ".\Essential8-Reports\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
if (!(Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host "Output directory: $OutputPath" -ForegroundColor Gray
Write-Host ""

# Run compliance analysis
Write-Host "Running compliance analysis..." -ForegroundColor Yellow

$DataFiles = @(
    "Essential8-Data/aad.users.json",
    "Essential8-Data/aad.user.enforced.json", 
    "Essential8-Data/aad.serviceprincipals.json"
)

$RulesPath = "rules"
$AllResults = @()

foreach ($DataFile in $DataFiles) {
    if (Test-Path $DataFile) {
        $Results = Invoke-PSRule -InputPath $DataFile -Path $RulesPath
        if ($Results) {
            $RealResults = $Results | Where-Object { $_.RuleName -ne 'Essential8.Test.Simple' }
            if ($RealResults) {
                $AllResults += $RealResults
            }
        }
    }
}

# Save results to JSON
$ResultsFile = Join-Path $OutputPath "results.json"
$AllResults | ConvertTo-Json -Depth 10 | Out-File $ResultsFile -Force

Write-Host "✓ Analysis completed - $($AllResults.Count) rules evaluated" -ForegroundColor Green

# Generate HTML report
Write-Host "Generating HTML report..." -ForegroundColor Yellow

$ReportGenerator = Join-Path $PSScriptRoot "New-Essential8Report.ps1"
if (Test-Path $ReportGenerator) {
    $ReportFile = & $ReportGenerator -ResultsPath $ResultsFile `
                                     -OutputPath $OutputPath `
                                     -TenantId "camnetcybersecurity.onmicrosoft.com" `
                                     -MaturityLevel "ML2"
    
    if ($ReportFile -and (Test-Path $ReportFile)) {
        Write-Host "✓ HTML report generated successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "📄 Report Location:" -ForegroundColor Cyan
        Write-Host "  $ReportFile" -ForegroundColor White
        Write-Host ""
        Write-Host "🌐 Open report:" -ForegroundColor Yellow
        Write-Host "  Start-Process '$ReportFile'" -ForegroundColor Gray
        Write-Host ""
        
        $OpenReport = Read-Host "Open HTML report now? (Y/N)"
        if ($OpenReport -eq 'Y') {
            Start-Process $ReportFile
        }
    } else {
        Write-Host "✗ Failed to generate HTML report" -ForegroundColor Red
    }
} else {
    Write-Host "✗ Report generator not found: $ReportGenerator" -ForegroundColor Red
}

Write-Host ""
Write-Host "✅ Report generation completed!" -ForegroundColor Green
Write-Host ""
