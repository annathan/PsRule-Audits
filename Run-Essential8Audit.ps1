# Run-Essential8Audit.ps1
# Customer-friendly script to execute Essential 8 compliance audit
# This script collects data, runs PSRule analysis, and generates reports with historical tracking

<#
.SYNOPSIS
    Runs Essential 8 compliance audit against your Microsoft 365/Azure environment

.DESCRIPTION
    This script automates the complete Essential 8 audit process:
    1. Checks prerequisites and installs missing modules
    2. Collects configuration data from your tenant
    3. Runs PSRule compliance checks
    4. Generates HTML report with results
    5. Tracks historical results for progress monitoring

.PARAMETER TenantId
    Your Microsoft 365 tenant ID or domain (e.g., contoso.onmicrosoft.com)

.PARAMETER MaturityLevel
    Target Essential 8 maturity level: ML1, ML2, or ML3
    Default: ML2 (recommended for most organizations)

.PARAMETER SkipDataCollection
    Skip data collection and use existing data (useful for re-running analysis)

.PARAMETER OutputPath
    Path where reports and data will be saved
    Default: .\Essential8-Reports

.EXAMPLE
    .\Run-Essential8Audit.ps1 -TenantId "contoso.onmicrosoft.com"
    
    Runs complete audit against contoso tenant with ML2 baseline

.EXAMPLE
    .\Run-Essential8Audit.ps1 -TenantId "contoso.onmicrosoft.com" -MaturityLevel ML3
    
    Runs audit against ML3 (advanced) baseline

.EXAMPLE
    .\Run-Essential8Audit.ps1 -TenantId "contoso.onmicrosoft.com" -SkipDataCollection
    
    Re-runs analysis using previously collected data
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('ML1', 'ML2', 'ML3')]
    [string]$MaturityLevel = 'ML2',
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDataCollection,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Essential8-Reports"
)

#region Helper Functions

function Write-AuditHeader {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "║           Essential 8 Compliance Audit Tool                      ║" -ForegroundColor Cyan
    Write-Host "║           Australian Cyber Security Centre (ACSC)                ║" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-AuditStep {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor White
}

function Write-AuditSuccess {
    param([string]$Message)
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
    Write-Host $Message -ForegroundColor Gray
}

function Write-AuditError {
    param([string]$Message)
    Write-Host "  ✗ " -NoNewline -ForegroundColor Red
    Write-Host $Message -ForegroundColor Gray
}

#endregion

#region Main Execution

$StartTime = Get-Date
$AuditRunId = $StartTime.ToString('yyyyMMdd-HHmmss')

Write-AuditHeader

Write-Host "Audit Configuration:" -ForegroundColor Cyan
Write-Host "  Tenant:         $TenantId" -ForegroundColor Gray
Write-Host "  Maturity Level: $MaturityLevel" -ForegroundColor Gray
Write-Host "  Run ID:         $AuditRunId" -ForegroundColor Gray
Write-Host "  Output Path:    $OutputPath" -ForegroundColor Gray
Write-Host ""

# Create output directories
$ReportPath = Join-Path $OutputPath $AuditRunId
$DataPath = Join-Path $ReportPath "Data"
$HistoryPath = Join-Path $OutputPath "History"

foreach ($path in @($ReportPath, $DataPath, $HistoryPath)) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
}

try {
    # Step 1: Check Prerequisites
    Write-AuditStep "1/5" "Checking prerequisites..."
    
    $RequiredModules = @('PSRule', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 
                         'Microsoft.Graph.Identity.SignIns', 'ExchangeOnlineManagement', 'PnP.PowerShell')
    
    $MissingModules = @()
    foreach ($Module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            $MissingModules += $Module
            Write-AuditError "Module $Module not found"
        } else {
            Write-AuditSuccess "Module $Module found"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-Host ""
        Write-Host "  Missing modules detected. Install with:" -ForegroundColor Yellow
        Write-Host "  Install-Module $($MissingModules -join ', ') -Force" -ForegroundColor Gray
        Write-Host ""
        $Install = Read-Host "  Install missing modules now? (Y/N)"
        
        if ($Install -eq 'Y') {
            foreach ($Module in $MissingModules) {
                Write-Host "  Installing $Module..." -ForegroundColor Gray
                Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
            }
        } else {
            throw "Required modules are missing. Please install them and try again."
        }
    }
    
    Write-Host ""
    
    # Step 2: Collect Data
    if (!$SkipDataCollection) {
        Write-AuditStep "2/5" "Collecting configuration data from tenant..."
        Write-Host "  This may take 5-10 minutes depending on tenant size" -ForegroundColor Gray
        Write-Host ""
        
        $CollectorScript = Join-Path $PSScriptRoot "Collectors\Essential8-DataCollector.ps1"
        if (Test-Path $CollectorScript) {
            & $CollectorScript -TenantId $TenantId -OutputPath $DataPath -Services 'All' -ErrorAction Stop
            Write-AuditSuccess "Data collection completed"
        } else {
            throw "Data collector script not found: $CollectorScript"
        }
    } else {
        Write-AuditStep "2/5" "Skipping data collection (using existing data)..."
        
        # Use most recent data collection
        $LatestData = Get-ChildItem -Path $OutputPath -Directory | 
                     Where-Object { $_.Name -match '^\d{8}-\d{6}$' } | 
                     Sort-Object Name -Descending | 
                     Select-Object -First 1
        
        if ($LatestData) {
            $DataPath = Join-Path $LatestData.FullName "Data"
            Write-AuditSuccess "Using data from: $($LatestData.Name)"
        } else {
            throw "No existing data found. Run without -SkipDataCollection first."
        }
    }
    
    Write-Host ""
    
    # Step 3: Run PSRule Analysis
    Write-AuditStep "3/5" "Running Essential 8 compliance checks..."
    
    $RulesPath = Join-Path $PSScriptRoot "rules"
    $BaselineName = "Essential8.$MaturityLevel"
    $ResultsFile = Join-Path $ReportPath "results.json"
    
    # Run PSRule
    $Results = Invoke-PSRule -InputPath $DataPath `
                              -Path $RulesPath `
                              -Baseline $BaselineName `
                              -OutputFormat Json `
                              -OutputPath $ResultsFile `
                              -ErrorAction Stop
    
    Write-AuditSuccess "Analysis completed"
    Write-Host "  Total rules evaluated: $($Results.Count)" -ForegroundColor Gray
    
    # Calculate statistics
    $PassedRules = ($Results | Where-Object { $_.Outcome -eq 'Pass' }).Count
    $FailedRules = ($Results | Where-Object { $_.Outcome -eq 'Fail' }).Count
    $WarningRules = ($Results | Where-Object { $_.Outcome -eq 'Warning' }).Count
    $ComplianceScore = if ($Results.Count -gt 0) { 
        [Math]::Round(($PassedRules / $Results.Count) * 100, 1) 
    } else { 
        0 
    }
    
    Write-Host "  Passed:  $PassedRules" -ForegroundColor Green
    Write-Host "  Failed:  $FailedRules" -ForegroundColor Red
    Write-Host "  Warning: $WarningRules" -ForegroundColor Yellow
    Write-Host "  Compliance Score: $ComplianceScore%" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    
    # Step 4: Save Historical Data
    Write-AuditStep "4/5" "Saving historical tracking data..."
    
    $HistoryRecord = [PSCustomObject]@{
        AuditDate = $StartTime
        RunId = $AuditRunId
        TenantId = $TenantId
        MaturityLevel = $MaturityLevel
        TotalRules = $Results.Count
        Passed = $PassedRules
        Failed = $FailedRules
        Warning = $WarningRules
        ComplianceScore = $ComplianceScore
    }
    
    $HistoryFile = Join-Path $HistoryPath "audit-history.json"
    $HistoryData = @()
    if (Test-Path $HistoryFile) {
        $HistoryData = Get-Content $HistoryFile | ConvertFrom-Json
    }
    $HistoryData += $HistoryRecord
    $HistoryData | ConvertTo-Json -Depth 10 | Out-File $HistoryFile -Force
    
    Write-AuditSuccess "Historical data saved"
    Write-Host ""
    
    # Step 5: Generate HTML Report
    Write-AuditStep "5/5" "Generating compliance report..."
    
    $ReportGenerator = Join-Path $PSScriptRoot "New-Essential8Report.ps1"
    if (Test-Path $ReportGenerator) {
        $ReportFile = & $ReportGenerator -ResultsPath $ResultsFile `
                                         -OutputPath $ReportPath `
                                         -TenantId $TenantId `
                                         -MaturityLevel $MaturityLevel `
                                         -HistoryPath $HistoryFile
        
        Write-AuditSuccess "Report generated: $ReportFile"
    } else {
        Write-AuditError "Report generator not found - skipping HTML report"
    }
    
    Write-Host ""
    
    # Summary
    $Duration = ((Get-Date) - $StartTime).TotalMinutes
    
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    Audit Completed Successfully                  ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Duration: $([Math]::Round($Duration, 1)) minutes" -ForegroundColor Gray
    Write-Host "Compliance Score: $ComplianceScore% ($PassedRules/$($Results.Count) rules passed)" -ForegroundColor $(if($ComplianceScore -ge 80){'Green'}elseif($ComplianceScore -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
    Write-Host "Reports saved to: $ReportPath" -ForegroundColor Cyan
    Write-Host ""
    
    if ($ReportFile -and (Test-Path $ReportFile)) {
        Write-Host "Open report: " -NoNewline -ForegroundColor Yellow
        Write-Host $ReportFile -ForegroundColor White
        Write-Host ""
        
        $OpenReport = Read-Host "Open HTML report now? (Y/N)"
        if ($OpenReport -eq 'Y') {
            Start-Process $ReportFile
        }
    }
    
} catch {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                        Audit Failed                              ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Gray
    Write-Host $_.Exception.StackTrace -ForegroundColor DarkGray
    
    exit 1
}

#endregion

