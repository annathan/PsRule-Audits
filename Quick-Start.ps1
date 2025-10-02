# Quick-Start.ps1
# One-click Essential 8 compliance assessment for customers
# Handles all authentication and data collection automatically

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Essential8-Data",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipInteractiveAuth,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           Essential 8 Quick Start - One-Click Assessment        ║" -ForegroundColor Cyan
Write-Host "║           Complete Microsoft 365 Compliance Check               ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function Write-QuickStep {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor White
}

function Write-QuickSuccess {
    param([string]$Message)
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
    Write-Host $Message -ForegroundColor Gray
}

function Write-QuickError {
    param([string]$Message)
    Write-Host "  ✗ " -NoNewline -ForegroundColor Red
    Write-Host $Message -ForegroundColor Gray
}

function Write-QuickWarning {
    param([string]$Message)
    Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor Gray
}

#endregion

#region Step 1: Prerequisites Check

Write-QuickStep "1/4" "Checking prerequisites and installing required modules..."

# Check PowerShell execution policy
$ExecutionPolicy = Get-ExecutionPolicy
if ($ExecutionPolicy -eq 'Restricted') {
    Write-QuickWarning "Execution policy is Restricted - attempting to change it"
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop
        Write-QuickSuccess "Execution policy updated to RemoteSigned"
    } catch {
        Write-QuickError "Could not change execution policy - you may need to run as Administrator"
    }
}

# Install required modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Applications',
    'ExchangeOnlineManagement',
    'PnP.PowerShell',
    'MicrosoftTeams'
)

$InstalledCount = 0
foreach ($Module in $RequiredModules) {
    try {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            Write-Host "  Installing $Module..." -ForegroundColor Gray
            Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop | Out-Null
        }
        $InstalledCount++
    } catch {
        Write-QuickWarning "Failed to install $Module - some features may be limited"
    }
}

Write-QuickSuccess "Installed $InstalledCount of $($RequiredModules.Count) required modules"

Write-Host ""

#endregion

#region Step 2: Data Collection

Write-QuickStep "2/4" "Collecting Microsoft 365 data for Essential 8 assessment..."

try {
    # Run the production data collector
    $DataCollectorPath = Join-Path $PSScriptRoot "Collectors\Essential8-DataCollector-Production.ps1"
    
    if (Test-Path $DataCollectorPath) {
        Write-Host "  Running comprehensive data collection..." -ForegroundColor Gray
        
        $CollectorParams = @{
            TenantId = $TenantId
            OutputPath = $OutputPath
        }
        
        if ($SkipInteractiveAuth) {
            $CollectorParams.Add('SkipInteractiveAuth', $true)
        }
        
        & $DataCollectorPath @CollectorParams
        
        if ($LASTEXITCODE -eq 0) {
            Write-QuickSuccess "Data collection completed successfully"
        } else {
            Write-QuickWarning "Data collection completed with warnings - some data may be missing"
        }
    } else {
        Write-QuickError "Data collector not found at $DataCollectorPath"
        exit 1
    }
    
} catch {
    Write-QuickError "Data collection failed: $($_.Exception.Message)"
    Write-QuickWarning "Continuing with available data..."
}

Write-Host ""

#endregion

#region Step 3: Compliance Analysis

Write-QuickStep "3/4" "Running Essential 8 compliance analysis..."

try {
    # Run the complete rule test
    $RuleTestPath = Join-Path $PSScriptRoot "Complete-Rule-Test.ps1"
    
    if (Test-Path $RuleTestPath) {
        Write-Host "  Analyzing compliance against Essential 8 framework..." -ForegroundColor Gray
        
        & $RuleTestPath
        
        if ($LASTEXITCODE -eq 0) {
            Write-QuickSuccess "Compliance analysis completed successfully"
        } else {
            Write-QuickWarning "Compliance analysis completed with warnings"
        }
    } else {
        Write-QuickError "Rule test script not found at $RuleTestPath"
        exit 1
    }
    
} catch {
    Write-QuickError "Compliance analysis failed: $($_.Exception.Message)"
    Write-QuickWarning "Check the data collection results and try again"
}

Write-Host ""

#endregion

#region Step 4: Report Generation

if ($GenerateReport) {
    Write-QuickStep "4/4" "Generating professional HTML compliance report..."
    
    try {
        # Run the report generator
        $ReportPath = Join-Path $PSScriptRoot "Generate-Report.ps1"
        
        if (Test-Path $ReportPath) {
            Write-Host "  Creating HTML compliance report..." -ForegroundColor Gray
            
            & $ReportPath
            
            if ($LASTEXITCODE -eq 0) {
                Write-QuickSuccess "HTML compliance report generated successfully"
            } else {
                Write-QuickWarning "Report generation completed with warnings"
            }
        } else {
            Write-QuickError "Report generator not found at $ReportPath"
        }
        
    } catch {
        Write-QuickError "Report generation failed: $($_.Exception.Message)"
    }
} else {
    Write-QuickStep "4/4" "Skipping report generation (use -GenerateReport to create HTML report)"
}

Write-Host ""

#endregion

#region Final Summary

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Essential 8 Quick Start Complete! ✓                ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# Check results
$ResultsFile = Join-Path $PSScriptRoot "Essential8-Results.json"
$ReportFile = Join-Path $PSScriptRoot "Essential8-Compliance-Report.html"

Write-Host "📊 Quick Start Summary:" -ForegroundColor Cyan
Write-Host "  Tenant: $TenantId" -ForegroundColor Gray
Write-Host "  Data collected: $(if(Test-Path $OutputPath){'✅ Yes'}else{'❌ No'})" -ForegroundColor $(if(Test-Path $OutputPath){'Green'}else{'Red'})
Write-Host "  Compliance analysis: $(if(Test-Path $ResultsFile){'✅ Complete'}else{'❌ Failed'})" -ForegroundColor $(if(Test-Path $ResultsFile){'Green'}else{'Red'})
Write-Host "  HTML report: $(if(Test-Path $ReportFile){'✅ Generated'}else{'❌ Not generated'})" -ForegroundColor $(if(Test-Path $ReportFile){'Green'}else{'Red'})

Write-Host ""
Write-Host "📋 What's Next:" -ForegroundColor Yellow
Write-Host "  1. Review the compliance results in Essential8-Results.json" -ForegroundColor Gray
if (Test-Path $ReportFile) {
    Write-Host "  2. Open the HTML report: $ReportFile" -ForegroundColor Gray
} else {
    Write-Host "  2. Generate HTML report: .\Generate-Report.ps1" -ForegroundColor Gray
}
Write-Host "  3. Address any compliance issues identified" -ForegroundColor Gray
Write-Host "  4. Schedule regular compliance checks" -ForegroundColor Gray

Write-Host ""
Write-Host "🎯 Essential 8 Strategies Assessed:" -ForegroundColor Yellow
Write-Host "  • E8-1: Application Control" -ForegroundColor Gray
Write-Host "  • E8-2: Patch Applications" -ForegroundColor Gray
Write-Host "  • E8-3: Configure Microsoft Office Macro Settings" -ForegroundColor Gray
Write-Host "  • E8-4: User Application Hardening" -ForegroundColor Gray
Write-Host "  • E8-5: Restrict Administrative Privileges" -ForegroundColor Gray
Write-Host "  • E8-6: Patch Operating Systems" -ForegroundColor Gray
Write-Host "  • E8-7: Multi-Factor Authentication" -ForegroundColor Gray
Write-Host "  • E8-8: Regular Backups" -ForegroundColor Gray

Write-Host ""
Write-Host "✅ Essential 8 Quick Start completed successfully!" -ForegroundColor Green
Write-Host "  Your Microsoft 365 environment has been assessed against Essential 8! 🎉" -ForegroundColor Green
Write-Host ""

#endregion
