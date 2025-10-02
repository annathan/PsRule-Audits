# Install-Prerequisites.ps1
# Installs all required PowerShell modules for Essential 8 auditing

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Essential 8 Audit Tool - Prerequisites Installation         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator (recommended but not required)
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "✓ Running as Administrator - modules will be installed for all users" -ForegroundColor Green
    $Scope = 'AllUsers'
} else {
    Write-Host "ℹ Running as standard user - modules will be installed for current user only" -ForegroundColor Yellow
    $Scope = 'CurrentUser'
}
Write-Host ""

# Required modules
$RequiredModules = @(
    @{ Name = 'PSRule'; MinVersion = '2.0.0'; Description = 'Rule engine for compliance testing' }
    @{ Name = 'Microsoft.Graph.Authentication'; MinVersion = '1.0.0'; Description = 'Microsoft Graph authentication' }
    @{ Name = 'Microsoft.Graph.Users'; MinVersion = '1.0.0'; Description = 'User account management' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns'; MinVersion = '1.0.0'; Description = 'MFA and sign-in policies' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinVersion = '1.0.0'; Description = 'Directory and roles' }
    @{ Name = 'Microsoft.Graph.Applications'; MinVersion = '1.0.0'; Description = 'Application registrations' }
    @{ Name = 'ExchangeOnlineManagement'; MinVersion = '2.0.0'; Description = 'Exchange Online policies' }
    @{ Name = 'PnP.PowerShell'; MinVersion = '1.12.0'; Description = 'SharePoint Online management' }
)

$InstalledCount = 0
$UpdatedCount = 0
$FailedModules = @()

Write-Host "Checking modules..." -ForegroundColor Cyan
Write-Host ""

foreach ($Module in $RequiredModules) {
    $ModuleName = $Module.Name
    $MinVersion = $Module.MinVersion
    $Description = $Module.Description
    
    Write-Host "  Checking: " -NoNewline
    Write-Host $ModuleName -ForegroundColor White -NoNewline
    Write-Host " ($Description)" -ForegroundColor Gray
    
    try {
        $Installed = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
        
        if ($Installed) {
            if ($Installed.Version -ge [Version]$MinVersion) {
                Write-Host "    ✓ Already installed - v$($Installed.Version)" -ForegroundColor Green
                
                if ($Force) {
                    Write-Host "    ↻ Updating to latest version..." -ForegroundColor Yellow
                    Update-Module -Name $ModuleName -Scope $Scope -Force -ErrorAction Stop
                    $UpdatedCount++
                    Write-Host "    ✓ Updated successfully" -ForegroundColor Green
                }
            } else {
                Write-Host "    ⚠ Installed version ($($Installed.Version)) is older than required ($MinVersion)" -ForegroundColor Yellow
                Write-Host "    ↻ Updating..." -ForegroundColor Yellow
                Update-Module -Name $ModuleName -Scope $Scope -Force -ErrorAction Stop
                $UpdatedCount++
                Write-Host "    ✓ Updated successfully" -ForegroundColor Green
            }
        } else {
            Write-Host "    ✗ Not installed - Installing..." -ForegroundColor Yellow
            Install-Module -Name $ModuleName -Scope $Scope -Force -AllowClobber -MinimumVersion $MinVersion -ErrorAction Stop
            $InstalledCount++
            Write-Host "    ✓ Installed successfully" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "    ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
        $FailedModules += $ModuleName
    }
    
    Write-Host ""
}

# Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    Installation Summary                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($FailedModules.Count -eq 0) {
    Write-Host "✓ All prerequisites installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Modules installed: $InstalledCount" -ForegroundColor Gray
    Write-Host "Modules updated: $UpdatedCount" -ForegroundColor Gray
    Write-Host ""
    Write-Host "You can now run your first audit:" -ForegroundColor Yellow
    Write-Host '  .\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com"' -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "⚠ Some modules failed to install:" -ForegroundColor Yellow
    foreach ($Failed in $FailedModules) {
        Write-Host "  - $Failed" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Try running this script as Administrator, or install manually:" -ForegroundColor Yellow
    Write-Host "  Install-Module $($FailedModules -join ', ') -Scope CurrentUser -Force" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# Test PSRule
Write-Host "Testing PSRule installation..." -ForegroundColor Cyan
try {
    $PSRuleVersion = (Get-Module PSRule -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
    Write-Host "✓ PSRule v$PSRuleVersion is ready" -ForegroundColor Green
} catch {
    Write-Host "✗ PSRule test failed - you may need to restart PowerShell" -ForegroundColor Red
}

Write-Host ""
Write-Host "Installation complete! 🎉" -ForegroundColor Green
Write-Host ""

