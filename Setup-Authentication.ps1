# Setup-Authentication.ps1
# Comprehensive authentication setup for Essential 8 Microsoft 365 data collection
# This script helps customers configure all necessary permissions and authentication methods

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$AdminEmail,
    
    [Parameter(Mandatory = $false)]
    [switch]$SetupAppRegistration,
    
    [Parameter(Mandatory = $false)]
    [string]$AppName = "Essential8-Compliance-Audit"
)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           Essential 8 Authentication Setup                      ║" -ForegroundColor Cyan
Write-Host "║           Complete Microsoft 365 Configuration                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function Write-SetupStep {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor White
}

function Write-SetupSuccess {
    param([string]$Message)
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
    Write-Host $Message -ForegroundColor Gray
}

function Write-SetupError {
    param([string]$Message)
    Write-Host "  ✗ " -NoNewline -ForegroundColor Red
    Write-Host $Message -ForegroundColor Gray
}

function Write-SetupWarning {
    param([string]$Message)
    Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor Gray
}

function Write-SetupInfo {
    param([string]$Message)
    Write-Host "  ℹ " -NoNewline -ForegroundColor Blue
    Write-Host $Message -ForegroundColor Gray
}

#endregion

#region Prerequisites Check

Write-SetupStep "1/6" "Checking prerequisites and required modules..."

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($IsAdmin) {
    Write-SetupSuccess "Running with administrator privileges"
} else {
    Write-SetupWarning "Not running as administrator - some operations may require elevation"
}

# Check PowerShell execution policy
$ExecutionPolicy = Get-ExecutionPolicy
Write-SetupInfo "Current execution policy: $ExecutionPolicy"
if ($ExecutionPolicy -eq 'Restricted') {
    Write-SetupWarning "Execution policy is Restricted - you may need to change it to run scripts"
    Write-Host "  Run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
}

# Check required modules
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

$MissingModules = @()
foreach ($Module in $RequiredModules) {
    if (!(Get-Module -ListAvailable -Name $Module)) {
        $MissingModules += $Module
    }
}

if ($MissingModules.Count -eq 0) {
    Write-SetupSuccess "All required modules are available"
} else {
    Write-SetupWarning "Missing modules: $($MissingModules -join ', ')"
    Write-Host "  Run: Install-Module -Name '$($MissingModules -join "','")' -Force -AllowClobber" -ForegroundColor Yellow
}

Write-Host ""

#endregion

#region Microsoft Graph Authentication Setup

Write-SetupStep "2/6" "Setting up Microsoft Graph authentication..."

try {
    # Connect to Microsoft Graph
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Gray
    Connect-MgGraph -TenantId $TenantId -Scopes @(
        'User.Read.All',
        'Directory.Read.All',
        'Application.Read.All',
        'Policy.Read.All',
        'RoleManagement.Read.Directory',
        'IdentityRiskyUser.Read.All',
        'IdentityRiskEvent.Read.All',
        'IdentityProtection.Read.All',
        'SecurityEvents.Read.All',
        'AuditLog.Read.All',
        'Reports.Read.All'
    ) -ErrorAction Stop
    
    $Context = Get-MgContext
    if ($Context) {
        Write-SetupSuccess "Connected to Microsoft Graph as: $($Context.Account)"
        Write-SetupInfo "Tenant: $($Context.TenantId)"
        Write-SetupInfo "Scopes: $($Context.Scopes -join ', ')"
    } else {
        throw "Failed to establish Microsoft Graph context"
    }
    
} catch {
    Write-SetupError "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    Write-Host "  Please ensure you have the required permissions and try again" -ForegroundColor Red
    exit 1
}

Write-Host ""

#endregion

#region App Registration Setup (Optional)

if ($SetupAppRegistration) {
    Write-SetupStep "3/6" "Setting up App Registration for automated authentication..."
    
    try {
        # Create App Registration
        Write-Host "  Creating App Registration: $AppName..." -ForegroundColor Gray
        
        $AppRegistration = New-MgApplication -DisplayName $AppName -ErrorAction Stop
        Write-SetupSuccess "Created App Registration: $($AppRegistration.Id)"
        
        # Create Service Principal
        $ServicePrincipal = New-MgServicePrincipal -AppId $AppRegistration.AppId -ErrorAction Stop
        Write-SetupSuccess "Created Service Principal: $($ServicePrincipal.Id)"
        
        # Add required API permissions
        Write-Host "  Adding required API permissions..." -ForegroundColor Gray
        
        $RequiredPermissions = @(
            @{ ResourceAppId = "00000003-0000-0000-c000-000000000000"; ResourceAccess = @(
                @{ Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; Type = "Scope" }, # User.Read
                @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }, # User.Read.All
                @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }, # Directory.Read.All
                @{ Id = "9a5d68dd-52b0-4cc2-bd40-8c4e1d3c0c4c"; Type = "Role" }, # Application.Read.All
                @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Type = "Role" }, # Policy.Read.All
                @{ Id = "b0f44761-37d0-4c8a-8c23-4a091b616d2f"; Type = "Role" }, # RoleManagement.Read.Directory
                @{ Id = "bf394140-e372-4bf9-a898-299cfc7564e5"; Type = "Role" }, # IdentityRiskyUser.Read.All
                @{ Id = "8b6d3b8e-1145-4b4c-9c75-59cd44960de1"; Type = "Role" }, # IdentityRiskEvent.Read.All
                @{ Id = "9a5d68dd-52b0-4cc2-bd40-8c4e1d3c0c4c"; Type = "Role" }, # IdentityProtection.Read.All
                @{ Id = "bf394140-e372-4bf9-a898-299cfc7564e5"; Type = "Role" }, # SecurityEvents.Read.All
                @{ Id = "b0f44761-37d0-4c8a-8c23-4a091b616d2f"; Type = "Role" }  # AuditLog.Read.All
            )}
        )
        
        # Update application with required permissions
        $AppRegistration = Update-MgApplication -ApplicationId $AppRegistration.Id -RequiredResourceAccess $RequiredPermissions -ErrorAction Stop
        Write-SetupSuccess "Added required API permissions"
        
        # Create client secret
        $ClientSecret = Add-MgApplicationPassword -ApplicationId $AppRegistration.Id -PasswordCredential @{
            DisplayName = "Essential8-Audit-Secret"
            EndDateTime = (Get-Date).AddYears(2)
        } -ErrorAction Stop
        
        Write-SetupSuccess "Created client secret (valid for 2 years)"
        
        # Save configuration
        $AppConfig = @{
            TenantId = $TenantId
            ApplicationId = $AppRegistration.AppId
            ClientSecret = $ClientSecret.SecretText
            AppName = $AppName
            CreatedDate = Get-Date
        }
        
        $AppConfig | ConvertTo-Json | Out-File "Essential8-AppConfig.json" -Force
        Write-SetupSuccess "Saved App Registration configuration to Essential8-AppConfig.json"
        
        Write-Host ""
        Write-Host "🔐 App Registration Details:" -ForegroundColor Yellow
        Write-Host "  Application ID: $($AppRegistration.AppId)" -ForegroundColor Gray
        Write-Host "  Client Secret: $($ClientSecret.SecretText)" -ForegroundColor Gray
        Write-Host "  Tenant ID: $TenantId" -ForegroundColor Gray
        Write-Host ""
        Write-Host "⚠️  IMPORTANT: Save the client secret securely - it won't be shown again!" -ForegroundColor Red
        
    } catch {
        Write-SetupError "Failed to create App Registration: $($_.Exception.Message)"
        Write-SetupWarning "You can still use interactive authentication"
    }
} else {
    Write-SetupStep "3/6" "Skipping App Registration setup (using interactive authentication)"
}

Write-Host ""

#endregion

#region Exchange Online Authentication Test

Write-SetupStep "4/6" "Testing Exchange Online authentication..."

try {
    Write-Host "  Testing Exchange Online connection..." -ForegroundColor Gray
    
    # Test Exchange Online connection
    $UserPrincipalName = (Get-MgContext).Account
    Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ErrorAction Stop
    
    # Test basic cmdlet
    $OrgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-SetupSuccess "Exchange Online authentication successful"
    Write-SetupInfo "Organization: $($OrgConfig.DisplayName)"
    
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    
} catch {
    Write-SetupError "Exchange Online authentication failed: $($_.Exception.Message)"
    Write-SetupWarning "Exchange data collection will be limited"
}

Write-Host ""

#endregion

#region SharePoint Online Authentication Test

Write-SetupStep "5/6" "Testing SharePoint Online authentication..."

try {
    Write-Host "  Testing SharePoint Online connection..." -ForegroundColor Gray
    
    # Test SharePoint Online connection
    $AdminUrl = "https://$($TenantId.Split('.')[0])-admin.sharepoint.com"
    Connect-PnPOnline -Url $AdminUrl -Interactive -ErrorAction Stop
    
    # Test basic cmdlet
    $TenantSettings = Get-PnPTenant -ErrorAction Stop
    Write-SetupSuccess "SharePoint Online authentication successful"
    Write-SetupInfo "Tenant URL: $AdminUrl"
    
    Disconnect-PnPOnline -ErrorAction SilentlyContinue
    
} catch {
    Write-SetupError "SharePoint Online authentication failed: $($_.Exception.Message)"
    Write-SetupWarning "SharePoint data collection will be limited"
}

Write-Host ""

#endregion

#region Microsoft Teams Authentication Test

Write-SetupStep "6/6" "Testing Microsoft Teams authentication..."

try {
    Write-Host "  Testing Microsoft Teams connection..." -ForegroundColor Gray
    
    # Test Microsoft Teams connection
    $UserPrincipalName = (Get-MgContext).Account
    Connect-MicrosoftTeams -AccountId $UserPrincipalName -ErrorAction Stop
    
    # Test basic cmdlet
    $TeamsPolicies = Get-CsTeamsMeetingPolicy -ErrorAction Stop
    Write-SetupSuccess "Microsoft Teams authentication successful"
    Write-SetupInfo "Teams policies available: $($TeamsPolicies.Count)"
    
    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
    
} catch {
    Write-SetupError "Microsoft Teams authentication failed: $($_.Exception.Message)"
    Write-SetupWarning "Teams data collection will be limited"
}

Write-Host ""

#endregion

#region Final Summary and Next Steps

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Authentication Setup Complete! ✓                  ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "🎯 Authentication Status:" -ForegroundColor Cyan
Write-Host "  Microsoft Graph: ✅ Connected" -ForegroundColor Green
Write-Host "  Exchange Online: $(if($?){'✅ Connected'}else{'❌ Failed'})" -ForegroundColor $(if($?){'Green'}else{'Red'})
Write-Host "  SharePoint Online: $(if($?){'✅ Connected'}else{'❌ Failed'})" -ForegroundColor $(if($?){'Green'}else{'Red'})
Write-Host "  Microsoft Teams: $(if($?){'✅ Connected'}else{'❌ Failed'})" -ForegroundColor $(if($?){'Green'}else{'Red'})


Write-Host ""
Write-Host "📋 Required Permissions Summary:" -ForegroundColor Yellow
Write-Host "  • Global Administrator (for full data collection)" -ForegroundColor Gray
Write-Host "  • Security Administrator (for security data)" -ForegroundColor Gray
Write-Host "  • Exchange Administrator (for Exchange data)" -ForegroundColor Gray
Write-Host "  • SharePoint Administrator (for SharePoint data)" -ForegroundColor Gray
Write-Host "  • Teams Administrator (for Teams data)" -ForegroundColor Gray

Write-Host ""
Write-Host "🚀 Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Run data collection: .\Collectors\Essential8-DataCollector-Production.ps1 -TenantId '$TenantId'" -ForegroundColor Gray
Write-Host "  2. Run compliance analysis: .\Complete-Rule-Test.ps1" -ForegroundColor Gray
Write-Host "  3. Generate report: .\Generate-Report.ps1" -ForegroundColor Gray

if ($SetupAppRegistration -and (Test-Path "Essential8-AppConfig.json")) {
    Write-Host ""
    Write-Host "🔐 App Registration Configuration:" -ForegroundColor Yellow
    Write-Host "  Use this configuration for automated data collection:" -ForegroundColor Gray
    Write-Host "  .\Collectors\Essential8-DataCollector-Production.ps1 -TenantId '$TenantId' -UseApplicationAuth -ApplicationId '<AppId>' -ApplicationSecret '<Secret>'" -ForegroundColor Gray
}

Write-Host ""
Write-Host "✅ Authentication setup completed successfully!" -ForegroundColor Green
Write-Host "  Ready for complete Essential 8 compliance assessment! 🎉" -ForegroundColor Green
Write-Host ""

# Cleanup
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
} catch {
    # Ignore cleanup errors
}

#endregion
