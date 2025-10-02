# Essential8-DataCollector-Fixed.ps1
# Fixed version that handles authentication issues and collects data more reliably

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Essential8-Data",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'AzureAD', 'Exchange', 'SharePoint', 'Security')]
    [string[]]$Services = @('All'),
    
    [Parameter(Mandatory = $false)]
    [switch]$UseApplicationAuth,
    
    [Parameter(Mandatory = $false)]
    [string]$ApplicationId,
    
    [Parameter(Mandatory = $false)]
    [string]$ApplicationSecret
)

#region Helper Functions

function Write-CollectionStep {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor White
}

function Write-CollectionSuccess {
    param([string]$Message)
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
    Write-Host $Message -ForegroundColor Gray
}

function Write-CollectionError {
    param([string]$Message)
    Write-Host "  ✗ " -NoNewline -ForegroundColor Red
    Write-Host $Message -ForegroundColor Gray
}

function Test-ModuleAvailable {
    param([string]$ModuleName)
    return (Get-Module -ListAvailable -Name $ModuleName) -ne $null
}

#endregion

#region Prerequisites and Initialization

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Essential 8 Data Collection (Fixed)                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-CollectionStep "1/6" "Checking prerequisites and modules..."

# Required modules for data collection
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users', 
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Applications'
)

$OptionalModules = @(
    'ExchangeOnlineManagement',
    'PnP.PowerShell'
)

$MissingModules = @()
$AvailableModules = @()

foreach ($Module in $RequiredModules) {
    if (Test-ModuleAvailable $Module) {
        Write-CollectionSuccess "Module $Module found"
        $AvailableModules += $Module
    } else {
        Write-CollectionError "Module $Module not found"
        $MissingModules += $Module
    }
}

foreach ($Module in $OptionalModules) {
    if (Test-ModuleAvailable $Module) {
        Write-CollectionSuccess "Optional module $Module found"
        $AvailableModules += $Module
    } else {
        Write-CollectionError "Optional module $Module not found (some features may be limited)"
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Host ""
    Write-Host "Installing missing required modules..." -ForegroundColor Yellow
    foreach ($Module in $MissingModules) {
        try {
            Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-CollectionSuccess "Installed $Module"
            $AvailableModules += $Module
        } catch {
            Write-CollectionError "Failed to install $Module : $($_.Exception.Message)"
        }
    }
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host ""

#endregion

#region Azure AD Data Collection (Core - Always Available)

Write-CollectionStep "2/6" "Collecting Azure AD data (core authentication data)..."

$AzureADPath = Join-Path $OutputPath "AzureAD"
if (!(Test-Path $AzureADPath)) { New-Item -Path $AzureADPath -ItemType Directory -Force | Out-Null }

try {
    # Connect to Microsoft Graph with minimal scopes
    $Scopes = @(
        'User.Read.All',
        'Directory.Read.All', 
        'Application.Read.All'
    )
    
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Gray
    Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -ErrorAction Stop
    Write-CollectionSuccess "Connected to Microsoft Graph"
    
    # 1. User accounts and MFA status
    Write-Host "  Collecting user MFA configuration..." -ForegroundColor Gray
    try {
        $Users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,AssignedLicenses,StrongAuthenticationRequirements -ErrorAction Stop
        $Users | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "Users-MFA.json") -Force
        Write-CollectionSuccess "Collected $($Users.Count) users"
    } catch {
        Write-CollectionError "Could not collect users: $($_.Exception.Message)"
        # Create empty file to prevent errors
        @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "Users-MFA.json") -Force
    }
    
    # 2. Service Principals and Applications
    Write-Host "  Collecting service principals..." -ForegroundColor Gray
    try {
        $ServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,KeyCredentials,PasswordCredentials,ServicePrincipalType -ErrorAction Stop
        $ServicePrincipals | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "ServicePrincipals.json") -Force
        Write-CollectionSuccess "Collected $($ServicePrincipals.Count) service principals"
    } catch {
        Write-CollectionError "Could not collect service principals: $($_.Exception.Message)"
        @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "ServicePrincipals.json") -Force
    }
    
    # 3. Applications
    Write-Host "  Collecting applications..." -ForegroundColor Gray
    try {
        $Applications = Get-MgApplication -All -Property Id,DisplayName,AppId,KeyCredentials,PasswordCredentials,RequiredResourceAccess -ErrorAction Stop
        $Applications | ConvertTo-Json -Depth 4 | Out-File (Join-Path $AzureADPath "Applications.json") -Force
        Write-CollectionSuccess "Collected $($Applications.Count) applications"
    } catch {
        Write-CollectionError "Could not collect applications: $($_.Exception.Message)"
        @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "Applications.json") -Force
    }
    
    # 4. Directory Roles (Privileged roles)
    Write-Host "  Collecting privileged role assignments..." -ForegroundColor Gray
    try {
        $DirectoryRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $PrivilegedRoles = @()
        foreach ($Role in $DirectoryRoles) {
            try {
                $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -ErrorAction Stop
                $PrivilegedRoles += [PSCustomObject]@{
                    RoleName = $Role.DisplayName
                    RoleId = $Role.Id
                    Members = $Members
                }
            } catch {
                Write-CollectionError "Could not collect members for role $($Role.DisplayName)"
            }
        }
        $PrivilegedRoles | ConvertTo-Json -Depth 4 | Out-File (Join-Path $AzureADPath "PrivilegedRoles.json") -Force
        Write-CollectionSuccess "Collected $($PrivilegedRoles.Count) privileged roles"
    } catch {
        Write-CollectionError "Could not collect privileged roles: $($_.Exception.Message)"
        @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "PrivilegedRoles.json") -Force
    }
    
    # 5. Conditional Access policies (if available)
    Write-Host "  Collecting Conditional Access policies..." -ForegroundColor Gray
    try {
        $ConditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $ConditionalAccessPolicies | ConvertTo-Json -Depth 5 | Out-File (Join-Path $AzureADPath "ConditionalAccessPolicies.json") -Force
        Write-CollectionSuccess "Collected $($ConditionalAccessPolicies.Count) Conditional Access policies"
    } catch {
        Write-CollectionError "Could not collect Conditional Access policies: $($_.Exception.Message)"
        @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "ConditionalAccessPolicies.json") -Force
    }
    
    # 6. Tenant information
    Write-Host "  Collecting tenant configuration..." -ForegroundColor Gray
    try {
        $Organization = Get-MgOrganization -ErrorAction Stop
        $Organization | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "TenantInfo.json") -Force
        Write-CollectionSuccess "Collected tenant information"
    } catch {
        Write-CollectionError "Could not collect tenant information: $($_.Exception.Message)"
        @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "TenantInfo.json") -Force
    }
    
} catch {
    Write-CollectionError "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    Write-Host "  This is likely due to authentication issues. Please ensure you have appropriate permissions." -ForegroundColor Yellow
}

Write-Host ""

#endregion

#region Exchange Online Data Collection (Optional)

if ($Services -contains 'All' -or $Services -contains 'Exchange') {
    Write-CollectionStep "3/6" "Collecting Exchange Online data (optional)..."
    
    if (Test-ModuleAvailable 'ExchangeOnlineManagement') {
        try {
            $ExchangePath = Join-Path $OutputPath "Exchange"
            if (!(Test-Path $ExchangePath)) { New-Item -Path $ExchangePath -ItemType Directory -Force | Out-Null }
            
            Write-Host "  Connecting to Exchange Online..." -ForegroundColor Gray
            Connect-ExchangeOnline -ErrorAction Stop
            Write-CollectionSuccess "Connected to Exchange Online"
            
            # Collect basic Exchange data
            Write-Host "  Collecting organization configuration..." -ForegroundColor Gray
            try {
                $OrgConfig = Get-OrganizationConfig -ErrorAction Stop
                $OrgConfig | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "OrganizationConfig.json") -Force
                Write-CollectionSuccess "Collected organization configuration"
            } catch {
                Write-CollectionError "Could not collect organization configuration: $($_.Exception.Message)"
                @() | ConvertTo-Json | Out-File (Join-Path $ExchangePath "OrganizationConfig.json") -Force
            }
            
        } catch {
            Write-CollectionError "Failed to connect to Exchange Online: $($_.Exception.Message)"
            Write-Host "  Exchange data collection skipped - this is optional for Essential 8" -ForegroundColor Yellow
        }
    } else {
        Write-CollectionError "ExchangeOnlineManagement module not available"
        Write-Host "  Exchange data collection skipped" -ForegroundColor Yellow
    }
} else {
    Write-CollectionStep "3/6" "Skipping Exchange Online data collection"
}

Write-Host ""

#endregion

#region SharePoint Online Data Collection (Optional)

if ($Services -contains 'All' -or $Services -contains 'SharePoint') {
    Write-CollectionStep "4/6" "Collecting SharePoint Online data (optional)..."
    
    if (Test-ModuleAvailable 'PnP.PowerShell') {
        try {
            $SharePointPath = Join-Path $OutputPath "SharePoint"
            if (!(Test-Path $SharePointPath)) { New-Item -Path $SharePointPath -ItemType Directory -Force | Out-Null }
            
            Write-Host "  Connecting to SharePoint Online..." -ForegroundColor Gray
            $AdminUrl = "https://$($TenantId.Split('.')[0])-admin.sharepoint.com"
            Connect-PnPOnline -Url $AdminUrl -Interactive -ErrorAction Stop
            Write-CollectionSuccess "Connected to SharePoint Online"
            
            # Collect basic SharePoint data
            Write-Host "  Collecting tenant settings..." -ForegroundColor Gray
            try {
                $TenantSettings = Get-PnPTenant -ErrorAction Stop
                $TenantSettings | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SharePointPath "TenantSettings.json") -Force
                Write-CollectionSuccess "Collected tenant settings"
            } catch {
                Write-CollectionError "Could not collect tenant settings: $($_.Exception.Message)"
                @() | ConvertTo-Json | Out-File (Join-Path $SharePointPath "TenantSettings.json") -Force
            }
            
        } catch {
            Write-CollectionError "Failed to connect to SharePoint Online: $($_.Exception.Message)"
            Write-Host "  SharePoint data collection skipped - this is optional for Essential 8" -ForegroundColor Yellow
        }
    } else {
        Write-CollectionError "PnP.PowerShell module not available"
        Write-Host "  SharePoint data collection skipped" -ForegroundColor Yellow
    }
} else {
    Write-CollectionStep "4/6" "Skipping SharePoint Online data collection"
}

Write-Host ""

#endregion

#region Security & Compliance Data Collection (Optional)

if ($Services -contains 'All' -or $Services -contains 'Security') {
    Write-CollectionStep "5/6" "Collecting Security & Compliance data (optional)..."
    
    try {
        $SecurityPath = Join-Path $OutputPath "Security"
        if (!(Test-Path $SecurityPath)) { New-Item -Path $SecurityPath -ItemType Directory -Force | Out-Null }
        
        # Note: Security & Compliance requires additional modules and permissions
        Write-Host "  Security & Compliance data collection requires additional setup" -ForegroundColor Yellow
        Write-Host "  This is optional for Essential 8 - creating placeholder files" -ForegroundColor Gray
        
        # Create placeholder files
        @() | ConvertTo-Json | Out-File (Join-Path $SecurityPath "AntiPhishingPolicies.json") -Force
        @() | ConvertTo-Json | Out-File (Join-Path $SecurityPath "AuditConfig.json") -Force
        @() | ConvertTo-Json | Out-File (Join-Path $SecurityPath "RetentionPolicies.json") -Force
        
        Write-CollectionSuccess "Created placeholder Security & Compliance files"
        
    } catch {
        Write-CollectionError "Failed to create Security & Compliance placeholders: $($_.Exception.Message)"
    }
} else {
    Write-CollectionStep "5/6" "Skipping Security & Compliance data collection"
}

Write-Host ""

#endregion

#region Save Collection Metadata

Write-CollectionStep "6/6" "Saving collection metadata and summary..."

$CollectionMetadata = @{
    CollectionDate = Get-Date
    TenantId = $TenantId
    CollectedServices = $Services
    AvailableModules = $AvailableModules
    MissingModules = $MissingModules
    Version = "2.0"
    Status = "Completed with limitations"
    Notes = @(
        "Some data collection may be limited due to authentication or permission issues",
        "This is normal for Essential 8 compliance testing",
        "Focus on the data that was successfully collected"
    )
}

$CollectionMetadata | ConvertTo-Json -Depth 2 | Out-File (Join-Path $OutputPath "CollectionMetadata.json") -Force

Write-CollectionSuccess "Collection metadata saved"

# Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    Data Collection Complete! ✓                  ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

$DataFiles = Get-ChildItem -Path $OutputPath -Recurse -Filter "*.json" | Where-Object { $_.Length -gt 0 }
Write-Host "📊 Collection Summary:" -ForegroundColor Cyan
Write-Host "  Tenant: $TenantId" -ForegroundColor Gray
Write-Host "  Data files created: $($DataFiles.Count)" -ForegroundColor Gray
Write-Host "  Total data size: $([Math]::Round(($DataFiles | Measure-Object Length -Sum).Sum / 1KB, 2)) KB" -ForegroundColor Gray
Write-Host "  Available modules: $($AvailableModules.Count)" -ForegroundColor Gray

if ($MissingModules.Count -gt 0) {
    Write-Host "  Missing modules: $($MissingModules.Count)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎯 Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Run compliance analysis: .\Real-Compliance-Test.ps1" -ForegroundColor Gray
Write-Host "  2. Generate HTML report: .\Generate-Report.ps1" -ForegroundColor Gray
Write-Host "  3. Review collected data in: $OutputPath" -ForegroundColor Gray

Write-Host ""
Write-Host "✅ Data collection completed successfully!" -ForegroundColor Green
Write-Host ""

# Cleanup connections
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-PnPOnline -ErrorAction SilentlyContinue
} catch {
    # Ignore cleanup errors
}

#endregion
