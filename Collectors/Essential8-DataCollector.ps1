# Essential8-DataCollector.ps1
# Collects configuration data from Azure AD, Microsoft 365, and SharePoint for Essential 8 compliance auditing

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

#region Prerequisites and Initialization

# Required modules for data collection
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users', 
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Applications',
    'ExchangeOnlineManagement',
    'PnP.PowerShell'
)

Write-Host "Checking required modules..." -ForegroundColor Yellow
foreach ($Module in $RequiredModules) {
    if (!(Get-Module -ListAvailable -Name $Module)) {
        Write-Warning "Module $Module not found. Installing..."
        Install-Module -Name $Module -Force -AllowClobber
    }
    Import-Module $Module -Force
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

#endregion

#region Authentication

function Connect-Essential8Services {
    param(
        [string]$TenantId,
        [bool]$UseAppAuth = $false,
        [string]$AppId,
        [string]$AppSecret
    )
    
    try {
        if ($UseAppAuth -and $AppId -and $AppSecret) {
            # Application authentication
            $SecureSecret = ConvertTo-SecureString $AppSecret -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential($AppId, $SecureSecret)
            
            # Connect to Microsoft Graph
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential
            
            # Connect to Exchange Online
            Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $AppSecret -Organization "$TenantId.onmicrosoft.com"
            
        } else {
            # Interactive authentication
            $Scopes = @(
                'User.Read.All',
                'Directory.Read.All', 
                'Policy.Read.All',
                'RoleManagement.Read.Directory',
                'IdentityRiskyUser.Read.All',
                'IdentityRiskEvent.Read.All',
                'Application.Read.All'
            )
            
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes
            Connect-ExchangeOnline
        }
        
        Write-Host "Successfully connected to Microsoft services" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to connect to Microsoft services: $($_.Exception.Message)"
        return $false
    }
    return $true
}

#endregion

#region Azure AD Data Collection

function Get-Essential8AzureADData {
    param([string]$OutputPath)
    
    Write-Host "Collecting Azure AD data for Essential 8 compliance..." -ForegroundColor Cyan
    
    $AzureADPath = Join-Path $OutputPath "AzureAD"
    if (!(Test-Path $AzureADPath)) { New-Item -Path $AzureADPath -ItemType Directory -Force | Out-Null }
    
    try {
        # 1. User accounts and MFA status
        Write-Host "  - Collecting user MFA configuration..." -ForegroundColor Gray
        $Users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,AssignedLicenses,StrongAuthenticationRequirements
        $Users | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "Users-MFA.json")
        
        # 2. Privileged role assignments
        Write-Host "  - Collecting privileged role assignments..." -ForegroundColor Gray
        $DirectoryRoles = Get-MgDirectoryRole -All
        $PrivilegedRoles = @()
        foreach ($Role in $DirectoryRoles) {
            $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id
            $PrivilegedRoles += [PSCustomObject]@{
                RoleName = $Role.DisplayName
                RoleId = $Role.Id
                Members = $Members
            }
        }
        $PrivilegedRoles | ConvertTo-Json -Depth 4 | Out-File (Join-Path $AzureADPath "PrivilegedRoles.json")
        
        # 3. Conditional Access policies
        Write-Host "  - Collecting Conditional Access policies..." -ForegroundColor Gray
        try {
            $ConditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -All
            $ConditionalAccessPolicies | ConvertTo-Json -Depth 5 | Out-File (Join-Path $AzureADPath "ConditionalAccessPolicies.json")
        } catch {
            Write-Warning "Could not collect Conditional Access policies: $($_.Exception.Message)"
            # Create empty file to prevent errors
            @() | ConvertTo-Json | Out-File (Join-Path $AzureADPath "ConditionalAccessPolicies.json")
        }
        
        # 4. Service Principals and Applications
        Write-Host "  - Collecting service principals..." -ForegroundColor Gray
        $ServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,KeyCredentials,PasswordCredentials,ServicePrincipalType
        $ServicePrincipals | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "ServicePrincipals.json")
        
        # 5. Applications
        Write-Host "  - Collecting applications..." -ForegroundColor Gray
        $Applications = Get-MgApplication -All -Property Id,DisplayName,AppId,KeyCredentials,PasswordCredentials,RequiredResourceAccess
        $Applications | ConvertTo-Json -Depth 4 | Out-File (Join-Path $AzureADPath "Applications.json")
        
        # 6. Sign-in risk events and risky users
        Write-Host "  - Collecting identity protection data..." -ForegroundColor Gray
        try {
            $RiskyUsers = Get-MgIdentityProtectionRiskyUser -All
            $RiskyUsers | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "RiskyUsers.json")
        } catch {
            Write-Warning "Could not collect risky users data: $($_.Exception.Message)"
        }
        
        # 7. Tenant information
        Write-Host "  - Collecting tenant configuration..." -ForegroundColor Gray
        $Organization = Get-MgOrganization
        $Organization | ConvertTo-Json -Depth 3 | Out-File (Join-Path $AzureADPath "TenantInfo.json")
        
    } catch {
        Write-Error "Error collecting Azure AD data: $($_.Exception.Message)"
    }
}

#endregion

#region Exchange Online Data Collection

function Get-Essential8ExchangeData {
    param([string]$OutputPath)
    
    Write-Host "Collecting Exchange Online data for Essential 8 compliance..." -ForegroundColor Cyan
    
    $ExchangePath = Join-Path $OutputPath "Exchange"
    if (!(Test-Path $ExchangePath)) { New-Item -Path $ExchangePath -ItemType Directory -Force | Out-Null }
    
    try {
        # 1. Organization configuration
        Write-Host "  - Collecting organization configuration..." -ForegroundColor Gray
        $OrgConfig = Get-OrganizationConfig
        $OrgConfig | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "OrganizationConfig.json")
        
        # 2. Authentication policies
        Write-Host "  - Collecting authentication policies..." -ForegroundColor Gray
        $AuthPolicies = Get-AuthenticationPolicy
        $AuthPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "AuthenticationPolicies.json")
        
        # 3. Mobile device mailbox policies
        Write-Host "  - Collecting mobile device policies..." -ForegroundColor Gray
        $MobileDevicePolicies = Get-MobileDeviceMailboxPolicy
        $MobileDevicePolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "MobileDevicePolicies.json")
        
        # 4. Anti-spam and anti-malware policies
        Write-Host "  - Collecting anti-spam policies..." -ForegroundColor Gray
        $AntiSpamPolicies = Get-HostedContentFilterPolicy
        $AntiSpamPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "AntiSpamPolicies.json")
        
        $AntiMalwarePolicies = Get-MalwareFilterPolicy
        $AntiMalwarePolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "AntiMalwarePolicies.json")
        
        # 5. Transport rules (for macro blocking)
        Write-Host "  - Collecting transport rules..." -ForegroundColor Gray
        $TransportRules = Get-TransportRule
        $TransportRules | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "TransportRules.json")
        
        # 6. Safe attachments and safe links policies
        Write-Host "  - Collecting safe attachments policies..." -ForegroundColor Gray
        try {
            $SafeAttachmentPolicies = Get-SafeAttachmentPolicy
            $SafeAttachmentPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "SafeAttachmentPolicies.json")
            
            $SafeLinksPolicies = Get-SafeLinksPolicy
            $SafeLinksPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $ExchangePath "SafeLinksPolicies.json")
        } catch {
            Write-Warning "Could not collect Defender for Office 365 policies: $($_.Exception.Message)"
        }
        
    } catch {
        Write-Error "Error collecting Exchange data: $($_.Exception.Message)"
    }
}

#endregion

#region SharePoint Online Data Collection

function Get-Essential8SharePointData {
    param([string]$OutputPath)
    
    Write-Host "Collecting SharePoint Online data for Essential 8 compliance..." -ForegroundColor Cyan
    
    $SharePointPath = Join-Path $OutputPath "SharePoint"
    if (!(Test-Path $SharePointPath)) { New-Item -Path $SharePointPath -ItemType Directory -Force | Out-Null }
    
    try {
        # Connect to SharePoint Online
        $AdminUrl = "https://$($TenantId.Split('.')[0])-admin.sharepoint.com"
        Connect-PnPOnline -Url $AdminUrl -Interactive
        
        # 1. Tenant settings
        Write-Host "  - Collecting tenant configuration..." -ForegroundColor Gray
        $TenantSettings = Get-PnPTenant
        $TenantSettings | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SharePointPath "TenantSettings.json")
        
        # 2. Site collections and their settings
        Write-Host "  - Collecting site collections..." -ForegroundColor Gray
        $SiteCollections = Get-PnPTenantSite -Detailed
        $SiteCollections | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SharePointPath "SiteCollections.json")
        
        # 3. External sharing policies
        Write-Host "  - Collecting sharing policies..." -ForegroundColor Gray
        $SharingPolicies = @()
        foreach ($Site in $SiteCollections) {
            $SiteInfo = Get-PnPTenantSite -Url $Site.Url -Detailed
            $SharingPolicies += [PSCustomObject]@{
                Url = $Site.Url
                Title = $Site.Title
                SharingCapability = $SiteInfo.SharingCapability
                DefaultSharingLinkType = $SiteInfo.DefaultSharingLinkType
                DefaultLinkPermission = $SiteInfo.DefaultLinkPermission
                RequireAcceptingAccountMatchInvitedAccount = $SiteInfo.RequireAcceptingAccountMatchInvitedAccount
                SiteOwners = $SiteInfo.Owner
            }
        }
        $SharingPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SharePointPath "SharingPolicies.json")
        
        # 4. App catalog and custom apps
        Write-Host "  - Collecting app catalog information..." -ForegroundColor Gray
        try {
            $AppCatalog = Get-PnPTenantAppCatalogUrl
            if ($AppCatalog) {
                Connect-PnPOnline -Url $AppCatalog -Interactive
                $Apps = Get-PnPApp
                $Apps | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SharePointPath "AppCatalog.json")
            }
        } catch {
            Write-Warning "Could not collect app catalog data: $($_.Exception.Message)"
        }
        
        # 5. Information Rights Management settings
        Write-Host "  - Collecting IRM settings..." -ForegroundColor Gray
        $IRMSettings = @{
            TenantIRMEnabled = $TenantSettings.IRMEnabled
            TenantIRMUserSync = $TenantSettings.IRMUserSync
        }
        $IRMSettings | ConvertTo-Json | Out-File (Join-Path $SharePointPath "IRMSettings.json")
        
        # 6. DLP policies (if available)
        Write-Host "  - Collecting DLP policies..." -ForegroundColor Gray
        try {
            # Note: This requires Security & Compliance Center connection
            # $DLPPolicies = Get-DlpCompliancePolicy
            # $DLPPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SharePointPath "DLPPolicies.json")
        } catch {
            Write-Warning "DLP policies require Security & Compliance Center access"
        }
        
    } catch {
        Write-Error "Error collecting SharePoint data: $($_.Exception.Message)"
    }
}

#endregion

#region Security & Compliance Data Collection

function Get-Essential8SecurityData {
    param([string]$OutputPath)
    
    Write-Host "Collecting Security & Compliance data for Essential 8..." -ForegroundColor Cyan
    
    $SecurityPath = Join-Path $OutputPath "Security"
    if (!(Test-Path $SecurityPath)) { New-Item -Path $SecurityPath -ItemType Directory -Force | Out-Null }
    
    try {
        # 1. Microsoft Defender for Office 365 policies
        Write-Host "  - Collecting Defender policies..." -ForegroundColor Gray
        
        # ATP Anti-phishing policies
        try {
            $AntiPhishingPolicies = Get-AntiPhishPolicy
            $AntiPhishingPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SecurityPath "AntiPhishingPolicies.json")
        } catch {
            Write-Warning "Could not collect anti-phishing policies"
        }
        
        # 2. Audit log configuration
        Write-Host "  - Collecting audit configuration..." -ForegroundColor Gray
        try {
            $AuditConfig = Get-AdminAuditLogConfig
            $AuditConfig | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SecurityPath "AuditConfig.json")
        } catch {
            Write-Warning "Could not collect audit configuration"
        }
        
        # 3. Retention policies
        Write-Host "  - Collecting retention policies..." -ForegroundColor Gray
        try {
            $RetentionPolicies = Get-RetentionCompliancePolicy
            $RetentionPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SecurityPath "RetentionPolicies.json")
        } catch {
            Write-Warning "Could not collect retention policies"
        }
        
        # 4. Information barriers
        Write-Host "  - Collecting information barriers..." -ForegroundColor Gray
        try {
            $InformationBarriers = Get-InformationBarrierPolicy
            $InformationBarriers | ConvertTo-Json -Depth 3 | Out-File (Join-Path $SecurityPath "InformationBarriers.json")
        } catch {
            Write-Warning "Could not collect information barriers"
        }
        
    } catch {
        Write-Error "Error collecting Security data: $($_.Exception.Message)"
    }
}

#endregion

#region Power Platform Data Collection

function Get-Essential8PowerPlatformData {
    param([string]$OutputPath)
    
    Write-Host "Collecting Power Platform data for Essential 8..." -ForegroundColor Cyan
    
    $PowerPlatformPath = Join-Path $OutputPath "PowerPlatform"
    if (!(Test-Path $PowerPlatformPath)) { New-Item -Path $PowerPlatformPath -ItemType Directory -Force | Out-Null }
    
    try {
        # Note: Power Platform cmdlets require separate module and authentication
        # This is a placeholder for Power Platform specific data collection
        
        # 1. DLP Policies for Power Platform
        Write-Host "  - Collecting Power Platform DLP policies..." -ForegroundColor Gray
        try {
            # Requires PowerApps administration module
            # $DLPPolicies = Get-AdminDlpPolicy
            # $DLPPolicies | ConvertTo-Json -Depth 3 | Out-File (Join-Path $PowerPlatformPath "DLPPolicies.json")
            
            Write-Warning "Power Platform data collection requires additional modules and authentication"
        } catch {
            Write-Warning "Could not collect Power Platform DLP policies"
        }
        
        # 2. Power BI tenant settings
        Write-Host "  - Power BI tenant settings collection not implemented..." -ForegroundColor Gray
        
        # 3. Power Automate governance
        Write-Host "  - Power Automate governance collection not implemented..." -ForegroundColor Gray
        
    } catch {
        Write-Error "Error collecting Power Platform data: $($_.Exception.Message)"
    }
}

#endregion

#region Main Collection Function

function Start-Essential8DataCollection {
    param(
        [string[]]$Services,
        [string]$OutputPath,
        [string]$TenantId
    )
    
    $StartTime = Get-Date
    Write-Host "Starting Essential 8 data collection at $StartTime" -ForegroundColor Green
    
    # Create main output structure
    $DataStructure = @{
        CollectionDate = $StartTime
        TenantId = $TenantId
        CollectedServices = $Services
        Version = "1.0"
    }
    
    if ($Services -contains 'All' -or $Services -contains 'AzureAD') {
        Get-Essential8AzureADData -OutputPath $OutputPath
    }
    
    if ($Services -contains 'All' -or $Services -contains 'Exchange') {
        Get-Essential8ExchangeData -OutputPath $OutputPath
    }
    
    if ($Services -contains 'All' -or $Services -contains 'SharePoint') {
        Get-Essential8SharePointData -OutputPath $OutputPath
    }
    
    if ($Services -contains 'All' -or $Services -contains 'Security') {
        Get-Essential8SecurityData -OutputPath $OutputPath
    }
    
    # Always collect Power Platform if 'All' is selected
    if ($Services -contains 'All') {
        Get-Essential8PowerPlatformData -OutputPath $OutputPath
    }
    
    # Save collection metadata
    $DataStructure.CollectionCompleted = Get-Date
    $DataStructure.Duration = (Get-Date) - $StartTime
    $DataStructure | ConvertTo-Json -Depth 2 | Out-File (Join-Path $OutputPath "CollectionMetadata.json")
    
    Write-Host "Data collection completed in $($DataStructure.Duration.TotalMinutes) minutes" -ForegroundColor Green
    Write-Host "Data saved to: $OutputPath" -ForegroundColor Yellow
}

#endregion

#region Main Execution

try {
    # Connect to services
    $Connected = Connect-Essential8Services -TenantId $TenantId -UseAppAuth $UseApplicationAuth -AppId $ApplicationId -AppSecret $ApplicationSecret
    
    if ($Connected) {
        # Start data collection
        Start-Essential8DataCollection -Services $Services -OutputPath $OutputPath -TenantId $TenantId
        
        # Generate collection summary
        Write-Host "`n=== Essential 8 Data Collection Summary ===" -ForegroundColor Cyan
        Write-Host "Tenant ID: $TenantId" -ForegroundColor White
        Write-Host "Output Path: $OutputPath" -ForegroundColor White
        Write-Host "Services Collected: $($Services -join ', ')" -ForegroundColor White
        
        $TotalFiles = (Get-ChildItem -Path $OutputPath -Recurse -File).Count
        Write-Host "Total Files Generated: $TotalFiles" -ForegroundColor White
        
        Write-Host "`nNext Steps:" -ForegroundColor Yellow
        Write-Host "1. Review collected data in $OutputPath" -ForegroundColor Gray
        Write-Host "2. Run PSRule analysis: Invoke-PSRule -InputPath '$OutputPath' -Module 'Essential8.Rules'" -ForegroundColor Gray
        Write-Host "3. Generate compliance report" -ForegroundColor Gray
        
    } else {
        Write-Error "Failed to connect to Microsoft services. Collection aborted."
        exit 1
    }
    
} catch {
    Write-Error "Collection failed with error: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.Exception.StackTrace)"
    exit 1
    
} finally {
    # Cleanup connections
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
    } catch {
        # Ignore cleanup errors
    }
}

#endregion

#region Usage Examples and Documentation

<#
.SYNOPSIS
    Collects configuration data from Microsoft cloud services for Essential 8 compliance auditing.

.DESCRIPTION
    This script connects to Azure AD, Exchange Online, SharePoint Online, and Security & Compliance
    centers to collect configuration data needed for Essential 8 compliance assessment using PSRule.

.PARAMETER TenantId
    The Azure AD tenant ID or domain name (e.g., contoso.onmicrosoft.com)

.PARAMETER OutputPath
    Path where collected data will be saved. Defaults to .\Essential8-Data

.PARAMETER Services
    Services to collect data from. Options: All, AzureAD, Exchange, SharePoint, Security

.PARAMETER UseApplicationAuth
    Use application-based authentication instead of interactive login

.PARAMETER ApplicationId
    Application ID for service principal authentication

.PARAMETER ApplicationSecret
    Application secret or certificate thumbprint for service principal authentication

.EXAMPLE
    .\Essential8-DataCollector.ps1 -TenantId "contoso.onmicrosoft.com"
    
    Collects data from all services using interactive authentication

.EXAMPLE
    .\Essential8-DataCollector.ps1 -TenantId "contoso.onmicrosoft.com" -Services AzureAD,Exchange
    
    Collects only Azure AD and Exchange data

.EXAMPLE
    .\Essential8-DataCollector.ps1 -TenantId "contoso.onmicrosoft.com" -UseApplicationAuth -ApplicationId "12345678-1234-1234-1234-123456789012" -ApplicationSecret "your-secret"
    
    Uses service principal authentication for unattended collection

.NOTES
    Requires the following PowerShell modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Users
    - Microsoft.Graph.Identity.SignIns
    - Microsoft.Graph.Identity.ConditionalAccess
    - Microsoft.Graph.Applications
    - ExchangeOnlineManagement
    - PnP.PowerShell
    - Microsoft.Graph.Security
    
    Ensure you have appropriate permissions in the target tenant:
    - Global Reader or Security Reader for Azure AD
    - Exchange Online Administrator for Exchange data
    - SharePoint Online Administrator for SharePoint data
    - Security Administrator for Security & Compliance data
#>

#endregion
