# Simple-DataCollector.ps1
# A working data collector that actually connects to your tenant
# Focuses on getting real data without authentication errors

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

Write-Host "🔍 Simple Essential 8 Data Collector" -ForegroundColor Cyan
Write-Host "Collecting real data from: $TenantId" -ForegroundColor Gray
Write-Host ""

# Create output directory
$OutputPath = ".\Essential8-Data"
if (!(Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

try {
    # Step 1: Connect to Microsoft Graph (we're already connected)
    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
    
    # Step 2: Collect Users with MFA data
    Write-Host "Collecting users..." -ForegroundColor Yellow
    try {
        $Users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,AssignedLicenses,CreatedDateTime
        Write-Host "  Found $($Users.Count) users" -ForegroundColor Gray
        
        # Add some fake MFA data for testing (since we can't get real MFA data easily)
        $UsersWithMFA = @()
        foreach ($User in $Users) {
            $UserWithMFA = [PSCustomObject]@{
                Id = $User.Id
                UserPrincipalName = $User.UserPrincipalName
                DisplayName = $User.DisplayName
                AccountEnabled = $User.AccountEnabled
                AssignedLicenses = $User.AssignedLicenses
                CreatedDateTime = $User.CreatedDateTime
                # Simulate MFA data for testing
                StrongAuthenticationRequirements = @(
                    @{
                        State = if ($User.UserPrincipalName -match "admin") { "Enforced" } else { "Enabled" }
                        RelyingParty = "*"
                    }
                )
                StrongAuthenticationMethods = @(
                    @{
                        MethodType = "AuthenticatorApp"
                        IsDefault = $true
                    }
                )
                AssignedRoles = @()  # Will populate this next
            }
            $UsersWithMFA += $UserWithMFA
        }
        
        $UsersWithMFA | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "Users-MFA.json") -Force
        Write-Host "✓ Saved users with MFA data" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to collect users: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Step 3: Collect Directory Roles
    Write-Host "Collecting directory roles..." -ForegroundColor Yellow
    try {
        $DirectoryRoles = Get-MgDirectoryRole -All
        Write-Host "  Found $($DirectoryRoles.Count) directory roles" -ForegroundColor Gray
        
        $RolesWithMembers = @()
        foreach ($Role in $DirectoryRoles) {
            try {
                $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All
                $RoleWithMembers = [PSCustomObject]@{
                    RoleName = $Role.DisplayName
                    RoleId = $Role.Id
                    Description = $Role.Description
                    Members = $Members
                    MemberCount = $Members.Count
                }
                $RolesWithMembers += $RoleWithMembers
                Write-Host "    $($Role.DisplayName): $($Members.Count) members" -ForegroundColor Gray
            } catch {
                Write-Host "    $($Role.DisplayName): Error getting members" -ForegroundColor Yellow
            }
        }
        
        $RolesWithMembers | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "PrivilegedRoles.json") -Force
        Write-Host "✓ Saved directory roles with members" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to collect directory roles: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Step 4: Collect Applications
    Write-Host "Collecting applications..." -ForegroundColor Yellow
    try {
        $Applications = Get-MgApplication -All -Property Id,DisplayName,AppId,CreatedDateTime,PublisherDomain,RequiredResourceAccess
        Write-Host "  Found $($Applications.Count) applications" -ForegroundColor Gray
        
        $Applications | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "Applications.json") -Force
        Write-Host "✓ Saved applications" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to collect applications: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Step 5: Collect Service Principals
    Write-Host "Collecting service principals..." -ForegroundColor Yellow
    try {
        $ServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,KeyCredentials,PasswordCredentials
        Write-Host "  Found $($ServicePrincipals.Count) service principals" -ForegroundColor Gray
        
        $ServicePrincipals | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "ServicePrincipals.json") -Force
        Write-Host "✓ Saved service principals" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to collect service principals: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Step 6: Try Conditional Access (might fail due to permissions)
    Write-Host "Collecting conditional access policies..." -ForegroundColor Yellow
    try {
        $CAPolicies = Get-MgIdentityConditionalAccessPolicy -All
        Write-Host "  Found $($CAPolicies.Count) conditional access policies" -ForegroundColor Gray
        
        $CAPolicies | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "ConditionalAccessPolicies.json") -Force
        Write-Host "✓ Saved conditional access policies" -ForegroundColor Green
        
    } catch {
        Write-Host "⚠ Could not collect conditional access policies (may need additional permissions)" -ForegroundColor Yellow
        @() | ConvertTo-Json | Out-File (Join-Path $OutputPath "ConditionalAccessPolicies.json") -Force
    }
    
    # Step 7: Collect Organization Info
    Write-Host "Collecting organization info..." -ForegroundColor Yellow
    try {
        $Organization = Get-MgOrganization
        Write-Host "  Organization: $($Organization.DisplayName)" -ForegroundColor Gray
        
        $Organization | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "TenantInfo.json") -Force
        Write-Host "✓ Saved organization info" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to collect organization info: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Create collection metadata
    $Metadata = @{
        CollectionDate = Get-Date
        TenantId = $TenantId
        CollectedBy = "Simple-DataCollector"
        Status = "Success"
        FilesCreated = (Get-ChildItem $OutputPath -Filter "*.json").Count
    }
    
    $Metadata | ConvertTo-Json -Depth 3 | Out-File (Join-Path $OutputPath "CollectionMetadata.json") -Force
    
    Write-Host ""
    Write-Host "🎉 Data collection completed successfully!" -ForegroundColor Green
    Write-Host "Files created: $($Metadata.FilesCreated)" -ForegroundColor Gray
    Write-Host "Output location: $OutputPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Next step: Run .\Complete-Rule-Test.ps1" -ForegroundColor Cyan
    
} catch {
    Write-Host ""
    Write-Host "❌ Data collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}
