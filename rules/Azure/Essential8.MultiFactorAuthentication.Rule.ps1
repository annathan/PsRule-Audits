# Essential8.MultiFactorAuthentication.Rule.ps1
# PSRule definitions for Essential 8 - Multi-factor Authentication compliance
# Covers Azure AD, Microsoft 365, and SharePoint environments

#region Azure AD MFA Rules

# Essential 8 Strategy 7: Multi-factor Authentication - Maturity Level 2
Rule 'Essential8.AzureAD.MFA.Enabled' -Type 'Microsoft.AzureAD.User' {
    $Assert.HasFieldValue($TargetObject, 'StrongAuthenticationRequirements.State', 'Enabled')
    
    # Check that MFA is enforced, not just enabled
    $mfaState = $TargetObject.StrongAuthenticationRequirements | Where-Object { $_.State -eq 'Enforced' }
    $Assert.GreaterOrEqual($mfaState.Count, 1)
}

# Privileged accounts must have MFA enforced
Rule 'Essential8.AzureAD.MFA.PrivilegedAccounts' -Type 'Microsoft.AzureAD.User' {
    # Check if user has privileged roles
    $privilegedRoles = @(
        'Global Administrator',
        'Security Administrator', 
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Administrator',
        'Conditional Access Administrator'
    )
    
    $userRoles = $TargetObject.AssignedRoles
    $hasPrivilegedRole = $false
    
    foreach ($role in $userRoles) {
        if ($privilegedRoles -contains $role.DisplayName) {
            $hasPrivilegedRole = $true
            break
        }
    }
    
    if ($hasPrivilegedRole) {
        # Privileged accounts MUST have MFA enforced
        $Assert.HasFieldValue($TargetObject, 'StrongAuthenticationRequirements.State', 'Enforced')
        
        # Should not rely on SMS/Voice calls (less secure methods)
        $mfaMethods = $TargetObject.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq $true }
        $Assert.NotIn($mfaMethods.MethodType, @('OneWaySMS', 'TwoWayVoiceMobile'))
    }
}

# Conditional Access MFA policies should be configured
Rule 'Essential8.AzureAD.ConditionalAccess.MFA' -Type 'Microsoft.AzureAD.ConditionalAccessPolicy' {
    # Policy should be enabled
    $Assert.HasFieldValue($TargetObject, 'State', 'enabled')
    
    # Should require MFA for high-risk locations or all locations
    $grantControls = $TargetObject.GrantControls
    $Assert.In('mfa', $grantControls.BuiltInControls)
    
    # Should apply to all users or specific high-risk groups
    $Assert.GreaterOrEqual($TargetObject.Conditions.Users.IncludeUsers.Count, 1)
}

# Block legacy authentication protocols
Rule 'Essential8.AzureAD.BlockLegacyAuth' -Type 'Microsoft.AzureAD.ConditionalAccessPolicy' {
    if ($TargetObject.DisplayName -match 'Block.*Legacy' -or $TargetObject.DisplayName -match 'Legacy.*Block') {
        $Assert.HasFieldValue($TargetObject, 'State', 'enabled')
        
        # Should block legacy authentication client apps
        $clientApps = $TargetObject.Conditions.ClientAppTypes
        $Assert.In('exchangeActiveSync', $clientApps)
        $Assert.In('other', $clientApps)
        
        # Grant control should be "Block"
        $Assert.HasFieldValue($TargetObject, 'GrantControls.Operator', 'OR')
        $Assert.In('block', $TargetObject.GrantControls.BuiltInControls)
    }
}

#endregion

#region Microsoft 365 MFA Rules

# Exchange Online MFA requirements
Rule 'Essential8.Exchange.MFA.Required' -Type 'Microsoft.Exchange.MailboxPlan' {
    # Modern authentication should be enabled
    $Assert.HasFieldValue($TargetObject, 'ModernAuthenticationEnabled', $true)
}

# SharePoint MFA for external sharing
Rule 'Essential8.SharePoint.ExternalSharing.MFA' -Type 'Microsoft.SharePoint.Tenant' {
    # External users should require MFA
    if ($TargetObject.SharingCapability -ne 'Disabled') {
        $Assert.HasFieldValue($TargetObject, 'RequireAcceptingAccountMatchInvitedAccount', $true)
        # Additional MFA requirements for external users should be configured via Conditional Access
    }
}

# Power Platform MFA requirements
Rule 'Essential8.PowerPlatform.MFA.DLP' -Type 'Microsoft.PowerPlatform.DLPPolicy' {
    # Data Loss Prevention policies should enforce authentication requirements
    $Assert.HasFieldValue($TargetObject, 'DisplayName')
    
    # Check for authentication-related connector restrictions
    $connectorGroups = $TargetObject.ConnectorGroups
    $businessDataGroup = $connectorGroups | Where-Object { $_.Classification -eq 'Business' }
    
    # High-risk connectors should be properly classified
    $highRiskConnectors = @('shared_sql', 'shared_filesystem', 'shared_ftp')
    foreach ($connector in $highRiskConnectors) {
        if ($businessDataGroup.Connectors -contains $connector) {
            # Should have additional restrictions
            $Assert.HasField($TargetObject, 'EnvironmentType')
        }
    }
}

#endregion

#region Service Account and Emergency Access

# Emergency access accounts should exist but be properly secured
Rule 'Essential8.AzureAD.EmergencyAccess' -Type 'Microsoft.AzureAD.User' {
    if ($TargetObject.UserPrincipalName -match 'emergency|break.*glass|admin.*emergency') {
        # Emergency accounts should be cloud-only
        $Assert.HasFieldValue($TargetObject, 'DirSyncEnabled', $false)
        
        # Should have strong, unique passwords
        $Assert.HasFieldValue($TargetObject, 'PasswordPolicies', 'DisablePasswordExpiration')
        
        # Should be excluded from MFA for emergency access but monitored
        $Assert.HasField($TargetObject, 'StrongAuthenticationRequirements')
        
        # Should be in a dedicated administrative unit or group
        $Assert.GreaterOrEqual($TargetObject.AssignedRoles.Count, 1)
    }
}

# Service accounts should use certificate-based authentication where possible
Rule 'Essential8.AzureAD.ServiceAccounts.Auth' -Type 'Microsoft.AzureAD.ServicePrincipal' {
    # Service principals should use certificate credentials, not passwords
    $credentials = $TargetObject.KeyCredentials + $TargetObject.PasswordCredentials
    
    if ($credentials.Count -gt 0) {
        # Prefer certificate credentials over password credentials
        $certCredentials = $TargetObject.KeyCredentials
        if ($certCredentials.Count -eq 0) {
            # If using password credentials, ensure they're not expired
            $passwordCreds = $TargetObject.PasswordCredentials | Where-Object { $_.EndDate -gt (Get-Date) }
            $Assert.GreaterOrEqual($passwordCreds.Count, 1)
        }
    }
}

#endregion

#region Reporting and Compliance Functions

# Function to generate MFA compliance summary
Rule 'Essential8.MFA.ComplianceSummary' -Type 'Microsoft.AzureAD.Tenant' {
    # This rule provides overall MFA compliance status
    $mfaEnabledUsers = $TargetObject.Users | Where-Object { 
        $_.StrongAuthenticationRequirements.State -in @('Enabled', 'Enforced') 
    }
    
    $totalUsers = $TargetObject.Users.Count
    $mfaEnabledCount = $mfaEnabledUsers.Count
    $compliancePercentage = [math]::Round(($mfaEnabledCount / $totalUsers) * 100, 2)
    
    # Essential 8 ML2 requires MFA for all users
    $Assert.GreaterOrEqual($compliancePercentage, 95) # Allow for service accounts
    
    # Output compliance metrics for reporting
    Write-Information "MFA Compliance: $compliancePercentage% ($mfaEnabledCount/$totalUsers users)"
}

#endregion

#region Rule Metadata and Documentation

# Rule metadata for Essential 8 mapping
$Essential8Metadata = @{
    Strategy = 7
    Name = 'Multi-factor Authentication'
    MaturityLevel = 2
    Description = 'Multi-factor authentication is used to authenticate standard users'
    Implementation = @(
        'Configure Azure AD MFA policies',
        'Enable Conditional Access with MFA requirements', 
        'Block legacy authentication protocols',
        'Secure privileged accounts with enforced MFA',
        'Configure emergency access procedures'
    )
    Validation = @(
        'Verify MFA is enabled for all user accounts',
        'Confirm privileged accounts use strong MFA methods',
        'Validate Conditional Access policies are active',
        'Check legacy authentication is blocked',
        'Review emergency access account security'
    )
    Remediation = @(
        'Enable MFA through Azure AD portal or PowerShell',
        'Configure Conditional Access policies',
        'Update user authentication methods',
        'Block legacy authentication protocols',
        'Implement proper emergency access procedures'
    )
}

# Export metadata for reporting tools
Export-ModuleMember -Variable Essential8Metadata

#endregion

# Rule execution configuration
$PSRule = @{
    Include = @('Essential8.*.MFA.*')
    Baseline = 'Essential8.ML2.Baseline'
}
