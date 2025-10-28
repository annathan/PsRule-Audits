# Synopsis: Essential 8 - Mitigation Strategy 7: Multi-Factor Authentication
# Description: Rules to verify MFA is properly configured across Azure AD/Entra ID
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/multi-factor-authentication

# ---------- Azure AD MFA Rules ----------

Rule 'Essential8.E8-7.AzureAD.MFA.AllUsersEnabled' -If { $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' } {
    # Recommendation for compliance
    Recommend 'Multi-factor authentication should be enabled for all users'
    
    # Reasoning behind the rule
    Reason 'Essential 8 requires MFA for all users to protect against credential theft'
    
    # Check if StrongAuthenticationRequirements is present and not null, and if any state is 'Enforced' or 'Enabled'
    $mfaEnabled = $TargetObject.StrongAuthenticationRequirements | Where-Object { $_.State -eq 'Enforced' -or $_.State -eq 'Enabled' }
    $Assert.Create(($mfaEnabled.Count -gt 0), 'MFA must be enabled or enforced for all users')
}

Rule 'Essential8.E8-7.AzureAD.MFA.PrivilegedEnforced' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' -and
    $TargetObject.PSObject.Properties.Name -contains 'AssignedRoles'
} {
    Recommend 'Privileged accounts must have MFA enforced, not just enabled'
    Reason 'Essential 8 requires stronger MFA controls for privileged accounts'
    
    # Check if user has privileged roles
    $isPrivileged = $False
    $privilegedRoles = @(
        "Global Administrator", "Privileged Role Administrator", "Exchange Administrator",
        "SharePoint Administrator", "Security Administrator", "User Administrator",
        "Authentication Administrator", "Conditional Access Administrator", "Cloud Application Administrator"
    )
    
    if ($TargetObject.AssignedRoles) {
        foreach ($role in $TargetObject.AssignedRoles) {
            if ($privilegedRoles -contains $role.DisplayName) {
                $isPrivileged = $True
                break
            }
        }
    }
    
    if ($isPrivileged) {
        # Assert that StrongAuthenticationRequirements is present and at least one state is 'Enforced'
        $mfaEnforced = $TargetObject.StrongAuthenticationRequirements | Where-Object { $_.State -eq 'Enforced' }
        $Assert.Create(($mfaEnforced.Count -gt 0), 'Privileged accounts must have MFA enforced')
    } else {
        # If not privileged, this rule is not applicable
        $Assert.Pass()
    }
}

Rule 'Essential8.E8-7.AzureAD.MFA.PhishingResistant' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' -and
    $TargetObject.PSObject.Properties.Name -contains 'StrongAuthenticationMethods'
} {
    Recommend 'Users should use phishing-resistant MFA methods (Authenticator app, FIDO2, Windows Hello)'
    Reason 'Essential 8 ML2+ requires phishing-resistant MFA methods over SMS'
    
    if ($TargetObject.StrongAuthenticationMethods -and $TargetObject.StrongAuthenticationMethods.Count -gt 0) {
        $hasAppMethod = $False
        foreach ($method in $TargetObject.StrongAuthenticationMethods) {
            if ($method.MethodType -eq 'AuthenticatorApp' -or $method.MethodType -eq 'Fido2' -or $method.MethodType -eq 'WindowsHelloForBusiness') {
                $hasAppMethod = $True
                break
            }
        }
        $Assert.Create($hasAppMethod, 'Users should use phishing-resistant MFA methods')
    } else {
        # If no strong authentication methods are configured, it fails
        $Assert.Fail('No strong authentication methods configured')
    }
}

Rule 'Essential8.E8-7.AzureAD.ConditionalAccess.MFA' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'GrantControls' -and 
    $TargetObject.PSObject.Properties.Name -contains 'Conditions' 
} {
    Recommend 'Conditional Access policies should enforce MFA for all users'
    Reason 'Essential 8 requires MFA enforcement through Conditional Access policies'
    
    $Assert.Create(($TargetObject.State -eq 'enabled'), 'CA policy should be enabled')
    $Assert.Create(($TargetObject.GrantControls.BuiltInControls -contains 'mfa'), 'CA must require MFA')
    $Assert.Create(($TargetObject.Conditions.Users.IncludeUsers.Count -ge 1), 'Policy must target users or groups')
}

Rule 'Essential8.E8-7.AzureAD.BlockLegacyAuth' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and 
    $TargetObject.PSObject.Properties.Name -contains 'Conditions' 
} {
    Recommend 'Legacy authentication should be blocked to prevent MFA bypass'
    Reason 'Essential 8 requires blocking legacy authentication protocols that cannot support MFA'
    
    if ($TargetObject.DisplayName -match 'Block.*Legacy' -or $TargetObject.DisplayName -match 'Legacy.*Block') {
        $TargetObject.State | Should -Be 'enabled' -Because 'Block legacy auth policy should be enabled'
        $TargetObject.Conditions.ClientAppTypes | Should -Contain 'exchangeActiveSync'
        $TargetObject.Conditions.ClientAppTypes | Should -Contain 'other'
        $TargetObject.GrantControls.Operator | Should -Be 'OR'
        $TargetObject.GrantControls.BuiltInControls | Should -Contain 'block'
    }
}

Rule 'Essential8.E8-7.AzureAD.EmergencyAccess' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' 
} {
    Recommend 'Emergency access accounts should be properly configured and monitored'
    Reason 'Essential 8 requires emergency access accounts to be cloud-only and properly secured'
    
    if ($TargetObject.UserPrincipalName -match 'emergency|break.*glass|admin.*emergency') {
        if ($TargetObject.PSObject.Properties.Name -contains 'DirSyncEnabled') {
            $TargetObject.DirSyncEnabled | Should -BeFalse -Because 'Emergency accounts should be cloud-only'
        }
        if ($TargetObject.PSObject.Properties.Name -contains 'PasswordPolicies') {
            $TargetObject.PasswordPolicies | Should -Be 'DisablePasswordExpiration'
        }
        if ($TargetObject.PSObject.Properties.Name -contains 'AssignedRoles') {
            ($TargetObject.AssignedRoles.Count) | Should -BeGreaterOrEqual 1
        }
    }
}