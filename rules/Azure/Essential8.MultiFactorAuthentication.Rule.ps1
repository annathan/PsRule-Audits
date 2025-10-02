# Synopsis: Essential 8 - Mitigation Strategy 7: Multi-Factor Authentication
# Description: Rules to verify MFA is properly configured across Azure AD/Entra ID
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/multi-factor-authentication

# ---------------------------------------------------------------------------------------------------
# Rule: All users should have MFA enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-7.AzureAD.MFA.AllUsersEnabled' -If { $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' } {
    # Recommendation for compliance
    Recommend 'Multi-factor authentication should be enabled for all users'
    
    # Reasoning behind the rule
    Reason 'Essential 8 requires MFA for all users to protect against credential theft'
    
    # Check if MFA is configured
    $hasMFAEnabled = $False
    
    # Check for MFA through various methods
    if ($TargetObject.PSObject.Properties.Name -contains 'StrongAuthenticationRequirements') {
        if ($TargetObject.StrongAuthenticationRequirements -and $TargetObject.StrongAuthenticationRequirements.Count -gt 0) {
            $hasMFAEnabled = $True
        }
    }
    
    # Check for MFA methods configured
    if ($TargetObject.PSObject.Properties.Name -contains 'StrongAuthenticationMethods') {
        if ($TargetObject.StrongAuthenticationMethods -and $TargetObject.StrongAuthenticationMethods.Count -gt 0) {
            $hasMFAEnabled = $True
        }
    }
    
    # Check for authentication methods (new property)
    if ($TargetObject.PSObject.Properties.Name -contains 'AuthenticationMethods') {
        if ($TargetObject.AuthenticationMethods -and $TargetObject.AuthenticationMethods.Count -gt 0) {
            $hasMFAEnabled = $True
        }
    }
    
    # Assert MFA is enabled
    $Assert.Create($hasMFAEnabled, "User '$($TargetObject.UserPrincipalName)' does not have MFA enabled")
    
} -Tag @{ 
    E8 = 'E8-7'
    Category = 'Multi-Factor Authentication' 
    Severity = 'Critical'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Privileged users must have MFA enforced (not just enabled)
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-7.AzureAD.MFA.PrivilegedEnforced' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' -and
    $TargetObject.PSObject.Properties.Name -contains 'AssignedRoles'
} {
    Recommend 'Privileged accounts must have MFA enforced, not just enabled'
    Reason 'Essential 8 requires stronger MFA controls for privileged accounts'
    
    # Check if user has privileged roles
    $isPrivileged = $False
    $privilegedRoles = @(
        'Global Administrator',
        'Privileged Role Administrator', 
        'Security Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Administrator',
        'Helpdesk Administrator',
        'Authentication Administrator',
        'Cloud Application Administrator',
        'Application Administrator'
    )
    
    if ($TargetObject.AssignedRoles) {
        foreach ($role in $TargetObject.AssignedRoles) {
            if ($privilegedRoles -contains $role.DisplayName) {
                $isPrivileged = $True
                break
            }
        }
    }
    
    # If privileged, check MFA is enforced
    if ($isPrivileged) {
        $mfaEnforced = $False
        
        if ($TargetObject.StrongAuthenticationRequirements) {
            foreach ($req in $TargetObject.StrongAuthenticationRequirements) {
                if ($req.State -eq 'Enforced') {
                    $mfaEnforced = $True
                    break
                }
            }
        }
        
        $Assert.Create($mfaEnforced, "Privileged user '$($TargetObject.UserPrincipalName)' does not have MFA enforced")
    } else {
        # Not a privileged user, pass this rule
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-7'
    Category = 'Multi-Factor Authentication'
    Severity = 'Critical'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: SMS should not be the only MFA method (prefer app-based)
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-7.AzureAD.MFA.PhishingResistant' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' -and
    $TargetObject.PSObject.Properties.Name -contains 'StrongAuthenticationMethods'
} {
    Recommend 'Users should use phishing-resistant MFA methods (Authenticator app, FIDO2, Windows Hello)'
    Reason 'Essential 8 ML2+ requires phishing-resistant MFA methods over SMS'
    
    if ($TargetObject.StrongAuthenticationMethods -and $TargetObject.StrongAuthenticationMethods.Count -gt 0) {
        $hasAppMethod = $False
        $onlySMS = $True
        
        foreach ($method in $TargetObject.StrongAuthenticationMethods) {
            if ($method.MethodType -in @('PhoneAppNotification', 'PhoneAppOTP', 'AuthenticatorApp', 'FIDO2', 'WindowsHello')) {
                $hasAppMethod = $True
                $onlySMS = $False
            }
        }
        
        # Warn if only SMS is configured
        if (!$hasAppMethod -and $onlySMS) {
            $Assert.Create($False, "User '$($TargetObject.UserPrincipalName)' relies on SMS/phone call for MFA - should use app-based authentication")
        } else {
            $Assert.Pass()
        }
    } else {
        # No MFA methods - fail
        $Assert.Create($False, "User '$($TargetObject.UserPrincipalName)' has no MFA methods configured")
    }
    
} -Tag @{ 
    E8 = 'E8-7'
    Category = 'Multi-Factor Authentication'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Conditional Access policies should enforce MFA
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-7.AzureAD.ConditionalAccess.MFARequired' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and
    $TargetObject.PSObject.Properties.Name -contains 'State' -and
    $TargetObject.PSObject.Properties.Name -contains 'Conditions'
} {
    Recommend 'Conditional Access policies should enforce MFA for all users and applications'
    Reason 'Essential 8 recommends using Conditional Access to enforce MFA consistently'
    
    # Check if this is an enabled MFA policy
    $isMFAPolicy = $False
    $isEnabled = $False
    
    if ($TargetObject.State -in @('enabled', 'Enabled')) {
        $isEnabled = $True
    }
    
    # Check if policy grants MFA requirement
    if ($TargetObject.PSObject.Properties.Name -contains 'GrantControls') {
        if ($TargetObject.GrantControls.BuiltInControls -contains 'mfa') {
            $isMFAPolicy = $True
        }
    }
    
    if ($isMFAPolicy) {
        $Assert.Create($isEnabled, "Conditional Access policy '$($TargetObject.DisplayName)' requires MFA but is not enabled")
    } else {
        # Not an MFA policy, skip
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-7'
    Category = 'Multi-Factor Authentication'
    Severity = 'High'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Legacy authentication should be blocked
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-7.AzureAD.ConditionalAccess.BlockLegacyAuth' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and
    $TargetObject.PSObject.Properties.Name -contains 'Conditions' -and
    $TargetObject.PSObject.Properties.Name -contains 'State'
} {
    Recommend 'Legacy authentication protocols should be blocked via Conditional Access'
    Reason 'Legacy authentication does not support MFA and poses a security risk'
    
    $blocksLegacyAuth = $False
    $isEnabled = $False
    
    if ($TargetObject.State -in @('enabled', 'Enabled')) {
        $isEnabled = $True
    }
    
    # Check if policy targets legacy authentication
    if ($TargetObject.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or 
        $TargetObject.Conditions.ClientAppTypes -contains 'other') {
        
        # Check if it blocks access
        if ($TargetObject.PSObject.Properties.Name -contains 'GrantControls') {
            if ($TargetObject.GrantControls.BuiltInControls -contains 'block') {
                $blocksLegacyAuth = $True
            }
        }
        
        if ($blocksLegacyAuth) {
            $Assert.Create($isEnabled, "Conditional Access policy '$($TargetObject.DisplayName)' blocks legacy auth but is not enabled")
        } else {
            $Assert.Create($False, "Conditional Access policy '$($TargetObject.DisplayName)' targets legacy auth but does not block it")
        }
    } else {
        # Not a legacy auth policy
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-7'
    Category = 'Multi-Factor Authentication'
    Severity = 'High'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Service principals should use certificate-based authentication
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-7.AzureAD.ServicePrincipal.CertificateAuth' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and
    $TargetObject.PSObject.Properties.Name -contains 'KeyCredentials' -and
    $TargetObject.PSObject.Properties.Name -contains 'PasswordCredentials'
} {
    Recommend 'Service principals should use certificate-based authentication instead of secrets'
    Reason 'Certificates provide stronger authentication than client secrets'
    
    # Check if using password credentials (secrets)
    $hasSecrets = $False
    $hasCertificates = $False
    
    if ($TargetObject.PasswordCredentials -and $TargetObject.PasswordCredentials.Count -gt 0) {
        $hasSecrets = $True
    }
    
    if ($TargetObject.KeyCredentials -and $TargetObject.KeyCredentials.Count -gt 0) {
        $hasCertificates = $True
    }
    
    # Prefer certificates over secrets
    if ($hasSecrets -and !$hasCertificates) {
        $Assert.Create($False, "Service principal '$($TargetObject.DisplayName)' uses client secrets - should use certificate authentication")
    } elseif (!$hasSecrets -and !$hasCertificates) {
        # No auth configured - likely a Microsoft service principal
        $Assert.Pass()
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-7'
    Category = 'Multi-Factor Authentication'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}
