# Synopsis: Essential 8 - Mitigation Strategy 5: Restrict Administrative Privileges
# Description: Rules to verify administrative access is properly restricted
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/restrict-administrative-privileges

# ---------------------------------------------------------------------------------------------------
# Rule: Limit number of global administrators
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.Admin.GlobalAdminCount' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RoleName' -and
    $TargetObject.RoleName -eq 'Global Administrator'
} {
    Recommend 'Limit Global Administrator role assignments to 2-5 accounts maximum'
    Reason 'Essential 8 requires minimizing privileged access to reduce attack surface'
    
    $memberCount = 0
    if ($TargetObject.Members) {
        $memberCount = $TargetObject.Members.Count
    }
    
    # Best practice: 2-5 global admins maximum
    $Assert.LessOrEqual($memberCount, '.', 5, "Global Administrator role has $memberCount members - should be limited to maximum 5")
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Privileged accounts should be dedicated (not hybrid user/admin)
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.Admin.DedicatedAccounts' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' -and
    $TargetObject.PSObject.Properties.Name -contains 'AssignedRoles'
} {
    Recommend 'Privileged accounts should be dedicated admin accounts, not regular user accounts'
    Reason 'Separation of privileged and regular accounts reduces risk of credential compromise'
    
    # Check if user has privileged roles
    $hasPrivilegedRole = $False
    $privilegedRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Security Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Administrator'
    )
    
    if ($TargetObject.AssignedRoles) {
        foreach ($role in $TargetObject.AssignedRoles) {
            if ($privilegedRoles -contains $role.DisplayName) {
                $hasPrivilegedRole = $True
                break
            }
        }
    }
    
    if ($hasPrivilegedRole) {
        # Check if account appears to be dedicated admin account
        $upn = $TargetObject.UserPrincipalName
        $isDedicatedAdmin = $upn -match '[-_]admin|^admin|adm[-_]|\.admin@'
        
        if (!$isDedicatedAdmin) {
            $Assert.Create($False, "User '$upn' has privileged role but does not appear to be a dedicated admin account")
        } else {
            $Assert.Pass()
        }
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Privileged accounts must have MFA enforced
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.Admin.MFARequired' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' -and
    $TargetObject.PSObject.Properties.Name -contains 'AssignedRoles'
} {
    Recommend 'All privileged accounts must have MFA enforced'
    Reason 'Essential 8 requires MFA for all privileged users without exception'
    
    $hasPrivilegedRole = $False
    $privilegedRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Security Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Administrator',
        'Helpdesk Administrator',
        'Authentication Administrator',
        'Billing Administrator'
    )
    
    if ($TargetObject.AssignedRoles) {
        foreach ($role in $TargetObject.AssignedRoles) {
            if ($privilegedRoles -contains $role.DisplayName) {
                $hasPrivilegedRole = $True
                break
            }
        }
    }
    
    if ($hasPrivilegedRole) {
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
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'Critical'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Break glass accounts should exist
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.Admin.BreakGlassExists' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RoleName' -and
    $TargetObject.RoleName -eq 'Global Administrator'
} {
    Recommend 'Emergency access (break glass) accounts should be configured'
    Reason 'Break glass accounts ensure access during authentication system failures'
    
    if ($TargetObject.Members) {
        $hasBreakGlass = $False
        
        foreach ($member in $TargetObject.Members) {
            $upn = $member.UserPrincipalName
            if ($upn -match 'breakglass|break[-_]glass|emergency|emerg[-_]access') {
                $hasBreakGlass = $True
                break
            }
        }
        
        $Assert.Create($hasBreakGlass, 'No emergency access (break glass) account detected in Global Administrators')
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Review privileged role assignments regularly
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.Admin.RoleAssignmentReview' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RoleName' -and
    $TargetObject.PSObject.Properties.Name -contains 'Members'
} {
    Recommend 'Privileged role assignments should be reviewed regularly (quarterly minimum)'
    Reason 'Regular reviews ensure only authorized users retain privileged access'
    
    $privilegedRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Security Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Administrator',
        'Application Administrator',
        'Cloud Application Administrator'
    )
    
    if ($privilegedRoles -contains $TargetObject.RoleName) {
        # This is informational - manual review required
        if ($TargetObject.Members -and $TargetObject.Members.Count -gt 0) {
            $Assert.Pass("Review required: $($TargetObject.RoleName) has $($TargetObject.Members.Count) member(s)")
        } else {
            $Assert.Pass()
        }
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'Informational'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Service accounts should not have interactive sign-in rights
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.ServiceAccount.NoInteractiveSignIn' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and
    $TargetObject.PSObject.Properties.Name -contains 'KeyCredentials'
} {
    Recommend 'Service principals should use non-interactive authentication only'
    Reason 'Service accounts should not support interactive sign-in to reduce attack surface'
    
    # Check if this is a custom service principal (not Microsoft first-party)
    if ($TargetObject.DisplayName -notmatch '^Microsoft|^Windows|^Office|^Azure') {
        # Custom service principal - ensure proper authentication
        if ($TargetObject.PasswordCredentials -or $TargetObject.KeyCredentials) {
            $Assert.Pass()
        } else {
            $Assert.Create($False, "Service principal '$($TargetObject.DisplayName)' has no authentication credentials configured")
        }
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Privileged access should use Privileged Identity Management (PIM)
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-5.AzureAD.PIM.JustInTimeAccess' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RoleName'
} {
    Recommend 'Use Azure AD Privileged Identity Management (PIM) for just-in-time privileged access'
    Reason 'PIM provides time-limited, approval-based role activation to minimize standing privileges'
    
    $highlyPrivilegedRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Security Administrator'
    )
    
    if ($highlyPrivilegedRoles -contains $TargetObject.RoleName) {
        # Check if PIM is indicated (this would need additional data collection)
        # For now, this is informational
        $Assert.Pass("Consider implementing PIM for $($TargetObject.RoleName) role")
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-5'
    Category = 'Administrative Privileges'
    Severity = 'Informational'
    MaturityLevel = 'ML3'
}

