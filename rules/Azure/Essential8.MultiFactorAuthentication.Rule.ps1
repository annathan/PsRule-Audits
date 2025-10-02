# Synopsis: Essential 8 - Mitigation Strategy 7: Multi-Factor Authentication
# Description: Rules to verify MFA is properly configured across Azure AD/Entra ID
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/multi-factor-authentication
# Essential8.MultiFactorAuthentication.Rule.ps1
# Type-agnostic PSRule rules so they run without binding

# Helper: fast field existence check
function Test-HasField {
    param($obj, [string]$name)
    return $null -ne ($obj.PSObject.Properties[$name])
}

# ---------- Azure AD MFA Rules ----------

Rule 'Essential8.AzureAD.MFA.Enabled' {
    # Only evaluate on objects that look like users
    if (Test-HasField $TargetObject 'StrongAuthenticationRequirements') {
        $state = $TargetObject.StrongAuthenticationRequirements.State
        $state | Should -BeIn @('Enabled','Enforced') -Because 'MFA must be enabled or enforced for all users'

        $mfaState = @($TargetObject.StrongAuthenticationRequirements | Where-Object { $_.State -eq 'Enforced' })
        ($mfaState.Count) | Should -BeGreaterOrEqual 1 -Because 'MFA should be enforced, not just enabled'
    }
}

Rule 'Essential8.AzureAD.MFA.PrivilegedAccounts' {
    if (Test-HasField $TargetObject 'AssignedRoles' -and Test-HasField $TargetObject 'StrongAuthenticationRequirements') {

        $privilegedRoles = @(
            'Global Administrator','Security Administrator','Exchange Administrator',
            'SharePoint Administrator','User Administrator','Conditional Access Administrator'
        )

        $userRoles = @($TargetObject.AssignedRoles | ForEach-Object { $_.DisplayName })
        $hasPrivileged = $userRoles | Where-Object { $privilegedRoles -contains $_ }

        if ($hasPrivileged) {
            $TargetObject.StrongAuthenticationRequirements.State |
                Should -Be 'Enforced' -Because 'Privileged accounts must have MFA enforced'

            $defaultMethods = @($TargetObject.StrongAuthenticationMethods | Where-Object { $_.IsDefault }).MethodType
            foreach ($m in $defaultMethods) {
                $m | Should -Not -BeIn @('OneWaySMS','TwoWayVoiceMobile') -Because 'SMS/Voice are weaker factors for admins'
            }
        }
    }
}

Rule 'Essential8.AzureAD.ConditionalAccess.MFA' {
    if (Test-HasField $TargetObject 'GrantControls' -and Test-HasField $TargetObject 'Conditions') {
        $TargetObject.State | Should -Be 'enabled' -Because 'CA policy should be enabled'
        $TargetObject.GrantControls.BuiltInControls | Should -Contain 'mfa' -Because 'CA must require MFA'
        ($TargetObject.Conditions.Users.IncludeUsers.Count) |
            Should -BeGreaterOrEqual 1 -Because 'Policy must target users or groups'
    }
}

Rule 'Essential8.AzureAD.BlockLegacyAuth' {
    if (Test-HasField $TargetObject 'DisplayName' -and Test-HasField $TargetObject 'Conditions') {
        if ($TargetObject.DisplayName -match 'Block.*Legacy' -or $TargetObject.DisplayName -match 'Legacy.*Block') {
            $TargetObject.State | Should -Be 'enabled' -Because 'Block legacy auth policy should be enabled'
            $TargetObject.Conditions.ClientAppTypes | Should -Contain 'exchangeActiveSync'
            $TargetObject.Conditions.ClientAppTypes | Should -Contain 'other'
            $TargetObject.GrantControls.Operator | Should -Be 'OR'
            $TargetObject.GrantControls.BuiltInControls | Should -Contain 'block'
        }
    }
}

# ---------- Microsoft 365 MFA Rules ----------

Rule 'Essential8.Exchange.MFA.Required' {
    if (Test-HasField $TargetObject 'ModernAuthenticationEnabled') {
        $TargetObject.ModernAuthenticationEnabled | Should -BeTrue -Because 'Modern Auth must be enabled'
    }
}

Rule 'Essential8.SharePoint.ExternalSharing.MFA' {
    if (Test-HasField $TargetObject 'SharingCapability') {
        if ($TargetObject.SharingCapability -ne 'Disabled') {
            $TargetObject.RequireAcceptingAccountMatchInvitedAccount |
                Should -BeTrue -Because 'External users must authenticate strongly'
        }
    }
}

Rule 'Essential8.PowerPlatform.MFA.DLP' {
    if (Test-HasField $TargetObject 'ConnectorGroups') {
        $TargetObject.DisplayName | Should -Not -BeNullOrEmpty

        $business = $TargetObject.ConnectorGroups | Where-Object { $_.Classification -eq 'Business' }
        if ($business) {
            foreach ($connector in @('shared_sql','shared_filesystem','shared_ftp')) {
                if ($business.Connectors -contains $connector) {
                    (Test-HasField $TargetObject 'EnvironmentType') |
                        Should -BeTrue -Because 'High-risk connectors require explicit environment scoping'
                }
            }
        }
    }
}

# ---------- Service Account and Emergency Access ----------

Rule 'Essential8.AzureAD.EmergencyAccess' {
    if (Test-HasField $TargetObject 'UserPrincipalName') {
        if ($TargetObject.UserPrincipalName -match 'emergency|break.*glass|admin.*emergency') {
            if (Test-HasField $TargetObject 'DirSyncEnabled') {
                $TargetObject.DirSyncEnabled | Should -BeFalse -Because 'Emergency accounts should be cloud-only'
            }
            if (Test-HasField $TargetObject 'PasswordPolicies') {
                $TargetObject.PasswordPolicies | Should -Be 'DisablePasswordExpiration'
            }
            (Test-HasField $TargetObject 'StrongAuthenticationRequirements') |
                Should -BeTrue -Because 'Emergency accounts still tracked for MFA config'
            if (Test-HasField $TargetObject 'AssignedRoles') {
                ($TargetObject.AssignedRoles.Count) | Should -BeGreaterOrEqual 1
            }
        }
    }
}

Rule 'Essential8.AzureAD.ServiceAccounts.Auth' {
    if (Test-HasField $TargetObject 'KeyCredentials' -or Test-HasField $TargetObject 'PasswordCredentials') {
        $keyCount = @($TargetObject.KeyCredentials).Count
        $pwdValid = @($TargetObject.PasswordCredentials | Where-Object { $_.EndDate -gt (Get-Date) }).Count
        if ($keyCount -eq 0) {
            $pwdValid | Should -BeGreaterOrEqual 1 -Because 'Service principals need non-expired credentials at minimum'
        }
    }
}

# ---------- Reporting ----------

Rule 'Essential8.MFA.ComplianceSummary' {
    if (Test-HasField $TargetObject 'Users') {
        $mfaEnabledUsers = @(
            $TargetObject.Users | Where-Object {
                $_.StrongAuthenticationRequirements.State -in @('Enabled','Enforced')
            }
        )
        $total = @($TargetObject.Users).Count
        if ($total -gt 0) {
            $pct = [math]::Round(($mfaEnabledUsers.Count / $total) * 100, 2)
            $pct | Should -BeGreaterOrEqual 95 -Because 'E8 ML2 expects near-universal MFA'
            Write-Information "MFA Compliance: $pct% ($($mfaEnabledUsers.Count)/$total users)"
        }
    }
}
