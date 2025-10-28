# Synopsis: Essential 8 - Mitigation Strategy 1: Application Control
# Description: Rules to verify application control is properly configured
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/application-control

# ---------- Azure AD Application Control Rules ----------

Rule 'Essential8.E8-1.AzureAD.Apps.AdminConsentRequired' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AppId' -and
    $TargetObject.PSObject.Properties.Name -contains 'RequiredResourceAccess'
} {
    Recommend 'Applications should require admin consent for high-risk permissions'
    Reason 'Essential 8 requires control over application permissions to prevent unauthorized access'
    
    # Check for high-risk permissions that should require admin consent
    $highRiskPermissions = @(
        'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'User.ReadWrite.All',
        'Mail.ReadWrite', 'Files.ReadWrite.All', 'Sites.ReadWrite.All'
    )
    
    if ($TargetObject.RequiredResourceAccess) {
        foreach ($resource in $TargetObject.RequiredResourceAccess) {
            foreach ($access in $resource.ResourceAccess) {
                if ($access.Type -eq 'Role' -and $highRiskPermissions -contains $access.Id) {
                    # High-risk permissions should be application permissions (Role type)
                    $access.Type | Should -Be 'Role' -Because 'High-risk permissions should require admin consent'
                }
            }
        }
    }
}

Rule 'Essential8.E8-1.AzureAD.Apps.PublisherVerification' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AppId' -and
    $TargetObject.PSObject.Properties.Name -contains 'PublisherDomain'
} {
    Recommend 'Applications should have verified publishers for security assurance'
    Reason 'Essential 8 requires verification of application sources to prevent malicious apps'
    
    if ($TargetObject.PublisherDomain) {
        $TargetObject.PublisherDomain | Should -Not -BeNullOrEmpty -Because 'Applications should have verified publishers'
    }
}

Rule 'Essential8.E8-1.AzureAD.Apps.ConsentSettings' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DefaultUserRolePermissions'
} {
    Recommend 'User consent for applications should be restricted or disabled'
    Reason 'Essential 8 requires control over application installations and permissions'
    
    if ($TargetObject.DefaultUserRolePermissions) {
        $TargetObject.DefaultUserRolePermissions.AllowedToCreateApps | Should -BeFalse -Because 'Users should not be able to create applications without approval'
        $TargetObject.DefaultUserRolePermissions.AllowedToReadOtherUsers | Should -BeFalse -Because 'Default user permissions should be restricted'
    }
}

Rule 'Essential8.E8-1.AzureAD.ServicePrincipals.Credentials' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AppId' -and
    $TargetObject.PSObject.Properties.Name -contains 'KeyCredentials'
} {
    Recommend 'Service principals should use certificate-based authentication where possible'
    Reason 'Essential 8 requires strong authentication for service accounts'
    
    $keyCount = @($TargetObject.KeyCredentials).Count
    $passwordCount = @($TargetObject.PasswordCredentials).Count
    
    if ($keyCount -eq 0 -and $passwordCount -gt 0) {
        # Prefer certificate authentication over password authentication
        $keyCount | Should -BeGreaterThan 0 -Because 'Service principals should use certificate authentication'
    }
}

# ---------- SharePoint Application Control Rules ----------

Rule 'Essential8.E8-1.SharePoint.Apps.StoreSettings' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AppCatalogUrl'
} {
    Recommend 'SharePoint app store should be configured to allow only approved apps'
    Reason 'Essential 8 requires control over application installations'
    
    # This would check SharePoint app catalog settings
    # Implementation depends on collected SharePoint data structure
    $Assert.Pass() # Placeholder - implement based on actual SharePoint data
}

Rule 'Essential8.E8-1.SharePoint.ExternalSharing.Control' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'SharingCapability'
} {
    Recommend 'External sharing should be controlled to prevent unauthorized access'
    Reason 'Essential 8 requires control over data access and sharing'
    
    # SharePoint sharing should be restricted
    $TargetObject.SharingCapability | Should -BeIn @('Disabled', 'ExistingExternalUserSharingOnly') -Because 'External sharing should be restricted'
}

# ---------- Teams Application Control Rules ----------

Rule 'Essential8.E8-1.Teams.Apps.Policy' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AllowUserPinning' -or
    $TargetObject.PSObject.Properties.Name -contains 'AllowSideLoading'
} {
    Recommend 'Teams app policies should restrict unauthorized app installations'
    Reason 'Essential 8 requires control over application installations in collaboration platforms'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowSideLoading') {
        $TargetObject.AllowSideLoading | Should -BeFalse -Because 'Side-loading of apps should be disabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowUserPinning') {
        # User pinning can be allowed but should be controlled
        # This is less critical than side-loading
    }
}
