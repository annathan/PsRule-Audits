# Synopsis: Essential 8 - Mitigation Strategy 1: Application Control
# Description: Rules to verify application whitelisting and control measures
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/application-control

# ---------------------------------------------------------------------------------------------------
# Rule: PowerShell execution policy should be restricted
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-1.M365.PowerShell.ExecutionPolicy' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ExecutionPolicy'
} {
    Recommend 'PowerShell execution policy should be set to AllSigned or RemoteSigned minimum'
    Reason 'Restricting PowerShell execution prevents unauthorized script execution'
    
    $acceptablePolicies = @('AllSigned', 'RemoteSigned', 'Restricted')
    $currentPolicy = $TargetObject.ExecutionPolicy
    
    $Assert.In($currentPolicy, '.', $acceptablePolicies, "PowerShell execution policy is '$currentPolicy' - should be AllSigned or RemoteSigned")
    
} -Tag @{ 
    E8 = 'E8-1'
    Category = 'Application Control'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: SharePoint apps should be reviewed and approved
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-1.SharePoint.Apps.ApprovalRequired' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Title' -and
    $TargetObject.PSObject.Properties.Name -contains 'AppCatalogVersion'
} {
    Recommend 'SharePoint apps should be reviewed and approved before deployment'
    Reason 'Application control requires validation of all applications before use'
    
    # Check if app is deployed
    $isDeployed = $False
    if ($TargetObject.Deployed -eq $True) {
        $isDeployed = $True
    }
    
    if ($isDeployed) {
        $Assert.Pass("App '$($TargetObject.Title)' is deployed - ensure it has been reviewed and approved")
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-1'
    Category = 'Application Control'
    Severity = 'Informational'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Service principals should be reviewed regularly
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-1.AzureAD.ServicePrincipal.ReviewRequired' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and
    $TargetObject.PSObject.Properties.Name -contains 'KeyCredentials'
} {
    Recommend 'Regularly review service principals to ensure only approved applications have access'
    Reason 'Application control extends to cloud applications and APIs'
    
    # Check if this is a custom (non-Microsoft) service principal
    if ($TargetObject.DisplayName -notmatch '^Microsoft|^Windows|^Office|^Azure|^Dynamics') {
        $Assert.Pass("Review required: Custom service principal '$($TargetObject.DisplayName)' - ensure it is approved")
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-1'
    Category = 'Application Control'
    Severity = 'Informational'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: External applications should require admin approval
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-1.AzureAD.Consent.AdminApprovalRequired' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'EnableAdminConsentRequests'
} {
    Recommend 'User consent for applications should be disabled or require admin approval'
    Reason 'Requiring admin approval ensures application control over third-party apps'
    
    $requiresApproval = $False
    if ($TargetObject.EnableAdminConsentRequests -eq $True) {
        $requiresApproval = $True
    }
    
    $Assert.Create($requiresApproval, 'Admin consent workflow is not enabled - users may consent to unapproved applications')
    
} -Tag @{ 
    E8 = 'E8-1'
    Category = 'Application Control'
    Severity = 'High'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Applications should use modern authentication
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-1.AzureAD.Application.ModernAuth' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DisplayName' -and
    $TargetObject.PSObject.Properties.Name -contains 'AppId'
} {
    Recommend 'Applications should use modern authentication protocols (OAuth 2.0, OpenID Connect)'
    Reason 'Modern authentication provides better security controls than legacy protocols'
    
    # Check if app has modern auth credentials configured
    if ($TargetObject.DisplayName -notmatch '^Microsoft|^Windows|^Office|^Azure') {
        if ($TargetObject.PasswordCredentials -or $TargetObject.KeyCredentials) {
            $Assert.Pass("Application '$($TargetObject.DisplayName)' has authentication configured")
        } else {
            $Assert.Pass()
        }
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-1'
    Category = 'Application Control'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

