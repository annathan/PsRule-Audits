# SharePoint-Audit.ps1
# Essential 8 PSRule definitions for SharePoint Online and On-Premises environments
# Covers SharePoint security, governance, and compliance controls

#region Strategy 1: Application Control (SharePoint Apps and Solutions)

# SharePoint App Catalog should have governance controls
Rule 'Essential8.SharePoint.Apps.Governance' -Type 'Microsoft.SharePoint.AppCatalog' {
    # App catalog should exist and be properly configured
    $Assert.HasField($TargetObject, 'AppCatalogUrl')
    $Assert.NotNull($TargetObject.AppCatalogUrl)
    
    # App requests should require approval
    $Assert.HasFieldValue($TargetObject, 'AppRequestsEnabled', $true)
    $Assert.HasField($TargetObject, 'AppCatalogOwners')
    $Assert.GreaterOrEqual($TargetObject.AppCatalogOwners.Count, 1)
    
    # Custom script should be controlled
    $Assert.HasFieldValue($TargetObject, 'CustomScriptEnabled', $false)
}

# Only approved/certified apps should be allowed
Rule 'Essential8.SharePoint.Apps.CertifiedOnly' -Type 'Microsoft.SharePoint.InstalledApp' {
    # Apps should be from trusted sources
    $trustedSources = @('Microsoft', 'FirstParty', 'AppCatalog')
    $Assert.In($TargetObject.AppSource, $trustedSources)
    
    # Third-party apps should be reviewed and approved
    if ($TargetObject.AppSource -eq 'Store') {
        $Assert.HasField($TargetObject, 'ApprovalStatus')
        $Assert.HasFieldValue($TargetObject, 'ApprovalStatus', 'Approved')
        $Assert.HasField($TargetObject, 'ReviewedBy')
    }
    
    # Apps should have current versions (not outdated)
    if ($TargetObject.LastUpdated) {
        $daysSinceUpdate = (Get-Date) - [DateTime]$TargetObject.LastUpdated
        $Assert.LessOrEqual($daysSinceUpdate.Days, 365) # Updated within last year
    }
}

# Power Platform integration should be controlled
Rule 'Essential8.SharePoint.PowerPlatform.DLP' -Type 'Microsoft.SharePoint.PowerPlatformIntegration' {
    # Power Apps and Power Automate should be governed
    $Assert.HasFieldValue($TargetObject, 'PowerAppsEnvironment', 'Managed')
    
    # Data connectors should be classified appropriately
    $Assert.HasField($TargetObject, 'DataLossPreventionPolicy')
    $Assert.NotNull($TargetObject.DataLossPreventionPolicy)
    
    # Cross-tenant connections should be restricted
    $Assert.HasFieldValue($TargetObject, 'CrossTenantAccessEnabled', $false)
}

#endregion

#region Strategy 3: Configure Microsoft Office Macro Settings (SharePoint Document Libraries)

# Document libraries should have macro restrictions
Rule 'Essential8.SharePoint.MacroRestrictions.Strict' -Type 'Microsoft.SharePoint.DocumentLibrary' {
    # IRM (Information Rights Management) should be enabled for sensitive libraries
    $Assert.HasField($TargetObject, 'IRMEnabled')
    
    # File types with macros should be restricted or scanned
    $macroFileTypes = @('*.docm', '*.xlsm', '*.pptm', '*.dotm', '*.xltm', '*.potm')
    
    if ($TargetObject.BlockedFileExtensions) {
        $blockedExtensions = $TargetObject.BlockedFileExtensions -split ';'
        # Should block some macro-enabled file types or have scanning
        $macroTypesBlocked = $macroFileTypes | Where-Object { $_ -in $blockedExtensions }
        
        # Either block macro files or ensure ATP is scanning them
        if ($macroTypesBlocked.Count -eq 0) {
            # If not blocking, ensure ATP scanning is enabled
            $Assert.HasFieldValue($TargetObject, 'ATPEnabled', $true)
        }
    }
}

# Site collection policies for macro handling
Rule 'Essential8.SharePoint.Site.MacroPolicy' -Type 'Microsoft.SharePoint.SiteCollection' {
    # Custom script should be disabled to prevent macro execution
    $Assert.HasFieldValue($TargetObject, 'DenyAddAndCustomizePages', $true)
    
    # Script editor web parts should be disabled
    $Assert.HasFieldValue($TargetObject, 'CustomScriptEnabled', $false)
    
    # External sharing should be controlled for macro-containing files
    if ($TargetObject.SharingCapability -ne 'Disabled') {
        $Assert.HasField($TargetObject, 'DefaultSharingLinkType')
        $Assert.HasFieldValue($TargetObject, 'RequireAcceptingAccountMatchInvitedAccount', $true)
    }
}

#endregion

#region Strategy 4: User Application Hardening (SharePoint Browser Controls)

# SharePoint should enforce modern browsers and security
Rule 'Essential8.SharePoint.Browser.Compatibility' -Type 'Microsoft.SharePoint.TenantSettings' {
    # Legacy browser support should be disabled
    $Assert.HasFieldValue($TargetObject, 'LegacyAuthProtocolsEnabled', $false)
    
    # Modern authentication should be required
    $Assert.HasFieldValue($TargetObject, 'RequireModernAuth', $true)
    
    # ActiveX and Silverlight controls should be disabled
    $Assert.HasFieldValue($TargetObject, 'RequirePluginRemoval', $true)
}

# Site collections should use modern experiences
Rule 'Essential8.SharePoint.ModernExperience' -Type 'Microsoft.SharePoint.SiteCollection' {
    # Modern lists and libraries should be the default
    $Assert.HasFieldValue($TargetObject, 'ModernListExperienceEnabled', $true)
    $Assert.HasFieldValue($TargetObject, 'ModernSitePageExperienceEnabled', $true)
    
    # Classic publishing features should be minimized
    if ($TargetObject.PublishingEnabled) {
        # If publishing is enabled, ensure it's the modern version
        $Assert.HasField($TargetObject, 'ModernPublishingEnabled')
    }
}

#endregion

#region Strategy 5: Restrict Administrative Privileges (SharePoint Permissions)

# Site collection administrators should be minimal
Rule 'Essential8.SharePoint.AdminAccess.Restricted' -Type 'Microsoft.SharePoint.SiteCollection' {
    # Should have limited number of site collection admins
    $maxAdmins = 5 # Reasonable limit for most site collections
    $actualAdmins = $TargetObject.SiteCollectionAdministrators.Count
    $Assert.LessOrEqual($actualAdmins, $maxAdmins)
    
    # Admins should not include broad groups
    $adminGroups = $TargetObject.SiteCollectionAdministrators | Where-Object { $_.PrincipalType -eq 'SecurityGroup' }
    foreach ($group in $adminGroups) {
        # Groups should not be "Everyone" or overly broad
        $Assert.NotMatch($group.LoginName, 'Everyone|All Users|Domain Users')
    }
    
    # Should have at least one admin (not empty)
    $Assert.GreaterOrEqual($actualAdmins, 1)
}

# Farm administrators (on-premises) should be restricted
Rule 'Essential8.SharePoint.FarmAdmins.Minimal' -Type 'Microsoft.SharePoint.Farm' -If { $TargetObject.IsOnPremises } {
    # Farm administrators should be minimal
    $farmAdmins = $TargetObject.FarmAdministrators.Count
    $Assert.LessOrEqual($farmAdmins, 3) # Very limited for on-premises farms
    
    # Service accounts should be separate from admin accounts
    $serviceAccounts = $TargetObject.ServiceAccounts | Where-Object { $_.AccountType -eq 'Service' }
    $adminAccounts = $TargetObject.FarmAdministrators
    
    # Service accounts should not be farm admins
    foreach ($serviceAccount in $serviceAccounts) {
        $isAlsoAdmin = $adminAccounts | Where-Object { $_.LoginName -eq $serviceAccount.LoginName }
        $Assert.Null($isAlsoAdmin)
    }
}

# Permission inheritance should be reviewed
Rule 'Essential8.SharePoint.Permissions.Review' -Type 'Microsoft.SharePoint.WebPermissions' {
    # Unique permissions should be documented and justified
    if (-not $TargetObject.HasUniqueRoleAssignments) {
        # Inheriting permissions is generally good
        $Assert.HasFieldValue($TargetObject, 'HasUniqueRoleAssignments', $false)
    } else {
        # If unique permissions exist, they should be documented
        $Assert.HasField($TargetObject, 'PermissionJustification')
        $Assert.HasField($TargetObject, 'LastReviewDate')
        
        # Review should be recent (within 90 days)
        if ($TargetObject.LastReviewDate) {
            $daysSinceReview = (Get-Date) - [DateTime]$TargetObject.LastReviewDate
            $Assert.LessOrEqual($daysSinceReview.Days, 90)
        }
    }
}

#endregion

#region Strategy 8: Regular Backups (SharePoint Data Protection)

# SharePoint backup should be configured
Rule 'Essential8.SharePoint.Backup.ThirdParty' -Type 'Microsoft.SharePoint.BackupSolution' {
    # For SharePoint Online, third-party backup is recommended
    if ($TargetObject.Platform -eq 'SharePointOnline') {
        $Assert.HasField($TargetObject, 'BackupSolutionName')
        $Assert.NotNull($TargetObject.BackupSolutionName)
        
        # Backup should be recent
        $Assert.HasField($TargetObject, 'LastBackupDate')
        if ($TargetObject.LastBackupDate) {
            $daysSinceBackup = (Get-Date) - [DateTime]$TargetObject.LastBackupDate
            $Assert.LessOrEqual($daysSinceBackup.Days, 1) # Daily backups
        }
        
        # Should include all site collections
        $Assert.HasField($TargetObject, 'SiteCollectionsCovered')
        $Assert.GreaterOrEqual($TargetObject.SiteCollectionsCovered, 1)
    }
}

# Versioning should be enabled for document protection
Rule 'Essential8.SharePoint.Versioning.Enabled' -Type 'Microsoft.SharePoint.DocumentLibrary' {
    # Major and minor versioning should be enabled
    $Assert.HasFieldValue($TargetObject, 'EnableVersioning', $true)
    
    # Should retain reasonable number of versions
    $Assert.GreaterOrEqual($TargetObject.MajorVersions, 10)
    
    # Minor versions for Office documents
    if ($TargetObject.EnableMinorVersions) {
        $Assert.GreaterOrEqual($TargetObject.MajorWithMinorVersions, 5)
    }
    
    # Content approval for sensitive libraries
    if ($TargetObject.IsBusinessCritical) {
        $Assert.HasFieldValue($TargetObject, 'ContentApprovalRequired', $true)
    }
}

# Recycle bin retention should be configured
Rule 'Essential8.SharePoint.RecycleBin.Retention' -Type 'Microsoft.SharePoint.SiteCollection' {
    # First-stage recycle bin should be enabled with adequate retention
    $Assert.HasField($TargetObject, 'RecycleBinEnabled')
    $Assert.HasFieldValue($TargetObject, 'RecycleBinEnabled', $true)
    
    # Retention period should be at least 30 days
    if ($TargetObject.RecycleBinRetentionPeriod) {
        $Assert.GreaterOrEqual($TargetObject.RecycleBinRetentionPeriod, 30)
    }
    
    # Second-stage recycle bin should also be enabled (tenant level)
    $Assert.HasField($TargetObject, 'SecondStageRecycleBinQuota')
    $Assert.GreaterOrEqual($TargetObject.SecondStageRecycleBinQuota, 50) # 50% of site quota
}

# Information Rights Management for data protection
Rule 'Essential8.SharePoint.IRM.DataProtection' -Type 'Microsoft.SharePoint.DocumentLibrary' {
    # Sensitive libraries should have IRM enabled
    if ($TargetObject.ContainsSensitiveData) {
        $Assert.HasFieldValue($TargetObject, 'IRMEnabled', $true)
        
        # IRM settings should be properly configured
        $Assert.HasField($TargetObject, 'IRMExpire')
        $Assert.HasField($TargetObject, 'IRMReject')
        
        # Offline access should be controlled
        $Assert.HasFieldValue($TargetObject, 'IRMEnableOfflineAccess', $false)
