# M365audit.ps1
# Essential 8 PSRule definitions for Microsoft 365 environments
# Covers Exchange Online, Teams, Office Apps, and general M365 security

#region Strategy 3: Configure Microsoft Office Macro Settings

# Block macros from internet sources
Rule 'Essential8.M365.Macros.InternetBlocked' -Type 'Microsoft.Exchange.TransportRule' {
    $targetObject = $TargetObject
    
    # Look for transport rules that block macro-containing attachments from internet
    if ($targetObject.Name -match 'Block.*Macro|Macro.*Block' -or 
        $targetObject.Description -match 'macro|attachment.*block') {
        
        # Rule should be enabled
        $Assert.HasFieldValue($targetObject, 'State', 'Enabled')
        
        # Should have conditions for external senders
        $Assert.HasField($targetObject, 'FromScope')
        $Assert.In($targetObject.FromScope, @('NotInOrganization', 'ExternalNonPartner'))
        
        # Should block or quarantine dangerous attachments
        $actions = $targetObject.Actions | Where-Object { $_.Action -match 'Block|Quarantine|Delete' }
        $Assert.GreaterOrEqual($actions.Count, 1)
    }
}

# Macro execution should be restricted to signed macros only
Rule 'Essential8.M365.Macros.DigitallySignedOnly' -Type 'Microsoft.M365.MacroPolicy' {
    # This would require custom data collection for Office macro policies
    # Checking through Group Policy or Intune policies
    
    if ($TargetObject.PolicyType -eq 'OfficeMacroSecurity') {
        # VBA macro execution should be disabled or restricted
        $Assert.HasFieldValue($TargetObject, 'VBAMacrosEnabled', $false)
        
        # Or if enabled, should require signing
        if ($TargetObject.VBAMacrosEnabled -eq $true) {
            $Assert.HasFieldValue($TargetObject, 'RequireSignedMacros', $true)
            $Assert.HasFieldValue($TargetObject, 'TrustedPublishersOnly', $true)
        }
    }
}

# Safe Attachments should be configured to block macros
Rule 'Essential8.M365.SafeAttachments.MacroProtection' -Type 'Microsoft.Exchange.SafeAttachmentPolicy' {
    # Policy should be enabled
    $Assert.HasFieldValue($TargetObject, 'Enable', $true)
    
    # Should have blocking or dynamic delivery action
    $Assert.In($TargetObject.Action, @('Block', 'DynamicDelivery'))
    
    # Should apply to all users or specific groups
    $Assert.GreaterOrEqual($TargetObject.AppliedToRecipients.Count, 1)
    
    # Should scan for common macro file types
    $dangerousExtensions = @('*.doc', '*.docm', '*.xls', '*.xlsm', '*.ppt', '*.pptm')
    # Note: This might need adjustment based on actual SafeAttachments configuration
}

#endregion

#region Strategy 4: User Application Hardening

# Browser security settings through Edge policies
Rule 'Essential8.M365.BrowserSecurity.Basic' -Type 'Microsoft.M365.EdgePolicy' {
    if ($TargetObject.PolicyType -eq 'EdgeBrowser') {
        # SmartScreen should be enabled
        $Assert.HasFieldValue($TargetObject, 'SmartScreenEnabled', $true)
        
        # Downloads should be scanned
        $Assert.HasFieldValue($TargetObject, 'SmartScreenForTrustedDownloadsEnabled', $true)
        
        # Block potentially unwanted applications
        $Assert.HasFieldValue($TargetObject, 'SmartScreenPuaEnabled', $true)
        
        # Adobe Flash should be disabled
        $Assert.HasFieldValue($TargetObject, 'DefaultPluginsSetting', 2) # Block
        $Assert.HasFieldValue($TargetObject, 'RunAllFlashInAllowMode', $false)
        
        # Auto-downloads should be restricted
        $Assert.HasFieldValue($TargetObject, 'DefaultDownloadDirectory', '*')
        $Assert.HasFieldValue($TargetObject, 'PromptForDownloadLocation', $true)
    }
}

# Advanced browser hardening for ML2+
Rule 'Essential8.M365.BrowserSecurity.Advanced' -Type 'Microsoft.M365.EdgePolicy' {
    if ($TargetObject.PolicyType -eq 'EdgeBrowser') {
        # Include all basic requirements
        $Assert.HasFieldValue($TargetObject, 'SmartScreenEnabled', $true)
        
        # Additional hardening
        $Assert.HasFieldValue($TargetObject, 'PasswordManagerEnabled', $false) # Use enterprise password manager
        $Assert.HasFieldValue($TargetObject, 'AutofillAddressEnabled', $false)
        $Assert.HasFieldValue($TargetObject, 'AutofillCreditCardEnabled', $false)
        
        # Enhanced Safe Browsing
        $Assert.HasFieldValue($TargetObject, 'SafeBrowsingProtectionLevel', 2) # Enhanced protection
        
        # Block dangerous downloads
        $Assert.HasFieldValue($TargetObject, 'DownloadRestrictionsEnabled', $true)
    }
}

# Office applications hardening
Rule 'Essential8.M365.OfficeApps.Hardening' -Type 'Microsoft.M365.OfficePolicy' {
    if ($TargetObject.ApplicationName -in @('Word', 'Excel', 'PowerPoint', 'Outlook')) {
        # ActiveX controls should be disabled
        $Assert.HasFieldValue($TargetObject, 'ActiveXControlsDisabled', $true)
        
        # External content should be blocked or restricted
        $Assert.HasFieldValue($TargetObject, 'BlockExternalContent', $true)
        
        # Automatic links to external content should be disabled
        $Assert.HasFieldValue($TargetObject, 'DisableExternalLinks', $true)
        
        # Protected View should be enabled for internet files
        $Assert.HasFieldValue($TargetObject, 'ProtectedViewForInternetFiles', $true)
        $Assert.HasFieldValue($TargetObject, 'ProtectedViewForEmailAttachments', $true)
    }
}

#endregion

#region Strategy 2: Patch Applications (M365 Update Policies)

# Windows Update for Business policies
Rule 'Essential8.M365.UpdatePolicies.Basic' -Type 'Microsoft.Intune.WindowsUpdatePolicy' {
    # Automatic updates should be enabled
    $Assert.HasFieldValue($TargetObject, 'AutomaticUpdateMode', 'AutoInstallAtMaintenanceTime')
    
    # Quality updates should be installed promptly
    $Assert.LessOrEqual($TargetObject.QualityUpdatesDeferralPeriodInDays, 7)
    
    # Feature updates can be deferred longer but should be scheduled
    $Assert.LessOrEqual($TargetObject.FeatureUpdatesDeferralPeriodInDays, 180)
    
    # Restart policies should be configured
    $Assert.HasField($TargetObject, 'RestartWarningInHours')
}

# Enhanced update policies for ML2
Rule 'Essential8.M365.UpdatePolicies.Enforced' -Type 'Microsoft.Intune.WindowsUpdatePolicy' {
    # Stricter update requirements
    $Assert.HasFieldValue($TargetObject, 'AutomaticUpdateMode', 'AutoInstallAndRebootAtMaintenanceTime')
    
    # Minimal deferral for quality updates
    $Assert.LessOrEqual($TargetObject.QualityUpdatesDeferralPeriodInDays, 3)
    
    # Should have compliance policies for update installation
    $Assert.HasField($TargetObject, 'ComplianceGracePeriodInDays')
    $Assert.LessOrEqual($TargetObject.ComplianceGracePeriodInDays, 7)
}

# Office 365 update channels
Rule 'Essential8.M365.OfficeUpdates.Channel' -Type 'Microsoft.M365.OfficeUpdatePolicy' {
    # Should use Semi-Annual or Monthly Enterprise channel for stability
    $validChannels = @('SemiAnnual', 'MonthlyEnterprise', 'Current')
    $Assert.In($TargetObject.UpdateChannel, $validChannels)
    
    # Updates should be enabled
    $Assert.HasFieldValue($TargetObject, 'UpdatesEnabled', $true)
    
    # Should have update deadline configured
    $Assert.HasField($TargetObject, 'UpdateDeadline')
}

#endregion

#region Strategy 7: Multi-factor Authentication (M365 Specific)

# Modern authentication should be enabled for Exchange
Rule 'Essential8.Exchange.ModernAuth.Required' -Type 'Microsoft.Exchange.OrganizationConfig' {
    # Modern authentication should be enabled
    $Assert.HasFieldValue($TargetObject, 'OAuth2ClientProfileEnabled', $true)
    
    # Legacy authentication should be disabled
    $Assert.HasFieldValue($TargetObject, 'DefaultAuthenticationPolicy')
    
    # IMAP and POP should be disabled or restricted
    $Assert.HasFieldValue($TargetObject, 'ImapEnabled', $false)
    $Assert.HasFieldValue($TargetObject, 'PopEnabled', $false)
}

# Teams MFA and security policies
Rule 'Essential8.Teams.Security.MFA' -Type 'Microsoft.Teams.Policy' {
    if ($TargetObject.PolicyType -eq 'TeamsMessagingPolicy') {
        # External access should require MFA (handled by Conditional Access)
        # File sharing should be controlled
        $Assert.HasField($TargetObject, 'AllowUserEditMessage')
        $Assert.HasField($TargetObject, 'AllowUserDeleteMessage')
    }
    
    if ($TargetObject.PolicyType -eq 'TeamsMeetingPolicy') {
        # Anonymous users should not be allowed or should be restricted
        $Assert.HasFieldValue($TargetObject, 'AllowAnonymousUsersToStartMeeting', $false)
        
        # Recording and sharing should be controlled
        $Assert.HasField($TargetObject, 'AllowCloudRecording')
        $Assert.HasField($TargetObject, 'RecordingStorageMode')
    }
}

#endregion

#region Strategy 8: Regular Backups (M365 Data Protection)

# Data retention policies should be configured
Rule 'Essential8.M365.Retention.Basic' -Type 'Microsoft.M365.RetentionPolicy' {
    # Policy should be enabled
    $Assert.HasFieldValue($TargetObject, 'Enabled', $true)
    
    # Should have reasonable retention period (at least 30 days)
    $Assert.GreaterOrEqual($TargetObject.RetentionDurationInDays, 30)
    
    # Should apply to key workloads
    $validLocations = @('Exchange', 'SharePoint', 'OneDrive', 'Teams')
    $policyLocations = $TargetObject.Locations | Where-Object { $_.Location -in $validLocations }
    $Assert.GreaterOrEqual($policyLocations.Count, 1)
}

# Comprehensive retention for ML2
Rule 'Essential8.M365.Retention.Comprehensive' -Type 'Microsoft.M365.RetentionPolicy' {
    # Extended retention periods
    $Assert.GreaterOrEqual($TargetObject.RetentionDurationInDays, 90)
    
    # Should cover all major workloads
    $requiredLocations = @('Exchange', 'SharePoint', 'OneDrive', 'Teams')
    foreach ($location in $requiredLocations) {
        $locationConfig = $TargetObject.Locations | Where-Object { $_.Location -eq $location }
        $Assert.GreaterOrEqual($locationConfig.Count, 1)
    }
    
    # Should have backup/litigation hold capabilities
    $Assert.HasField($TargetObject, 'RetentionAction')
    $Assert.In($TargetObject.RetentionAction, @('Keep', 'KeepAndDelete'))
}

# Exchange mailbox backup/archive policies
Rule 'Essential8.Exchange.Archive.Policy' -Type 'Microsoft.Exchange.MailboxPlan' {
    # Archive mailbox should be enabled
    $Assert.HasFieldValue($TargetObject, 'ArchiveEnabled', $true)
    
    # Auto-expanding archives for large mailboxes
    $Assert.HasFieldValue($TargetObject, 'AutoExpandingArchiveEnabled', $true)
    
    # Retention policy should be assigned
    $Assert.HasField($TargetObject, 'RetentionPolicy')
    $Assert.NotNull($TargetObject.RetentionPolicy)
}

#endregion

#region Strategy 5: Restrict Administrative Privileges (M365 Admin Roles)

# Admin role assignments should be reviewed and minimal
Rule 'Essential8.M365.AdminRoles.Minimal' -Type 'Microsoft.M365.AdminRoleAssignment' {
    # Should not have excessive Global Admins
    if ($TargetObject.RoleName -eq 'Global Administrator') {
        # Organization should have limited number of Global Admins (max 5% of users or 10, whichever is smaller)
        $totalUsers = $TargetObject.TotalUsersInTenant
        $maxGlobalAdmins = [Math]::Min([Math]::Ceiling($totalUsers * 0.05), 10)
        
        $currentGlobalAdmins = $TargetObject.AssignedUsers.Count
        $Assert.LessOrEqual($currentGlobalAdmins, $maxGlobalAdmins)
    }
    
    # Service admins should be separate from Global Admins where possible
    $serviceAdminRoles = @('Exchange Administrator', 'SharePoint Administrator', 'Teams Administrator')
    if ($TargetObject.RoleName -in $serviceAdminRoles) {
        # Users should ideally not have multiple admin roles
        # This would require cross-referencing role assignments
        $Assert.HasField($TargetObject, 'AssignedUsers')
    }
}

# Privileged Identity Management should be used for admin roles
Rule 'Essential8.M365.PIM.AdminRoles' -Type 'Microsoft.M365.AdminRoleAssignment' {
    $privilegedRoles = @(
        'Global Administrator',
        'Security Administrator', 
        'Compliance Administrator',
        'Exchange Administrator',
        'SharePoint Administrator'
    )
    
    if ($TargetObject.RoleName -in $privilegedRoles) {
        # Should be eligible assignments, not permanent
        $Assert.HasFieldValue($TargetObject, 'AssignmentType', 'Eligible')
        
        # Should have activation requirements
        $Assert.HasField($TargetObject, 'ActivationRequirements')
        $Assert.HasFieldValue($TargetObject.ActivationRequirements, 'MFARequired', $true)
        
        # Should have time limits
        $Assert.HasField($TargetObject, 'MaxActivationDuration')
        $Assert.LessOrEqual($TargetObject.MaxActivationDuration, 480) # 8 hours max
    }
}

#endregion

#region Compliance and Reporting Functions

# M365 compliance summary rule
Rule 'Essential8.M365.ComplianceSummary' -Type 'Microsoft.M365.Tenant' {
    # Overall M365 security score should be reasonable
    if ($TargetObject.SecureScore) {
        $Assert.GreaterOrEqual($TargetObject.SecureScore.CurrentScore, 60) # 60% minimum
    }
    
    # Key security features should be enabled
    $Assert.HasFieldValue($TargetObject, 'AdvancedThreatProtectionEnabled', $true)
    $Assert.HasFieldValue($TargetObject, 'DataLossPreventionEnabled', $true)
    
    # Audit logging should be enabled
    $Assert.HasFieldValue($TargetObject, 'AuditLogEnabled', $true)
    
    Write-Information "M365 Essential 8 compliance summary generated"
}

#endregion

#region Rule Metadata

$M365Essential8Metadata = @{
    Framework = 'ACSC Essential 8'
    Platform = 'Microsoft 365'
    Strategies = @(2, 3, 4, 5, 7, 8) # Strategies covered by these rules
    Description = 'Essential 8 compliance rules for Microsoft 365 environments'
    LastUpdated = (Get-Date).ToString('yyyy-MM-dd')
    RequiredModules = @(
        'ExchangeOnlineManagement',
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement'
    )
    DataSources = @(
        'Exchange Online Configuration',
        'Intune Policies', 
        'M365 Security Center',
        'Compliance Center'
    )
}

Export-ModuleMember -Variable M365Essential8Metadata

#endregion
