# Synopsis: Essential 8 - Mitigation Strategy 8: Regular Backups
# Description: Rules to verify backup strategies are properly implemented
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/regular-backups

# ---------- SharePoint Backup Rules ----------

Rule 'Essential8.E8-8.SharePoint.Versioning.Enabled' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'EnableVersioning' -and
    $TargetObject.PSObject.Properties.Name -contains 'MajorVersionLimit'
} {
    Recommend 'SharePoint document versioning should be enabled as a backup mechanism'
    Reason 'Essential 8 requires backup mechanisms, SharePoint versioning provides file-level backup capability'
    
    $TargetObject.EnableVersioning | Should -BeTrue -Because 'Document versioning must be enabled for backup protection'
    $TargetObject.MajorVersionLimit | Should -BeGreaterOrEqual 50 -Because 'Sufficient version history should be maintained (minimum 50 versions)'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'MinorVersionLimit') {
        $TargetObject.MinorVersionLimit | Should -BeGreaterOrEqual 10 -Because 'Minor version history should also be maintained'
    }
}

Rule 'Essential8.E8-8.SharePoint.RecycleBin.Configuration' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RecycleBinEnabled' -and
    $TargetObject.PSObject.Properties.Name -contains 'RecycleBinRetentionPeriod'
} {
    Recommend 'SharePoint Recycle Bin should be configured for data recovery'
    Reason 'Essential 8 requires backup and recovery capabilities, Recycle Bin provides deletion protection'
    
    $TargetObject.RecycleBinEnabled | Should -BeTrue -Because 'Recycle Bin must be enabled for data recovery'
    $TargetObject.RecycleBinRetentionPeriod | Should -BeGreaterOrEqual 90 -Because 'Recycle Bin retention should be at least 90 days'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'SecondStageRecycleBinQuota') {
        $TargetObject.SecondStageRecycleBinQuota | Should -BeGreaterOrEqual 50 -Because 'Second-stage recycle bin should have adequate quota'
    }
}

Rule 'Essential8.E8-8.SharePoint.RetentionPolicies' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RetentionEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'RetentionPeriod'
} {
    Recommend 'SharePoint retention policies should preserve data for compliance and recovery'
    Reason 'Essential 8 requires data preservation capabilities for business continuity'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RetentionEnabled') {
        $TargetObject.RetentionEnabled | Should -BeTrue -Because 'Retention policies should be enabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RetentionPeriod') {
        $TargetObject.RetentionPeriod | Should -BeGreaterOrEqual 2555 -Because 'Retention period should be at least 7 years (2555 days) for business data'
    }
}

# ---------- Exchange Online Backup Rules ----------

Rule 'Essential8.E8-8.Exchange.LitigationHold.Enabled' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'LitigationHoldEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'InPlaceHolds'
} {
    Recommend 'Exchange mailboxes should have litigation hold or in-place holds for data preservation'
    Reason 'Essential 8 requires backup and preservation of critical business data including email'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'LitigationHoldEnabled') {
        # For critical users, litigation hold should be enabled
        if ($TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName') {
            # Check if this is a privileged user who should have litigation hold
            $privilegedDomains = @('admin', 'executive', 'manager', 'director', 'ceo', 'cfo', 'cto')
            $isPrivileged = $false
            foreach ($domain in $privilegedDomains) {
                if ($TargetObject.UserPrincipalName -match $domain) {
                    $isPrivileged = $true
                    break
                }
            }
            
            if ($isPrivileged) {
                $TargetObject.LitigationHoldEnabled | Should -BeTrue -Because 'Privileged user mailboxes should have litigation hold enabled'
            }
        }
    }
}

Rule 'Essential8.E8-8.Exchange.MailboxRetention' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RetentionPolicy' -or
    $TargetObject.PSObject.Properties.Name -contains 'RetentionHoldEnabled'
} {
    Recommend 'Exchange mailboxes should have appropriate retention policies'
    Reason 'Essential 8 requires data retention as part of backup strategy'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RetentionPolicy') {
        $TargetObject.RetentionPolicy | Should -Not -BeNullOrEmpty -Because 'Mailboxes should have retention policies assigned'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RetentionHoldEnabled') {
        # Retention hold can be enabled for additional protection
        # This is not mandatory but recommended for critical data
    }
}

Rule 'Essential8.E8-8.Exchange.ArchiveMailbox' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ArchiveStatus' -or
    $TargetObject.PSObject.Properties.Name -contains 'AutoExpandingArchiveEnabled'
} {
    Recommend 'Exchange archive mailboxes should be enabled for long-term data retention'
    Reason 'Essential 8 requires long-term data preservation, archive mailboxes provide this capability'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'ArchiveStatus') {
        $TargetObject.ArchiveStatus | Should -BeIn @('Active', 'Enabled') -Because 'Archive mailboxes should be enabled for data retention'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AutoExpandingArchiveEnabled') {
        $TargetObject.AutoExpandingArchiveEnabled | Should -BeTrue -Because 'Auto-expanding archives should be enabled to prevent data loss'
    }
}

# ---------- OneDrive Backup Rules ----------

Rule 'Essential8.E8-8.OneDrive.VersionHistory' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'VersionHistoryEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'VersionRetentionDays'
} {
    Recommend 'OneDrive version history should be enabled and configured appropriately'
    Reason 'Essential 8 requires backup capabilities, OneDrive versioning provides file-level backup'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'VersionHistoryEnabled') {
        $TargetObject.VersionHistoryEnabled | Should -BeTrue -Because 'OneDrive version history must be enabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'VersionRetentionDays') {
        $TargetObject.VersionRetentionDays | Should -BeGreaterOrEqual 30 -Because 'Version history should be retained for at least 30 days'
    }
}

Rule 'Essential8.E8-8.OneDrive.RecycleBin' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RecycleBinRetentionDays' -or
    $TargetObject.PSObject.Properties.Name -contains 'OrphanedPersonalSitesRetentionPeriod'
} {
    Recommend 'OneDrive Recycle Bin should be configured for data recovery'
    Reason 'Essential 8 requires recovery mechanisms for accidentally deleted data'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RecycleBinRetentionDays') {
        $TargetObject.RecycleBinRetentionDays | Should -BeGreaterOrEqual 30 -Because 'OneDrive Recycle Bin should retain files for at least 30 days'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'OrphanedPersonalSitesRetentionPeriod') {
        $TargetObject.OrphanedPersonalSitesRetentionPeriod | Should -BeGreaterOrEqual 365 -Because 'Orphaned sites should be retained for at least 1 year'
    }
}

# ---------- Teams Backup Rules ----------

Rule 'Essential8.E8-8.Teams.DataRetention' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RetentionDuration' -or
    $TargetObject.PSObject.Properties.Name -contains 'RetentionAction'
} {
    Recommend 'Teams should have appropriate data retention policies'
    Reason 'Essential 8 requires backup and retention of business communications'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RetentionDuration') {
        $TargetObject.RetentionDuration | Should -BeGreaterOrEqual 2555 -Because 'Teams data should be retained for at least 7 years'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RetentionAction') {
        $TargetObject.RetentionAction | Should -BeIn @('Keep', 'KeepAndDelete') -Because 'Teams data should be kept, not automatically deleted'
    }
}

# ---------- Security & Compliance Backup Rules ----------

Rule 'Essential8.E8-8.Compliance.eDiscovery' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'eDiscoveryEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'ContentSearchEnabled'
} {
    Recommend 'eDiscovery should be enabled for data recovery and compliance'
    Reason 'Essential 8 requires ability to recover and search data, eDiscovery provides this capability'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'eDiscoveryEnabled') {
        $TargetObject.eDiscoveryEnabled | Should -BeTrue -Because 'eDiscovery should be enabled for data recovery'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'ContentSearchEnabled') {
        $TargetObject.ContentSearchEnabled | Should -BeTrue -Because 'Content search should be enabled for data location'
    }
}

Rule 'Essential8.E8-8.Compliance.AuditLog' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AuditLogEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'UnifiedAuditLogIngestionEnabled'
} {
    Recommend 'Audit logging should be enabled for backup verification and compliance'
    Reason 'Essential 8 requires monitoring of backup processes and data access'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AuditLogEnabled') {
        $TargetObject.AuditLogEnabled | Should -BeTrue -Because 'Audit logging must be enabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'UnifiedAuditLogIngestionEnabled') {
        $TargetObject.UnifiedAuditLogIngestionEnabled | Should -BeTrue -Because 'Unified audit log should be enabled'
    }
}

# ---------- Backup Testing and Verification Rules ----------

Rule 'Essential8.E8-8.Backup.TestingProcedures' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'BackupTestingEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'RestoreTestingFrequency'
} {
    Recommend 'Backup testing and restore procedures should be implemented'
    Reason 'Essential 8 requires regular testing of backup and restore procedures'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'BackupTestingEnabled') {
        $TargetObject.BackupTestingEnabled | Should -BeTrue -Because 'Backup testing must be performed regularly'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RestoreTestingFrequency') {
        $TargetObject.RestoreTestingFrequency | Should -BeIn @('Monthly', 'Quarterly') -Because 'Restore testing should be performed at least quarterly'
    }
}
