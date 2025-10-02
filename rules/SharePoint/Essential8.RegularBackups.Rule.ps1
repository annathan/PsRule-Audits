# Synopsis: Essential 8 - Mitigation Strategy 8: Regular Backups
# Description: Rules to verify backup and recovery capabilities are in place
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/regular-backups

# ---------------------------------------------------------------------------------------------------
# Rule: SharePoint versioning should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-8.SharePoint.Versioning.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Url' -and
    $TargetObject.PSObject.Properties.Name -contains 'EnableVersioning'
} {
    Recommend 'Enable versioning on SharePoint document libraries'
    Reason 'Versioning provides ability to recover from accidental changes or malicious activity'
    
    $versioningEnabled = $False
    if ($TargetObject.EnableVersioning -eq $True) {
        $versioningEnabled = $True
    }
    
    $Assert.Create($versioningEnabled, "SharePoint site '$($TargetObject.Url)' does not have versioning enabled")
    
} -Tag @{ 
    E8 = 'E8-8'
    Category = 'Regular Backups'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Retention policies should be configured
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-8.M365.Retention.Configured' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'Enabled' -and
    $TargetObject.PSObject.Properties.Name -contains 'RetentionDuration'
} {
    Recommend 'Configure retention policies to preserve data for recovery'
    Reason 'Retention policies ensure data can be recovered after deletion or corruption'
    
    $retentionEnabled = $False
    if ($TargetObject.Enabled -eq $True) {
        $retentionEnabled = $True
    }
    
    $Assert.Create($retentionEnabled, "Retention policy '$($TargetObject.Name)' is not enabled")
    
} -Tag @{ 
    E8 = 'E8-8'
    Category = 'Regular Backups'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Recycle bin should be configured with adequate retention
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-8.SharePoint.RecycleBin.Adequate' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RecycleBinRetentionPeriod'
} {
    Recommend 'Configure SharePoint recycle bin retention for at least 30 days'
    Reason 'Adequate recycle bin retention enables recovery from accidental deletions'
    
    $retentionDays = 0
    if ($TargetObject.RecycleBinRetentionPeriod) {
        $retentionDays = $TargetObject.RecycleBinRetentionPeriod
    }
    
    # Minimum 30 days recommended
    $Assert.GreaterOrEqual($retentionDays, '.', 30, "Recycle bin retention is $retentionDays days - should be at least 30 days")
    
} -Tag @{ 
    E8 = 'E8-8'
    Category = 'Regular Backups'
    Severity = 'Medium'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Legal hold or litigation hold should be considered for critical data
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-8.Exchange.LegalHold.CriticalData' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'LitigationHoldEnabled'
} {
    Recommend 'Enable legal hold for critical user mailboxes to prevent data loss'
    Reason 'Legal hold ensures email data cannot be permanently deleted'
    
    # This is informational - legal hold should be applied selectively
    if ($TargetObject.LitigationHoldEnabled -eq $True) {
        $Assert.Pass("Mailbox '$($TargetObject.DisplayName)' has legal hold enabled")
    } else {
        $Assert.Pass("Review: Consider legal hold for critical mailbox '$($TargetObject.DisplayName)'")
    }
    
} -Tag @{ 
    E8 = 'E8-8'
    Category = 'Regular Backups'
    Severity = 'Informational'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Audit logging should be enabled for recovery planning
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-8.M365.AuditLog.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AuditLogAgeLimit' -or
    $TargetObject.PSObject.Properties.Name -contains 'UnifiedAuditLogIngestionEnabled'
} {
    Recommend 'Enable audit logging to support backup verification and recovery procedures'
    Reason 'Audit logs help identify what needs to be restored and verify backup integrity'
    
    $auditEnabled = $False
    if ($TargetObject.UnifiedAuditLogIngestionEnabled -eq $True) {
        $auditEnabled = $True
    }
    
    $Assert.Create($auditEnabled, 'Unified audit logging is not enabled')
    
} -Tag @{ 
    E8 = 'E8-8'
    Category = 'Regular Backups'
    Severity = 'Medium'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Backup testing procedures should be documented
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-8.General.BackupTesting.Documented' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'BackupTestDate'
} {
    Recommend 'Regularly test backup restoration procedures (quarterly minimum)'
    Reason 'Essential 8 requires verification that backups can be successfully restored'
    
    if ($TargetObject.BackupTestDate) {
        $testDate = [DateTime]$TargetObject.BackupTestDate
        $daysSinceTest = ((Get-Date) - $testDate).Days
        
        # Should test at least quarterly (90 days)
        $Assert.LessOrEqual($daysSinceTest, '.', 90, "Backup restoration has not been tested in $daysSinceTest days - should test quarterly")
    } else {
        $Assert.Pass('Document and track backup testing procedures')
    }
    
} -Tag @{ 
    E8 = 'E8-8'
    Category = 'Regular Backups'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

