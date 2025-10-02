# Synopsis: Essential 8 - Mitigation Strategies 2 & 6: Patch Applications and Operating Systems
# Description: Rules to verify patch management processes are in place
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/patch-applications
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/patch-operating-systems

# ---------------------------------------------------------------------------------------------------
# Rule: Security updates should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-2.M365.Updates.SecurityUpdatesEnabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AutoUpdate'
} {
    Recommend 'Automatic security updates should be enabled'
    Reason 'Essential 8 requires timely patching of applications and operating systems'
    
    $autoUpdateEnabled = $False
    if ($TargetObject.AutoUpdate -eq $True) {
        $autoUpdateEnabled = $True
    }
    
    $Assert.Create($autoUpdateEnabled, 'Automatic updates are not enabled')
    
} -Tag @{ 
    E8 = 'E8-2'
    Category = 'Patch Management'
    Severity = 'Critical'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Review update compliance regularly
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-6.M365.Updates.ComplianceMonitoring' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UpdateStatus'
} {
    Recommend 'Monitor and report on patch compliance across all systems'
    Reason 'Essential 8 requires visibility into patch status to ensure timely updates'
    
    # Check update status
    $isCompliant = $False
    if ($TargetObject.UpdateStatus -in @('Compliant', 'UpToDate', 'Current')) {
        $isCompliant = $True
    }
    
    $Assert.Create($isCompliant, "System update status is '$($TargetObject.UpdateStatus)' - patches may be missing")
    
} -Tag @{ 
    E8 = 'E8-6'
    Category = 'Patch Management'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Critical patches should be applied within timeframes
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-2.M365.Updates.TimelyPatching' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'LastUpdateTime'
} {
    Recommend 'Critical and high severity patches should be applied within 48 hours'
    Reason 'Essential 8 ML2 requires extreme risk vulnerabilities patched within 48 hours'
    
    if ($TargetObject.LastUpdateTime) {
        $lastUpdate = [DateTime]$TargetObject.LastUpdateTime
        $daysSinceUpdate = ((Get-Date) - $lastUpdate).Days
        
        # Warning if not updated in 30 days
        $Assert.LessOrEqual($daysSinceUpdate, '.', 30, "System has not been updated in $daysSinceUpdate days - should be updated regularly")
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-2'
    Category = 'Patch Management'
    Severity = 'High'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Vulnerability scanning should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-2.M365.VulnerabilityScanning.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'VulnerabilityAssessment'
} {
    Recommend 'Enable vulnerability scanning to identify missing patches'
    Reason 'Vulnerability scanning provides visibility into patch gaps'
    
    $scanningEnabled = $False
    if ($TargetObject.VulnerabilityAssessment -eq 'Enabled') {
        $scanningEnabled = $True
    }
    
    $Assert.Create($scanningEnabled, 'Vulnerability assessment is not enabled')
    
} -Tag @{ 
    E8 = 'E8-2'
    Category = 'Patch Management'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

