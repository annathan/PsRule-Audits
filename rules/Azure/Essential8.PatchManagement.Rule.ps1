# Synopsis: Essential 8 - Mitigation Strategies 2 & 6: Patch Applications and Operating Systems
# Description: Rules to verify patch management is properly configured
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/patch-applications
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/patch-operating-systems

# ---------- Application Patching Rules (E8-2) ----------

Rule 'Essential8.E8-2.Applications.UpdatePolicy' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AutoUpdateEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'UpdateFrequency'
} {
    Recommend 'Applications should have automatic updates enabled'
    Reason 'Essential 8 requires timely patching of applications within 48 hours for extreme risk vulnerabilities'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AutoUpdateEnabled') {
        $TargetObject.AutoUpdateEnabled | Should -BeTrue -Because 'Automatic updates should be enabled for applications'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'UpdateFrequency') {
        $TargetObject.UpdateFrequency | Should -BeIn @('Daily', 'Weekly') -Because 'Update frequency should be at least weekly'
    }
}

Rule 'Essential8.E8-2.Office365.UpdateChannel' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UpdateChannel' -or
    $TargetObject.PSObject.Properties.Name -contains 'OfficeUpdateEnabled'
} {
    Recommend 'Office 365 should use Current Channel for fastest security updates'
    Reason 'Essential 8 requires timely application patching, Office Current Channel provides fastest updates'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'UpdateChannel') {
        $TargetObject.UpdateChannel | Should -BeIn @('Current', 'MonthlyEnterprise') -Because 'Office should use Current or Monthly Enterprise Channel for timely updates'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'OfficeUpdateEnabled') {
        $TargetObject.OfficeUpdateEnabled | Should -BeTrue -Because 'Office updates must be enabled'
    }
}

Rule 'Essential8.E8-2.Browser.AutoUpdate' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'BrowserAutoUpdateEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'ChromeUpdatePolicy'
} {
    Recommend 'Web browsers should have automatic updates enabled'
    Reason 'Essential 8 requires patching of internet-facing applications like browsers within 48 hours'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'BrowserAutoUpdateEnabled') {
        $TargetObject.BrowserAutoUpdateEnabled | Should -BeTrue -Because 'Browser auto-updates must be enabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'ChromeUpdatePolicy') {
        $TargetObject.ChromeUpdatePolicy | Should -BeIn @('Enabled', 'AutomaticUpdatesEnabled') -Because 'Chrome should have automatic updates enabled'
    }
}

Rule 'Essential8.E8-2.ThirdParty.UpdateManagement' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ThirdPartyUpdatesEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'VulnerabilityScanning'
} {
    Recommend 'Third-party applications should be included in update management'
    Reason 'Essential 8 requires comprehensive application patching including third-party software'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'ThirdPartyUpdatesEnabled') {
        $TargetObject.ThirdPartyUpdatesEnabled | Should -BeTrue -Because 'Third-party application updates should be managed'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'VulnerabilityScanning') {
        $TargetObject.VulnerabilityScanning | Should -BeTrue -Because 'Vulnerability scanning should identify outdated applications'
    }
}

# ---------- Operating System Patching Rules (E8-6) ----------

Rule 'Essential8.E8-6.Windows.UpdatePolicy' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'WindowsUpdateEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'AutomaticUpdatesEnabled'
} {
    Recommend 'Windows automatic updates should be enabled'
    Reason 'Essential 8 requires OS patching within 48 hours for extreme risk vulnerabilities'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'WindowsUpdateEnabled') {
        $TargetObject.WindowsUpdateEnabled | Should -BeTrue -Because 'Windows Update must be enabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AutomaticUpdatesEnabled') {
        $TargetObject.AutomaticUpdatesEnabled | Should -BeTrue -Because 'Automatic updates should be enabled'
    }
}

Rule 'Essential8.E8-6.WSUS.Configuration' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'WSUSServer' -or
    $TargetObject.PSObject.Properties.Name -contains 'UpdateServerURL'
} {
    Recommend 'WSUS should be properly configured for centralized update management'
    Reason 'Essential 8 allows centralized patch management through WSUS for controlled environments'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'WSUSServer') {
        $TargetObject.WSUSServer | Should -Not -BeNullOrEmpty -Because 'WSUS server should be configured'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AutomaticInstallTime') {
        # Updates should be installed outside business hours
        $TargetObject.AutomaticInstallTime | Should -BeIn @('2', '3', '4', '5') -Because 'Updates should be installed outside business hours (2-5 AM)'
    }
}

Rule 'Essential8.E8-6.SecurityUpdates.Priority' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'SecurityUpdatesEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'CriticalUpdatesEnabled'
} {
    Recommend 'Security and critical updates should be prioritized'
    Reason 'Essential 8 requires prioritization of security updates for timely installation'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'SecurityUpdatesEnabled') {
        $TargetObject.SecurityUpdatesEnabled | Should -BeTrue -Because 'Security updates must be enabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'CriticalUpdatesEnabled') {
        $TargetObject.CriticalUpdatesEnabled | Should -BeTrue -Because 'Critical updates must be enabled'
    }
}

Rule 'Essential8.E8-6.Intune.UpdateRings' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UpdateRingName' -or
    $TargetObject.PSObject.Properties.Name -contains 'DeferralPeriod'
} {
    Recommend 'Intune update rings should minimize deferral periods for security updates'
    Reason 'Essential 8 requires timely OS patching, excessive deferrals increase risk'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'DeferralPeriod') {
        # Security updates should not be deferred more than 7 days
        $TargetObject.DeferralPeriod | Should -BeLessOrEqual 7 -Because 'Security update deferral should not exceed 7 days'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'QualityUpdatesDeferralPeriod') {
        $TargetObject.QualityUpdatesDeferralPeriod | Should -BeLessOrEqual 7 -Because 'Quality update deferral should be minimal'
    }
}

# ---------- Patch Management Process Rules ----------

Rule 'Essential8.E8-2-6.PatchManagement.Testing' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'TestingGroupEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'PilotDeployment'
} {
    Recommend 'Patch management should include testing procedures'
    Reason 'Essential 8 allows testing of patches but requires timely deployment after testing'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'TestingGroupEnabled') {
        $TargetObject.TestingGroupEnabled | Should -BeTrue -Because 'Patch testing should be implemented'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'TestingDuration') {
        # Testing should not delay critical patches beyond Essential 8 timeframes
        $TargetObject.TestingDuration | Should -BeLessOrEqual 48 -Because 'Testing should not delay critical patches beyond 48 hours'
    }
}

Rule 'Essential8.E8-2-6.VulnerabilityManagement' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'VulnerabilityAssessment' -or
    $TargetObject.PSObject.Properties.Name -contains 'PatchComplianceReporting'
} {
    Recommend 'Vulnerability management should track patch compliance'
    Reason 'Essential 8 requires monitoring and reporting of patch status'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'VulnerabilityAssessment') {
        $TargetObject.VulnerabilityAssessment | Should -BeTrue -Because 'Regular vulnerability assessment should be performed'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'PatchComplianceReporting') {
        $TargetObject.PatchComplianceReporting | Should -BeTrue -Because 'Patch compliance should be monitored and reported'
    }
}
