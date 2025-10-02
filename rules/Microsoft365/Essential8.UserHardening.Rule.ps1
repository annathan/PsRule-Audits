# Synopsis: Essential 8 - Mitigation Strategy 4: User Application Hardening
# Description: Rules to verify web browsers and applications are hardened
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/user-application-hardening

# ---------------------------------------------------------------------------------------------------
# Rule: Safe Links should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-4.Exchange.SafeLinks.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'EnableSafeLinksForEmail'
} {
    Recommend 'Enable Safe Links (Defender for Office 365) to protect against malicious URLs'
    Reason 'Safe Links provides real-time URL scanning to protect users from phishing and malware'
    
    $safeLinksEnabled = $False
    if ($TargetObject.EnableSafeLinksForEmail -eq $True) {
        $safeLinksEnabled = $True
    }
    
    $Assert.Create($safeLinksEnabled, "Safe Links policy '$($TargetObject.Name)' does not protect email")
    
} -Tag @{ 
    E8 = 'E8-4'
    Category = 'User Application Hardening'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Web content filtering should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-4.Exchange.ContentFilter.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'EnableEndUserSpamNotifications'
} {
    Recommend 'Enable web content filtering and spam protection'
    Reason 'Content filtering helps block malicious content before it reaches users'
    
    $filteringEnabled = $False
    if ($TargetObject.EnableEndUserSpamNotifications -ne $null) {
        $filteringEnabled = $True
    }
    
    $Assert.Create($filteringEnabled, 'Content filtering policy is not properly configured')
    
} -Tag @{ 
    E8 = 'E8-4'
    Category = 'User Application Hardening'
    Severity = 'Medium'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Flash, Java, and browser plugins should be disabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-4.M365.BrowserPlugins.Disabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'BlockAdobeFlash' -or
    $TargetObject.PSObject.Properties.Name -contains 'BlockJava'
} {
    Recommend 'Disable or remove Flash, Java, and other vulnerable browser plugins'
    Reason 'These plugins are common attack vectors and should be disabled'
    
    $flashBlocked = $True
    if ($TargetObject.PSObject.Properties.Name -contains 'BlockAdobeFlash') {
        $flashBlocked = $TargetObject.BlockAdobeFlash -eq $True
    }
    
    $Assert.Create($flashBlocked, 'Adobe Flash is not blocked - should be disabled')
    
} -Tag @{ 
    E8 = 'E8-4'
    Category = 'User Application Hardening'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Anti-phishing policies should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-4.Exchange.AntiPhishing.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Enabled' -and
    $TargetObject.PSObject.Properties.Name -contains 'ImpersonationProtectionState'
} {
    Recommend 'Enable anti-phishing protection with impersonation detection'
    Reason 'Anti-phishing policies protect users from social engineering attacks'
    
    $antiPhishingEnabled = $False
    if ($TargetObject.Enabled -eq $True) {
        $antiPhishingEnabled = $True
    }
    
    $Assert.Create($antiPhishingEnabled, 'Anti-phishing policy is not enabled')
    
} -Tag @{ 
    E8 = 'E8-4'
    Category = 'User Application Hardening'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Browser should block unsafe downloads
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-4.M365.Browser.BlockUnsafeDownloads' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'BlockUnsafeDownloads'
} {
    Recommend 'Configure browsers to block potentially unsafe file downloads'
    Reason 'Blocking unsafe downloads reduces malware infection risk'
    
    $blocksUnsafe = $False
    if ($TargetObject.BlockUnsafeDownloads -eq $True) {
        $blocksUnsafe = $True
    }
    
    $Assert.Create($blocksUnsafe, 'Browser is not configured to block unsafe downloads')
    
} -Tag @{ 
    E8 = 'E8-4'
    Category = 'User Application Hardening'
    Severity = 'Medium'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: External email warnings should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-4.Exchange.ExternalSender.Warning' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ExternalInOutlook'
} {
    Recommend 'Enable external sender warnings to help users identify external emails'
    Reason 'Visual indicators help users identify potentially malicious external emails'
    
    $warningEnabled = $False
    if ($TargetObject.ExternalInOutlook -eq 'Enabled') {
        $warningEnabled = $True
    }
    
    $Assert.Create($warningEnabled, 'External sender warnings are not enabled')
    
} -Tag @{ 
    E8 = 'E8-4'
    Category = 'User Application Hardening'
    Severity = 'Medium'
    MaturityLevel = 'ML1'
}

