# Synopsis: Essential 8 - Mitigation Strategy 3: Configure Microsoft Office Macro Settings
# Description: Rules to verify macro execution is properly restricted
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/macro-security

# ---------------------------------------------------------------------------------------------------
# Rule: Block macros from the internet
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-3.Exchange.MacroPolicy.BlockInternet' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'BlockMacros'
} {
    Recommend 'Block macros in Office files from the internet'
    Reason 'Essential 8 requires blocking macros from untrusted sources to prevent malware execution'
    
    $blockMacros = $False
    if ($TargetObject.BlockMacros -eq $True) {
        $blockMacros = $True
    }
    
    $Assert.Create($blockMacros, "Policy '$($TargetObject.Name)' does not block macros from internet sources")
    
} -Tag @{ 
    E8 = 'E8-3'
    Category = 'Macro Security'
    Severity = 'Critical'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Transport rules should block macro-enabled files
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-3.Exchange.TransportRule.BlockMacroFiles' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'State' -and
    $TargetObject.PSObject.Properties.Name -contains 'Description'
} {
    Recommend 'Use transport rules to block email attachments with macros from external sources'
    Reason 'Blocking macro-enabled files at the mail gateway prevents them reaching users'
    
    # Check if this is a macro blocking rule
    $isMacroBlockRule = $False
    $isEnabled = $False
    
    if ($TargetObject.Description -match 'macro|\.xlsm|\.docm|\.pptm|vba|vbscript') {
        $isMacroBlockRule = $True
    }
    
    if ($TargetObject.Name -match 'macro|block.*office|vba') {
        $isMacroBlockRule = $True
    }
    
    if ($TargetObject.State -eq 'Enabled') {
        $isEnabled = $True
    }
    
    if ($isMacroBlockRule) {
        $Assert.Create($isEnabled, "Transport rule '$($TargetObject.Name)' appears to block macros but is not enabled")
    } else {
        $Assert.Pass()
    }
    
} -Tag @{ 
    E8 = 'E8-3'
    Category = 'Macro Security'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Safe Attachments should be enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-3.Exchange.SafeAttachments.Enabled' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'Enable'
} {
    Recommend 'Enable Safe Attachments (Defender for Office 365) to scan files for malicious content'
    Reason 'Safe Attachments provides dynamic scanning of attachments including macro-enabled files'
    
    $isEnabled = $False
    if ($TargetObject.Enable -eq $True) {
        $isEnabled = $True
    }
    
    $Assert.Create($isEnabled, "Safe Attachments policy '$($TargetObject.Name)' is not enabled")
    
} -Tag @{ 
    E8 = 'E8-3'
    Category = 'Macro Security'
    Severity = 'High'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Anti-malware policies should scan Office files
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-3.Exchange.AntiMalware.ScanOfficeFiles' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'EnableFileFilter'
} {
    Recommend 'Anti-malware policies should scan Office documents'
    Reason 'Scanning Office files helps detect malicious macros and embedded threats'
    
    $fileFilterEnabled = $False
    if ($TargetObject.EnableFileFilter -eq $True) {
        $fileFilterEnabled = $True
    }
    
    $Assert.Create($fileFilterEnabled, "Anti-malware policy '$($TargetObject.Name)' does not have file filter enabled")
    
} -Tag @{ 
    E8 = 'E8-3'
    Category = 'Macro Security'
    Severity = 'Medium'
    MaturityLevel = 'ML1'
}

# ---------------------------------------------------------------------------------------------------
# Rule: SharePoint should restrict macro execution
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-3.SharePoint.MacroExecution.Restricted' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Url' -and
    $TargetObject.PSObject.Properties.Name -contains 'DisableCompanyWideSharingLinks'
} {
    Recommend 'Configure SharePoint to restrict macro execution in uploaded documents'
    Reason 'Preventing macro execution in SharePoint reduces risk of stored malware'
    
    # This would require additional data about SharePoint IRM and Office Online settings
    # For now, this is informational
    $Assert.Pass("Review macro execution settings for SharePoint site: $($TargetObject.Url)")
    
} -Tag @{ 
    E8 = 'E8-3'
    Category = 'Macro Security'
    Severity = 'Informational'
    MaturityLevel = 'ML2'
}

# ---------------------------------------------------------------------------------------------------
# Rule: Organization config should have modern authentication enabled
# ---------------------------------------------------------------------------------------------------
Rule 'Essential8.E8-3.Exchange.OrgConfig.ModernAuth' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Name' -and
    $TargetObject.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled'
} {
    Recommend 'Enable modern authentication to support advanced security features'
    Reason 'Modern authentication is required for many macro security and MFA features'
    
    $modernAuthEnabled = $False
    if ($TargetObject.OAuth2ClientProfileEnabled -eq $True) {
        $modernAuthEnabled = $True
    }
    
    $Assert.Create($modernAuthEnabled, 'Modern authentication (OAuth2) is not enabled for the organization')
    
} -Tag @{ 
    E8 = 'E8-3'
    Category = 'Macro Security'
    Severity = 'High'
    MaturityLevel = 'ML1'
}

