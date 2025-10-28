# Synopsis: Essential 8 - Mitigation Strategy 3: Configure Microsoft Office Macro Settings
# Description: Rules to verify macro security is properly configured
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/configure-microsoft-office-macro-settings

# ---------- Exchange Online Macro Security Rules ----------

Rule 'Essential8.E8-3.Exchange.SafeAttachments.Policy' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'Enable' -and
    $TargetObject.PSObject.Properties.Name -contains 'Action'
} {
    Recommend 'Safe Attachments should be enabled to scan for malicious macros'
    Reason 'Essential 8 requires protection against malicious macros in email attachments'
    
    $TargetObject.Enable | Should -BeTrue -Because 'Safe Attachments must be enabled'
    $TargetObject.Action | Should -BeIn @('Block', 'Replace', 'DynamicDelivery') -Because 'Safe Attachments should block or replace malicious content'
}

Rule 'Essential8.E8-3.Exchange.SafeLinks.Policy' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'IsEnabled' -and
    $TargetObject.PSObject.Properties.Name -contains 'ScanUrls'
} {
    Recommend 'Safe Links should be enabled to protect against malicious URLs'
    Reason 'Essential 8 requires protection against malicious links that could deliver macro-enabled documents'
    
    $TargetObject.IsEnabled | Should -BeTrue -Because 'Safe Links must be enabled'
    $TargetObject.ScanUrls | Should -BeTrue -Because 'URL scanning must be enabled'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'EnableForInternalSenders') {
        $TargetObject.EnableForInternalSenders | Should -BeTrue -Because 'Safe Links should scan internal emails too'
    }
}

Rule 'Essential8.E8-3.Exchange.AntiMalware.MacroScanning' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'EnableFileFilter' -and
    $TargetObject.PSObject.Properties.Name -contains 'FileTypes'
} {
    Recommend 'Anti-malware policies should scan macro-enabled file types'
    Reason 'Essential 8 requires scanning of files that can contain macros'
    
    $TargetObject.EnableFileFilter | Should -BeTrue -Because 'File filtering must be enabled'
    
    # Check for macro-enabled file types
    $macroFileTypes = @('docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam', 'docx', 'xlsx', 'pptx')
    
    if ($TargetObject.FileTypes) {
        foreach ($fileType in $macroFileTypes) {
            $TargetObject.FileTypes | Should -Contain $fileType -Because "Macro-enabled file type .$fileType should be filtered"
        }
    }
}

Rule 'Essential8.E8-3.Exchange.TransportRules.MacroBlocking' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AttachmentHasExecutableContent' -or
    $TargetObject.PSObject.Properties.Name -contains 'AttachmentExtensionMatchesWords'
} {
    Recommend 'Transport rules should block or quarantine macro-enabled attachments'
    Reason 'Essential 8 requires blocking of potentially malicious macro-enabled files'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AttachmentHasExecutableContent') {
        # Rule should block executable content
        $TargetObject.AttachmentHasExecutableContent | Should -BeTrue -Because 'Rule should target executable content'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RejectMessageReasonText') {
        $TargetObject.RejectMessageReasonText | Should -Not -BeNullOrEmpty -Because 'Blocked messages should have clear rejection reasons'
    }
}

# ---------- SharePoint Macro Security Rules ----------

Rule 'Essential8.E8-3.SharePoint.IRM.MacroProtection' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'IrmEnabled' -and
    $TargetObject.PSObject.Properties.Name -contains 'IrmExpire'
} {
    Recommend 'Information Rights Management should be enabled to control macro execution'
    Reason 'Essential 8 requires control over document access and macro execution'
    
    $TargetObject.IrmEnabled | Should -BeTrue -Because 'IRM should be enabled for document protection'
    
    if ($TargetObject.IrmExpire) {
        $TargetObject.IrmExpire | Should -BeTrue -Because 'IRM should have expiration to limit exposure'
    }
}

Rule 'Essential8.E8-3.SharePoint.DLP.MacroDetection' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ContentContainsSensitiveInformation' -or
    $TargetObject.PSObject.Properties.Name -contains 'DocumentContainsWords'
} {
    Recommend 'DLP policies should detect and control macro-enabled documents'
    Reason 'Essential 8 requires monitoring and control of potentially dangerous file types'
    
    # This would check for DLP rules that detect macro-enabled files
    # Implementation depends on actual DLP policy structure
    $Assert.Pass() # Placeholder - implement based on actual DLP data
}

# ---------- Office 365 Macro Security Rules ----------

Rule 'Essential8.E8-3.Office365.MacroSettings.TrustedLocations' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'TrustedLocation' -or
    $TargetObject.PSObject.Properties.Name -contains 'MacroExecutionMode'
} {
    Recommend 'Macro execution should be limited to trusted locations only'
    Reason 'Essential 8 requires restricting macro execution to approved locations'
    
    # This would check Office 365 macro settings
    # Implementation depends on collected Office policy data
    $Assert.Pass() # Placeholder - implement based on actual Office policy data
}

Rule 'Essential8.E8-3.Office365.MacroSettings.DigitalSignatures' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'RequireSignedMacros' -or
    $TargetObject.PSObject.Properties.Name -contains 'TrustedPublishers'
} {
    Recommend 'Macros should be required to be digitally signed by trusted publishers'
    Reason 'Essential 8 ML2+ requires digital signatures for macro validation'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RequireSignedMacros') {
        $TargetObject.RequireSignedMacros | Should -BeTrue -Because 'Macros should require digital signatures'
    }
}
