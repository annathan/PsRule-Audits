# Synopsis: Essential 8 - Mitigation Strategy 4: User Application Hardening
# Description: Rules to verify user application hardening is properly configured
# Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/user-application-hardening

# ---------- Exchange Online User Hardening Rules ----------

Rule 'Essential8.E8-4.Exchange.OWA.Security' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'WebReadyDocumentViewingOnPublicComputersEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'WebReadyDocumentViewingOnPrivateComputersEnabled'
} {
    Recommend 'Outlook Web Access should have security features enabled'
    Reason 'Essential 8 requires hardening of web-based applications'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'WebReadyDocumentViewingOnPublicComputersEnabled') {
        $TargetObject.WebReadyDocumentViewingOnPublicComputersEnabled | Should -BeFalse -Because 'Document viewing on public computers should be disabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'DirectFileAccessOnPublicComputersEnabled') {
        $TargetObject.DirectFileAccessOnPublicComputersEnabled | Should -BeFalse -Because 'Direct file access on public computers should be disabled'
    }
}

Rule 'Essential8.E8-4.Exchange.ActiveSync.Security' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ActiveSyncEnabled' -and
    $TargetObject.PSObject.Properties.Name -contains 'DevicePasswordEnabled'
} {
    Recommend 'ActiveSync should require device passwords and encryption'
    Reason 'Essential 8 requires mobile device security controls'
    
    if ($TargetObject.ActiveSyncEnabled) {
        $TargetObject.DevicePasswordEnabled | Should -BeTrue -Because 'ActiveSync devices must require passwords'
        
        if ($TargetObject.PSObject.Properties.Name -contains 'DeviceEncryptionEnabled') {
            $TargetObject.DeviceEncryptionEnabled | Should -BeTrue -Because 'ActiveSync devices should require encryption'
        }
        
        if ($TargetObject.PSObject.Properties.Name -contains 'AllowNonProvisionableDevices') {
            $TargetObject.AllowNonProvisionableDevices | Should -BeFalse -Because 'Only manageable devices should be allowed'
        }
    }
}

Rule 'Essential8.E8-4.Exchange.IMAP.POP.Disabled' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'ImapEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'PopEnabled'
} {
    Recommend 'Legacy protocols (IMAP/POP) should be disabled'
    Reason 'Essential 8 requires disabling insecure legacy protocols'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'ImapEnabled') {
        $TargetObject.ImapEnabled | Should -BeFalse -Because 'IMAP should be disabled for security'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'PopEnabled') {
        $TargetObject.PopEnabled | Should -BeFalse -Because 'POP should be disabled for security'
    }
}

# ---------- SharePoint User Hardening Rules ----------

Rule 'Essential8.E8-4.SharePoint.ExternalSharing.Restrictions' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'DefaultSharingLinkType' -and
    $TargetObject.PSObject.Properties.Name -contains 'DefaultLinkPermission'
} {
    Recommend 'SharePoint sharing should use secure defaults'
    Reason 'Essential 8 requires secure configuration of collaboration tools'
    
    $TargetObject.DefaultSharingLinkType | Should -BeIn @('Internal', 'Direct') -Because 'Default sharing should be restricted to internal users'
    $TargetObject.DefaultLinkPermission | Should -Be 'View' -Because 'Default link permission should be view-only'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'RequireAcceptingAccountMatchInvitedAccount') {
        $TargetObject.RequireAcceptingAccountMatchInvitedAccount | Should -BeTrue -Because 'Account matching should be required for external sharing'
    }
}

Rule 'Essential8.E8-4.SharePoint.FileVersioning.Enabled' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'EnableVersioning' -and
    $TargetObject.PSObject.Properties.Name -contains 'MajorVersionLimit'
} {
    Recommend 'File versioning should be enabled for data protection'
    Reason 'Essential 8 requires data protection mechanisms including versioning'
    
    $TargetObject.EnableVersioning | Should -BeTrue -Because 'File versioning must be enabled'
    $TargetObject.MajorVersionLimit | Should -BeGreaterThan 10 -Because 'Sufficient version history should be maintained'
}

# ---------- Teams User Hardening Rules ----------

Rule 'Essential8.E8-4.Teams.ExternalAccess.Controlled' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AllowFederatedUsers' -or
    $TargetObject.PSObject.Properties.Name -contains 'AllowPublicUsers'
} {
    Recommend 'Teams external access should be controlled and restricted'
    Reason 'Essential 8 requires control over external communications'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowPublicUsers') {
        $TargetObject.AllowPublicUsers | Should -BeFalse -Because 'Public user access should be disabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowFederatedUsers') {
        # Federated users can be allowed but should be controlled
        # Check if there are domain restrictions
        if ($TargetObject.PSObject.Properties.Name -contains 'AllowedDomains') {
            $TargetObject.AllowedDomains | Should -Not -BeNullOrEmpty -Because 'If federation is allowed, domains should be restricted'
        }
    }
}

Rule 'Essential8.E8-4.Teams.FileSharing.Security' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'AllowDropBox' -or
    $TargetObject.PSObject.Properties.Name -contains 'AllowGoogleDrive'
} {
    Recommend 'Teams file sharing should be restricted to approved cloud storage'
    Reason 'Essential 8 requires control over data storage and sharing'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowDropBox') {
        $TargetObject.AllowDropBox | Should -BeFalse -Because 'Third-party cloud storage should be disabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowGoogleDrive') {
        $TargetObject.AllowGoogleDrive | Should -BeFalse -Because 'Third-party cloud storage should be disabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'AllowShareFile') {
        $TargetObject.AllowShareFile | Should -BeFalse -Because 'Third-party cloud storage should be disabled'
    }
}

# ---------- Browser Security Rules ----------

Rule 'Essential8.E8-4.Browser.SecuritySettings' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'SmartScreenEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'PopupBlockerEnabled'
} {
    Recommend 'Browser security features should be enabled'
    Reason 'Essential 8 requires hardening of web browsers'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'SmartScreenEnabled') {
        $TargetObject.SmartScreenEnabled | Should -BeTrue -Because 'SmartScreen should be enabled for malware protection'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'PopupBlockerEnabled') {
        $TargetObject.PopupBlockerEnabled | Should -BeTrue -Because 'Popup blocker should be enabled'
    }
}

Rule 'Essential8.E8-4.Browser.PluginSecurity' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'FlashPlayerEnabled' -or
    $TargetObject.PSObject.Properties.Name -contains 'JavaEnabled'
} {
    Recommend 'Insecure browser plugins should be disabled'
    Reason 'Essential 8 requires disabling or restricting insecure browser plugins'
    
    if ($TargetObject.PSObject.Properties.Name -contains 'FlashPlayerEnabled') {
        $TargetObject.FlashPlayerEnabled | Should -BeFalse -Because 'Flash Player should be disabled'
    }
    
    if ($TargetObject.PSObject.Properties.Name -contains 'JavaEnabled') {
        $TargetObject.JavaEnabled | Should -BeFalse -Because 'Java browser plugin should be disabled'
    }
}
