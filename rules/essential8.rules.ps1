# PSRule PowerShell rules
# Each Rule { } returns $true (pass) or $false (fail) for the $TargetObject being evaluated.

# --- Essential Eight: MFA for Admins (ML2)
Rule 'E8.MFA.AdminsEnabled' -Tag @{ e8 = 'MFA'; maturity = 'ML2' } -Level Error {
    # Expect a boolean flag on the target object
    $TargetObject.mfaForAdmins -eq $true
}

# --- Essential Eight: Regular Backups (ML2) - demo proxy
Rule 'E8.RegularBackups.Enabled' -Tag @{ e8 = 'RegularBackups'; maturity = 'ML2' } -Level Warning {
    # Example: expect a flag saying backups are enabled
    # (Later you’ll bind this to real Azure Backup discovery or exported config)
    $TargetObject.backupsEnabled -eq $true
}
