Rule ''E8.MFA.AdminsEnabled'' -Tag @{ e8 = ''MFA''; maturity = ''ML2'' } -Level Error {
    $TargetObject.mfaForAdmins -eq $true
}
Rule ''E8.RegularBackups.Enabled'' -Tag @{ e8 = ''RegularBackups''; maturity = ''ML2'' } -Level Warning {
    $TargetObject.backupsEnabled -eq $true
}
