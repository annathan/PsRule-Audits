# Essential 8 Compliance Audit Tool

## 🎯 What is This?

This tool automatically assesses your Microsoft 365 / Azure environment against the **Australian Cyber Security Centre (ACSC) Essential 8** framework. It helps you:

- **Identify security gaps** in your configuration
- **Track compliance progress** over time
- **Generate professional reports** for management and auditors
- **Prioritize remediation** efforts based on risk

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Global Administrator or Global Reader access to your Microsoft 365 tenant
- Internet connection

### Step 1: Download or Clone

```powershell
# Clone the repository
git clone https://github.com/yourorg/PsRule-Audits.git
cd PsRule-Audits

# Or download and extract the ZIP file
```

### Step 2: Install Prerequisites

Run the installation script (only needed once):

```powershell
.\Install-Prerequisites.ps1
```

This will install required PowerShell modules:
- PSRule
- Microsoft.Graph (various modules)
- ExchangeOnlineManagement
- PnP.PowerShell

### Step 3: Run Your First Audit

```powershell
.\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com"
```

**What happens:**
1. You'll be prompted to sign in to Microsoft 365 (uses your browser)
2. Configuration data is collected from your tenant (~5-10 minutes)
3. Compliance checks are run against Essential 8 requirements
4. An HTML report is generated and opened automatically

That's it! 🎉

## 📊 Understanding Your Results

### Compliance Score

Your overall score is calculated as:
```
(Rules Passed / Total Rules) × 100
```

**Score Guide:**
- **80-100%**: Excellent - Strong Essential 8 posture
- **60-79%**: Good - Some improvements needed
- **40-59%**: Fair - Significant gaps exist
- **< 40%**: Needs Attention - Priority remediation required

### Maturity Levels

The Essential 8 defines three maturity levels:

#### Maturity Level 1 (ML1) - Baseline
- Basic implementation
- Suitable for small businesses
- Protects against commodity threats

#### Maturity Level 2 (ML2) - Recommended ⭐
- **Default for this tool**
- Suitable for most organizations
- Required for Australian Government
- Protects against sophisticated threats

#### Maturity Level 3 (ML3) - Advanced
- Comprehensive implementation
- Suitable for high-security environments
- Protects against advanced persistent threats

To test against different maturity levels:

```powershell
# Level 1 - Baseline
.\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com" -MaturityLevel ML1

# Level 3 - Advanced
.\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com" -MaturityLevel ML3
```

## 📈 Tracking Progress Over Time

Every time you run an audit, the results are saved to `Essential8-Reports\History\`. This allows you to:

- **Track improvements** as you remediate issues
- **Demonstrate progress** to management
- **Identify trends** in your security posture

The HTML report automatically includes a trend chart showing your compliance score history.

**Recommended Schedule:**
- Initial audit: Run immediately
- Follow-up: Weekly during active remediation
- Ongoing: Monthly or quarterly for monitoring

## 🎯 The Essential 8 Strategies

Your environment is assessed against these eight mitigation strategies:

| Strategy | What It Checks |
|----------|----------------|
| **E8-1: Application Control** | Whitelisting and control of approved applications |
| **E8-2: Patch Applications** | Timely patching of applications |
| **E8-3: Macro Security** | Blocking macros from untrusted sources |
| **E8-4: User Hardening** | Web browser and Office application hardening |
| **E8-5: Admin Privileges** | Restriction and monitoring of privileged access |
| **E8-6: Patch Operating Systems** | Timely patching of operating systems |
| **E8-7: Multi-Factor Authentication** | MFA for all users, especially privileged accounts |
| **E8-8: Regular Backups** | Backup and recovery capabilities |

## 🔧 Advanced Usage

### Re-Run Analysis Without Data Collection

If you've already collected data and just want to re-run the analysis:

```powershell
.\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com" -SkipDataCollection
```

### Collect Data Only (For Offline Analysis)

```powershell
.\Collectors\Essential8-DataCollector.ps1 -TenantId "yourcompany.onmicrosoft.com"
```

### Custom Output Location

```powershell
.\Run-Essential8Audit.ps1 `
    -TenantId "yourcompany.onmicrosoft.com" `
    -OutputPath "C:\AuditsCompany\Client-Reports"
```

### Selective Data Collection

```powershell
.\Collectors\Essential8-DataCollector.ps1 `
    -TenantId "yourcompany.onmicrosoft.com" `
    -Services AzureAD,Exchange
```

Options: `All`, `AzureAD`, `Exchange`, `SharePoint`, `Security`

## 🔒 Security & Privacy

### What Data Is Collected?

The tool collects **configuration data only** - no user content or personal communications:

- User accounts and MFA status (UPN only, no passwords)
- Conditional Access policies
- Exchange security policies
- SharePoint sharing settings
- Service principal configurations
- Administrative role assignments

### Where Is Data Stored?

All data is stored **locally on your machine** in the `Essential8-Data` and `Essential8-Reports` folders. Nothing is sent to external servers or cloud services.

### Required Permissions

Minimum permissions needed:
- **Global Reader** role (read-only access) - Recommended ✓
- **Security Reader** role

Alternatively:
- **Global Administrator** (if Global Reader is not available)

## 📋 Common Issues & Troubleshooting

### "Module not found" Error

```powershell
# Install missing modules
Install-Module PSRule, Microsoft.Graph, ExchangeOnlineManagement, PnP.PowerShell -Force
```

### Authentication Fails

1. Ensure you have appropriate permissions (Global Reader or Global Administrator)
2. Check that modern authentication is enabled in your tenant
3. Try using an InPrivate/Incognito browser window when prompted to sign in

### No Data Collected

- Verify you're using the correct tenant ID
- Check network connectivity
- Ensure the account has appropriate permissions
- Review error messages in PowerShell output

### Rules Not Running

- Ensure PSRule module is installed: `Get-Module PSRule -ListAvailable`
- Check that data was successfully collected in `Essential8-Data` folder
- Verify JSON files are not empty

## 📞 Support & Contributing

### Getting Help

1. Check the [Implementation Guide](Implementation_Guide.md) for detailed information
2. Review [example reports](examples/) to understand expected output
3. Open an issue on GitHub with:
   - PowerShell version: `$PSVersionTable.PSVersion`
   - Error messages
   - Steps to reproduce

### Contributing

Contributions welcome! Areas for improvement:
- Additional rules for new Essential 8 guidance
- Enhanced reporting visualizations
- Integration with security tools (Sentinel, Defender)
- Power Platform assessment rules

## 📚 Additional Resources

- **Essential 8 Overview**: https://www.cyber.gov.au/acsc/view-all-content/essential-eight
- **Maturity Model**: https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model
- **PSRule Documentation**: https://microsoft.github.io/PSRule/

## ⚖️ License

This tool is provided under the MIT License. See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Australian Cyber Security Centre (ACSC) for the Essential 8 framework
- Microsoft PSRule team for the rules engine
- Microsoft Graph and PowerShell teams for the APIs

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║                    Audit Completed Successfully                  ║
╚══════════════════════════════════════════════════════════════════╝

Duration: 8.3 minutes
Compliance Score: 72.5% (58/80 rules passed)

Reports saved to: .\Essential8-Reports\20250101-143025\

Open report: .\Essential8-Reports\20250101-143025\Essential8-Report.html
```

**Report includes:**
- Overall compliance score with visual indicators
- Results by Essential 8 strategy
- Detailed findings for each rule
- Historical trend (if multiple audits run)
- Actionable recommendations

---

**Ready to improve your security posture? Run your first audit now! 🚀**

```powershell
.\Run-Essential8Audit.ps1 -TenantId "yourcompany.onmicrosoft.com"
```

