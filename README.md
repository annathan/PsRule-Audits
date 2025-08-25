# Essential 8 PSRule Audit Framework

## Overview
This framework provides automated compliance auditing for the Australian Cyber Security Centre (ACSC) Essential 8 mitigation strategies across Microsoft cloud environments (Azure, Microsoft 365, SharePoint).

## Essential 8 Strategies & Microsoft Cloud Mapping

### 1. Application Control
**Objective**: Prevent execution of unapproved/malicious applications
**Microsoft Services**:
- **Azure**: App Service, Azure Functions, Container Instances, Virtual Machines
- **Microsoft 365**: Microsoft Defender Application Guard, Windows Defender Application Control
- **SharePoint**: SharePoint Apps, Power Platform governance

**Key Audit Checks**:
- Application whitelisting policies enabled
- Code signing certificate validation
- Container image scanning and approval
- PowerShell execution policies
- Script execution restrictions

### 2. Patch Applications
**Objective**: Patch security vulnerabilities in applications within 48 hours for extreme risk
**Microsoft Services**:
- **Azure**: Update Management, Azure Security Center, Azure Policy
- **Microsoft 365**: Microsoft Update, Windows Update for Business
- **SharePoint**: SharePoint updates, Power Platform version management

**Key Audit Checks**:
- Automated patching enabled
- Critical patch deployment timeline compliance
- Vulnerability assessment integration
- Update approval workflows
- Patch testing procedures

### 3. Configure Microsoft Office Macro Settings
**Objective**: Block macros from the internet and untrusted sources
**Microsoft Services**:
- **Microsoft 365**: Group Policy, Intune policies, Security & Compliance Center
- **SharePoint**: Document libraries macro restrictions

**Key Audit Checks**:
- Macro execution policies (VBA, Excel, Word, PowerPoint)
- Trusted locations configuration
- Digital signature requirements for macros
- Macro warning settings
- Alternative solutions to macros implemented

### 4. User Application Hardening
**Objective**: Configure applications to reduce attack surface
**Microsoft Services**:
- **Azure**: Azure Policy, Security Center recommendations
- **Microsoft 365**: Edge browser policies, Internet Explorer settings
- **SharePoint**: Browser compatibility settings

**Key Audit Checks**:
- Web browser security settings
- Plugin/add-on restrictions (Flash, Java, ActiveX)
- Pop-up blocker configuration
- Safe browsing features enabled
- Automatic update settings

### 5. Restrict Administrative Privileges
**Objective**: Limit users with administrative privileges
**Microsoft Services**:
- **Azure**: RBAC, Privileged Identity Management (PIM), Azure AD
- **Microsoft 365**: Admin roles, Privileged Access Management
- **SharePoint**: Site collection admin permissions, farm admin access

**Key Audit Checks**:
- Privileged account inventory and justification
- Time-bound administrative access (PIM)
- Multi-factor authentication on admin accounts
- Regular access reviews
- Separation of duties implementation
- Emergency access account procedures

### 6. Patch Operating Systems
**Objective**: Patch security vulnerabilities in operating systems
**Microsoft Services**:
- **Azure**: Update Management, Azure Security Center, VM patching
- **Microsoft 365**: Windows Update policies, Intune management
- **Infrastructure**: Server patching schedules

**Key Audit Checks**:
- Automated OS patching enabled
- Critical security update deployment timelines
- Patch testing and rollback procedures
- System reboot management
- Legacy system patch management

### 7. Multi-factor Authentication
**Objective**: Strengthen user authentication
**Microsoft Services**:
- **Azure**: Azure AD MFA, Conditional Access
- **Microsoft 365**: MFA policies, modern authentication
- **SharePoint**: Authentication providers, external sharing controls

**Key Audit Checks**:
- MFA enabled for all users (especially privileged accounts)
- Authentication methods approved (avoid SMS where possible)
- Conditional access policies implemented
- Legacy authentication blocked
- Guest user MFA requirements
- Service account authentication

### 8. Regular Backups
**Objective**: Ensure data availability and recovery capability
**Microsoft Services**:
- **Azure**: Azure Backup, Site Recovery, Storage redundancy
- **Microsoft 365**: Data retention policies, legal hold, recycle bin settings
- **SharePoint**: Backup and restore capabilities, versioning

**Key Audit Checks**:
- Automated backup schedules configured
- Backup testing and restoration procedures
- Recovery time/point objectives defined and met
- Backup storage security and encryption
- Offline backup copies maintained
- Business continuity plan testing

## Maturity Levels Implementation

### Maturity Level 1 (Baseline)
- Basic implementation of each strategy
- Manual processes acceptable
- Partial coverage of assets

### Maturity Level 2 (Target for Government)
- Automated implementation where possible
- Comprehensive coverage of critical assets
- Regular monitoring and reporting

### Maturity Level 3 (Advanced)
- Fully automated and integrated implementation
- Continuous monitoring and improvement
- Complete asset coverage with exception management

## PSRule Implementation Structure

### Directory Structure
```
PsRule-Audits/
├── rules/
│   ├── Azure/
│   │   ├── Essential8.Application.Control.Rule.ps1
│   │   ├── Essential8.Patch.Management.Rule.ps1
│   │   └── ...
│   ├── Microsoft365/
│   │   ├── Essential8.MFA.Rule.ps1
│   │   ├── Essential8.Macro.Security.Rule.ps1
│   │   └── ...
│   └── SharePoint/
│       ├── Essential8.Admin.Access.Rule.ps1
│       ├── Essential8.Backup.Rule.ps1
│       └── ...
├── baselines/
│   ├── Essential8.Baseline.Rule.ps1
│   ├── Essential8.ML1.Baseline.Rule.ps1
│   ├── Essential8.ML2.Baseline.Rule.ps1
│   └── Essential8.ML3.Baseline.Rule.ps1
├── data/
│   ├── collectors/
│   └── templates/
├── docs/
│   ├── implementation-guide.md
│   ├── compliance-mapping.md
│   └── remediation-guidance.md
└── examples/
    ├── azure-audit-pipeline.yml
    ├── m365-compliance-check.ps1
    └── sharepoint-security-scan.ps1
```

### Key Configuration Files

#### ps-rule.yaml
```yaml
# Configuration for Essential 8 PSRule execution
execution:
  mode: 'strict'
  
baseline:
  - 'Essential8.ML2.Baseline'

rule:
  exclude: []
  include:
    - 'Essential8.*'

output:
  format: 'NUnit3'
  path: './reports/essential8-compliance.xml'

input:
  pathIgnore: []
  format: 'Auto'
```

## Data Collection Approach

### Azure Resources
- Use Azure Resource Graph queries
- Azure Policy compliance data
- Security Center recommendations
- Azure AD reports and logs

### Microsoft 365
- Microsoft Graph API calls
- Security & Compliance Center data
- Admin center reports
- PowerShell cmdlets (Exchange Online, SharePoint Online, etc.)

### SharePoint
- SharePoint Online Management Shell
- Site collection audit logs
- Permission reports
- Configuration databases

## Reporting & Remediation

### Compliance Dashboard
- Overall Essential 8 maturity score
- Individual strategy compliance status
- Trending and historical data
- Risk prioritization

### Remediation Guidance
- Specific configuration steps
- PowerShell scripts for fixes
- Policy templates
- Best practice recommendations

### Integration Points
- Azure DevOps pipelines
- GitHub Actions
- Microsoft Sentinel (for monitoring)
- Power BI (for reporting)

## Next Steps for Implementation

1. **Start with Core Rules**: Begin with high-impact, easily auditable controls
2. **Data Collection Scripts**: Build collectors for each Microsoft service
3. **Baseline Definitions**: Create maturity level baselines
4. **Testing Framework**: Develop test cases and validation scenarios
5. **Documentation**: Create implementation and user guides
6. **CI/CD Integration**: Build pipeline templates for automated auditing

This framework provides a comprehensive approach to automating Essential 8 compliance across Microsoft cloud environments, taking the guesswork out of security auditing for your customers.
