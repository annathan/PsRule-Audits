# PsRule-Audits Implementation Guide

## Taking the Guesswork Out of Essential 8 Compliance

This guide will help you implement and use the PsRule-Audits tool to automatically assess your Microsoft cloud environment against the Australian Cyber Security Centre (ACSC) Essential 8 framework.

## 🎯 What This Tool Solves

**Customer Pain Points:**
- ❌ Manual compliance assessments are time-consuming and error-prone
- ❌ Difficulty mapping cloud configurations to Essential 8 requirements
- ❌ Inconsistent audit processes across different environments
- ❌ No clear roadmap from current state to compliance
- ❌ Limited visibility into compliance drift over time

**Our Solution:**
- ✅ Automated compliance scanning across Azure AD, Microsoft 365, and SharePoint
- ✅ Clear mapping between cloud configurations and Essential 8 strategies
- ✅ Consistent, repeatable audit processes
- ✅ Actionable remediation guidance with specific steps
- ✅ Continuous monitoring and compliance reporting

## 🏗️ Repository Structure

```
PsRule-Audits/
├── 📁 rules/
│   ├── 📁 Azure/                    # Azure-specific Essential 8 rules
│   ├── 📁 Microsoft365/             # M365-specific Essential 8 rules
│   └── 📁 SharePoint/               # SharePoint-specific Essential 8 rules
├── 📁 baselines/                    # Maturity level definitions
├── 📁 collectors/                   # Data collection scripts
├── 📁 reports/                      # Report templates and outputs
├── 📁 remediation/                  # Fix scripts and guidance
├── 📁 examples/                     # Usage examples and pipelines
└── 📁 docs/                        # Documentation and guidance
```

## 🚀 Quick Start

### Prerequisites

```powershell
# Install required PowerShell modules
Install-Module PSRule -Force
Install-Module Microsoft.Graph -Force  
Install-Module ExchangeOnlineManagement -Force
Install-Module -Name "PnP.PowerShell" -Force 
Install-Module Az.Accounts -Force
```

### 1. Clone and Setup

```bash
git clone https://github.com/annathan/PsRule-Audits
cd PsRule-Audits
```

### 2. Collect Your Environment Data

```powershell
# Interactive collection (recommended for first-time users)
.\collectors\Essential8-DataCollector.ps1 -TenantId "your-tenant.onmicrosoft.com"

# Automated collection (for CI/CD pipelines)
