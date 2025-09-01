<#
.SYNOPSIS
  Export read-only M365/Entra data required for Essential 8 MFA checks.

.DESCRIPTION
  Collects snapshots for:
    - Entra ID users (MFA requirements)
    - Conditional Access policies
    - Service principals (key/password creds)
    - Exchange Online org + mailbox plans (Modern Auth)
    - SharePoint tenant external sharing flags
    - Power Platform DLP policies

  Outputs JSON files to -ExportPath. Each item includes a 'type' field
  (e.g., 'Microsoft.AzureAD.User') to support typed PSRule rules later.

.NOTES
  Read-only. Requires appropriate read scopes/roles.

.EXAMPLE
  # Export everything
  .\Collectors\Export-M365Essential8.ps1 -ExportPath .\Essential8-Data

.EXAMPLE
  # Export only Entra and CA
  .\Collectors\Export-M365Essential8.ps1 -ExportPath .\Essential8-Data -Entra -ConditionalAccess

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ExportPath,

  # Workload toggles (default: all)
  [switch]$Entra,
  [switch]$ConditionalAccess,
  [switch]$ServicePrincipals,
  [switch]$Exchange,
  [switch]$SharePoint,
  [switch]$PowerPlatform,

  # Force refresh of PowerShell modules
  [switch]$ForceModuleInstall
)

begin {
  # If no switches were passed, capture everything
  if (-not ($Entra -or $ConditionalAccess -or $ServicePrincipals -or $Exchange -or $SharePoint -or $PowerPlatform)) {
    $Entra = $ConditionalAccess = $ServicePrincipals = $Exchange = $SharePoint = $PowerPlatform = $true
  }

  New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null

  function Ensure-Module {
    param(
      [Parameter(Mandatory)][string]$Name,
      [string]$MinVersion = $null
    )
    $params = @{ Name = $Name; Scope = 'CurrentUser'; ErrorAction = 'Stop' }
    if ($MinVersion) { $params['MinimumVersion'] = $MinVersion }
    if ($ForceModuleInstall -and (Get-Module -ListAvailable -Name $Name | Measure-Object).Count -gt 0) {
      # ensure latest if forced
      Install-Module @params -Force -AllowClobber
    } elseif ((Get-Module -ListAvailable -Name $Name | Measure-Object).Count -eq 0) {
      Install-Module @params -Force -AllowClobber
    }
    Import-Module $Name -ErrorAction Stop | Out-Null
  }

  function Write-Json {
    param(
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)]$Object,
      [int]$Depth = 12
    )
    $Object | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "Wrote $Path"
  }

  function With-TypeField {
    param(
      [Parameter(Mandatory)]$InputObject,
      [Parameter(Mandatory)][string]$TypeName
    )
    $InputObject | ForEach-Object {
      $o = $_ | Select-Object * # shallow copy
      # add or overwrite 'type' field
      Add-Member -InputObject $o -NotePropertyName 'type' -NotePropertyValue $TypeName -Force
      $o
    }
  }

  $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
}

process {

  # ------------------ ENTRA / GRAPH ------------------
  if ($Entra -or $ConditionalAccess -or $ServicePrincipals) {
    Ensure-Module -Name Microsoft.Graph -MinVersion '2.11.0'

    $scopes = @()
    if ($Entra) { $scopes += 'User.Read.All','Directory.Read.All' }
    if ($ConditionalAccess) { $scopes += 'Policy.Read.All' }
    if ($ServicePrincipals) { $scopes += 'Application.Read.All' }

    # Deduplicate scopes
    $scopes = $scopes | Sort-Object -Unique
    Write-Host "Connecting to Microsoft Graph with scopes: $($scopes -join ', ')"
    Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
    Select-MgProfile -Name 'beta' | Out-Null  # beta has richer CA fields; safe for read

    if ($Entra) {
      try {
        $users = Get-MgUser -All -Property "id,displayName,userPrincipalName,strongAuthenticationRequirements,assignedLicenses" `
          | Select-Object id,displayName,userPrincipalName,strongAuthenticationRequirements,assignedLicenses

        $users = With-TypeField -InputObject $users -TypeName 'Microsoft.AzureAD.User'
        Write-Json -Path (Join-Path $ExportPath "aad.users.$ts.json") -Object $users -Depth 20
      } catch {
        Write-Warning "Entra users export failed: $($_.Exception.Message)"
      }
    }

    if ($ConditionalAccess) {
      try {
        $cap = Get-MgIdentityConditionalAccessPolicy -All
        $cap = With-TypeField -InputObject $cap -TypeName 'Microsoft.AzureAD.ConditionalAccessPolicy'
        Write-Json -Path (Join-Path $ExportPath "aad.conditionalaccess.$ts.json") -Object $cap -Depth 20
      } catch {
        Write-Warning "Conditional Access export failed: $($_.Exception.Message)"
      }
    }

    if ($ServicePrincipals) {
      try {
        $sps = Get-MgServicePrincipal -All -Property "id,displayName,keyCredentials,passwordCredentials" `
          | Select-Object id,displayName,keyCredentials,passwordCredentials
        $sps = With-TypeField -InputObject $sps -TypeName 'Microsoft.AzureAD.ServicePrincipal'
        Write-Json -Path (Join-Path $ExportPath "aad.serviceprincipals.$ts.json") -Object $sps -Depth 20
      } catch {
        Write-Warning "Service principals export failed: $($_.Exception.Message)"
      }
    }
  }

  # ------------------ EXCHANGE ONLINE ------------------
  if ($Exchange) {
    Ensure-Module -Name ExchangeOnlineManagement -MinVersion '3.5.0'
    try {
      Write-Host "Connecting to Exchange Online..."
      Connect-ExchangeOnline -ShowProgress:$false | Out-Null

      $org = Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled, *ModernAuth*, *OAuth*
      $plans = Get-MailboxPlan | Select-Object Name, IsDefault, ModernAuthenticationEnabled

      $org  = With-TypeField -InputObject $org   -TypeName 'Microsoft.Exchange.OrganizationConfig'
      $plans = With-TypeField -InputObject $plans -TypeName 'Microsoft.Exchange.MailboxPlan'

      Write-Json -Path (Join-Path $ExportPath "exo.org.$ts.json") -Object $org
      Write-Json -Path (Join-Path $ExportPath "exo.mailboxplans.$ts.json") -Object $plans
    } catch {
      Write-Warning "Exchange export failed: $($_.Exception.Message)"
    } finally {
      Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
  }

  # ------------------ SHAREPOINT ONLINE ------------------
  if ($SharePoint) {
    Ensure-Module -Name Microsoft.Online.SharePoint.PowerShell -MinVersion '16.0.24908.12000'
    try {
      # You must supply your admin URL once per session. Prompt if not set.
      $tenant = (Get-PnPTenant -ErrorAction SilentlyContinue) # if PnP already connected
    } catch { }

    try {
      # Fallback to SPO connection; ask for URL on prompt
      $adminUrl = Read-Host "Enter SharePoint Admin URL (e.g., https://contoso-admin.sharepoint.com)"
      Connect-SPOService -Url $adminUrl
      $spoTenant = Get-SPOTenant | Select-Object SharingCapability, RequireAcceptingAccountMatchInvitedAccount
      $spoTenant = With-TypeField -InputObject $spoTenant -TypeName 'Microsoft.SharePoint.Tenant'
      Write-Json -Path (Join-Path $ExportPath "spo.tenant.$ts.json") -Object $spoTenant
    } catch {
      Write-Warning "SharePoint export failed: $($_.Exception.Message)"
    }
  }

  # ------------------ POWER PLATFORM (DLP) ------------------
  if ($PowerPlatform) {
    Ensure-Module -Name Microsoft.PowerApps.Administration.PowerShell -MinVersion '2.0.164'
    try {
      Add-PowerAppsAccount -TenantID (Read-Host "Enter Tenant ID (GUID) for Power Platform sign-in") | Out-Null
      $dlp = Get-DlpPolicy
      $dlp = With-TypeField -InputObject $dlp -TypeName 'Microsoft.PowerPlatform.DLPPolicy'
      Write-Json -Path (Join-Path $ExportPath "pp.dlp.$ts.json") -Object $dlp -Depth 20
    } catch {
      Write-Warning "Power Platform export failed: $($_.Exception.Message)"
    }
  }
}

end {
  Write-Host "Done. JSON exports written to $ExportPath"
  Write-Host "Next: Invoke-PSRule -InputPath `"$ExportPath`" -Path .\rules\Azure"
}
