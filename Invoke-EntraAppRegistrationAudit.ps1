#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audits all Entra ID app registrations and exports the findings to CSV.

.DESCRIPTION
    Collects, for every app registration in the tenant:
      - Identity and metadata (names, IDs, created date, notes, tags, owners)
      - Supported account types (single tenant, multitenant, personal accounts)
      - Publisher domain and verified publisher status
      - Redirect URIs (web, SPA, public client), implicit grant and public client flow settings
      - Exposed API scopes and app roles defined by the app
      - Every configured API permission (application and delegated), resolved to its
        name, with its consent status (admin, user or not granted), plus permissions
        that are granted but NOT declared in the app manifest
      - Client secrets, certificates and federated identity credentials on the app object,
        plus any credentials on the backing service principal
      - Service principal state (enabled, assignment required) and last sign-in activity
      - Risk flags to speed up triage

    Output (in a timestamped folder):
      1. AppRegistrations_Summary.csv      One row per app, with roll-ups and risk flags
      2. AppRegistrations_Permissions.csv  One row per API permission per app
      3. AppRegistrations_Credentials.csv  One row per secret / certificate / federated credential

    Join the files on AppId.

.PERMISSIONS
    Delegated Graph scopes (read only):
      Application.Read.All
      Directory.Read.All
      AuditLog.Read.All   (for sign-in activity; needs Entra ID P1/P2. Use -SkipSignInActivity to omit)
    The signed-in account needs a role able to consent to / use these, e.g. Global Reader
    plus Reports Reader, or Security Reader.

.PARAMETER TenantId
    Tenant ID or primary domain to connect to.

.PARAMETER OutputPath
    Folder for the CSV files. Defaults to .\EntraAppAudit_<timestamp>.

.PARAMETER ExpiryWarningDays
    Credentials expiring within this many days are flagged "Expiring soon". Default 30.

.PARAMETER MaxCredentialLifetimeDays
    Credentials with a total lifetime longer than this are flagged as long-lived. Default 365.

.PARAMETER InactiveDays
    Apps with no sign-in in this many days are flagged inactive. Default 90.

.PARAMETER SkipSignInActivity
    Skip sign-in activity collection (no AuditLog.Read.All / P1 licence required).

.EXAMPLE
    .\Invoke-EntraAppRegistrationAudit.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Invoke-EntraAppRegistrationAudit.ps1 -ExpiryWarningDays 60 -InactiveDays 180 -OutputPath C:\Audits\Client1

.NOTES
    Read only. Makes no changes to the tenant.
    Requires: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Tested for PowerShell 5.1 and 7.x.
    Privilege levels are a heuristic to aid triage, not a definitive classification.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("EntraAppAudit_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [int]$ExpiryWarningDays = 30,
    [int]$MaxCredentialLifetimeDays = 365,
    [int]$InactiveDays = 90,
    [switch]$SkipSignInActivity
)

$ErrorActionPreference = 'Stop'
$now = (Get-Date).ToUniversalTime()
$graph = 'https://graph.microsoft.com'

#region Reference data ---------------------------------------------------------

$audienceMap = @{
    'AzureADMyOrg'                       = 'Single tenant (this organisation only)'
    'AzureADMultipleOrgs'                = 'Multitenant (any Entra ID organisation)'
    'AzureADandPersonalMicrosoftAccount' = 'Multitenant + personal Microsoft accounts'
    'PersonalMicrosoftAccount'           = 'Personal Microsoft accounts only'
}

# Permissions that allow tenant takeover, privilege escalation or broad data access
$criticalPerms = @(
    'Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy', 'AppRoleAssignment.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.Directory',
    'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'Domain.ReadWrite.All',
    'Organization.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All',
    'User.ReadWrite.All', 'User.ManageIdentities.All', 'UserAuthenticationMethod.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
    'Policy.ReadWrite.PermissionGrant', 'PrivilegedAccess.ReadWrite.AzureADGroup',
    'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
    'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'full_access_as_app', 'Exchange.ManageAsApp',
    'Files.ReadWrite.All', 'Sites.FullControl.All', 'Sites.ReadWrite.All', 'Sites.Manage.All',
    'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.ReadWrite.All',
    'DeviceManagementRBAC.ReadWrite.All', 'DeviceManagementApps.ReadWrite.All'
)

# Sensitive read access worth reviewing
$highPerms = @(
    'Mail.Read', 'Mail.ReadBasic.All', 'Files.Read.All', 'Sites.Read.All', 'Directory.Read.All',
    'User.Read.All', 'Group.Read.All', 'AuditLog.Read.All', 'Calendars.Read', 'Calendars.ReadWrite',
    'Contacts.Read', 'Contacts.ReadWrite', 'Chat.Read.All', 'Chat.ReadWrite.All', 'ChannelMessage.Read.All',
    'Notes.Read.All', 'Notes.ReadWrite.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory',
    'Policy.Read.All', 'IdentityRiskyUser.ReadWrite.All', 'SecurityEvents.ReadWrite.All',
    'ThreatIndicators.ReadWrite.OwnedBy', 'Team.ReadBasic.All', 'TeamMember.ReadWrite.All'
)

#endregion

#region Helpers ----------------------------------------------------------------

function Get-GraphAll {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($null -ne $resp.value) { foreach ($v in $resp.value) { $items.Add($v) } }
        $next = $resp.'@odata.nextLink'
    }
    return , $items
}

function ConvertTo-DateSafe {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
        return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    catch { return $null }
}

function Format-DateSafe {
    param($Value)
    if ($Value) { return $Value.ToString('yyyy-MM-dd HH:mm') } else { return '' }
}

function Get-PrivilegeLevel {
    param([string]$Name, [string]$Type)
    if ($criticalPerms -contains $Name) {
        if ($Type -eq 'Application') { return 'Critical' } else { return 'High' }
    }
    if ($highPerms -contains $Name) {
        if ($Type -eq 'Application') { return 'High' } else { return 'Medium' }
    }
    if ($Name -match '\.ReadWrite\.All$|\.Write\.All$|FullControl|\.Manage\.All$') {
        if ($Type -eq 'Application') { return 'High' } else { return 'Medium' }
    }
    if ($Name -match '\.Read\.All$') {
        if ($Type -eq 'Application') { return 'Medium' } else { return 'Low' }
    }
    return 'Low'
}

function Get-CredentialStatus {
    param($Start, $End)
    if (-not $End) { return 'Unknown' }
    if ($End -lt $now) { return 'Expired' }
    if ($Start -and $Start -gt $now) { return 'Not yet valid' }
    if ($End -lt $now.AddDays($ExpiryWarningDays)) { return 'Expiring soon' }
    return 'Active'
}

function ConvertTo-Thumbprint {
    param($Base64)
    if (-not $Base64) { return '' }
    try { return ([BitConverter]::ToString([Convert]::FromBase64String($Base64)) -replace '-', '') }
    catch { return [string]$Base64 }
}

function New-CredentialRows {
    param($App, [string]$Location, $Passwords, $Keys)

    foreach ($p in @($Passwords)) {
        if (-not $p) { continue }
        $start = ConvertTo-DateSafe $p.startDateTime
        $end = ConvertTo-DateSafe $p.endDateTime
        $life = if ($start -and $end) { [int]($end - $start).TotalDays } else { $null }
        [pscustomobject][ordered]@{
            AppDisplayName     = $App.displayName
            AppId              = $App.appId
            CredentialLocation = $Location
            CredentialType     = 'Client secret'
            Name               = $p.displayName
            KeyId              = $p.keyId
            SecretHint         = $p.hint
            CertUsage          = ''
            CertType           = ''
            Thumbprint         = ''
            StartDateUtc       = Format-DateSafe $start
            EndDateUtc         = Format-DateSafe $end
            Status             = Get-CredentialStatus $start $end
            DaysRemaining      = if ($end) { [int]($end - $now).TotalDays } else { '' }
            LifetimeDays       = $life
            ExceedsMaxLifetime = [bool]($life -and $life -gt $MaxCredentialLifetimeDays)
            FederatedIssuer    = ''
            FederatedSubject   = ''
            FederatedAudiences = ''
        }
    }

    foreach ($k in @($Keys)) {
        if (-not $k) { continue }
        $start = ConvertTo-DateSafe $k.startDateTime
        $end = ConvertTo-DateSafe $k.endDateTime
        $life = if ($start -and $end) { [int]($end - $start).TotalDays } else { $null }
        [pscustomobject][ordered]@{
            AppDisplayName     = $App.displayName
            AppId              = $App.appId
            CredentialLocation = $Location
            CredentialType     = 'Certificate'
            Name               = $k.displayName
            KeyId              = $k.keyId
            SecretHint         = ''
            CertUsage          = $k.usage
            CertType           = $k.type
            Thumbprint         = ConvertTo-Thumbprint $k.customKeyIdentifier
            StartDateUtc       = Format-DateSafe $start
            EndDateUtc         = Format-DateSafe $end
            Status             = Get-CredentialStatus $start $end
            DaysRemaining      = if ($end) { [int]($end - $now).TotalDays } else { '' }
            LifetimeDays       = $life
            ExceedsMaxLifetime = [bool]($life -and $life -gt $MaxCredentialLifetimeDays)
            FederatedIssuer    = ''
            FederatedSubject   = ''
            FederatedAudiences = ''
        }
    }
}

function New-PermissionRow {
    param($App, $ResourceName, $ResourceAppId, $Type, $Name, $Description, $Configured, $Status, $Detail, $GrantedOn)
    [pscustomobject][ordered]@{
        AppDisplayName        = $App.displayName
        AppId                 = $App.appId
        ResourceName          = $ResourceName
        ResourceAppId         = $ResourceAppId
        PermissionType        = $Type
        PermissionName        = $Name
        PermissionDescription = $Description
        ConfiguredInApp       = $Configured
        ConsentStatus         = $Status
        ConsentDetail         = $Detail
        GrantedOnUtc          = $GrantedOn
        PrivilegeLevel        = Get-PrivilegeLevel -Name $Name -Type $Type
    }
}

#endregion

#region Connect and collect tenant-wide data -----------------------------------

$scopes = @('Application.Read.All', 'Directory.Read.All')
if (-not $SkipSignInActivity) { $scopes += 'AuditLog.Read.All' }

$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$ctx = Get-MgContext
Write-Host ("Connected to tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) -ForegroundColor Cyan

Write-Host 'Retrieving app registrations...'
$appSelect = 'id,appId,displayName,createdDateTime,signInAudience,publisherDomain,verifiedPublisher,' +
             'passwordCredentials,keyCredentials,requiredResourceAccess,web,spa,publicClient,' +
             'isFallbackPublicClient,identifierUris,notes,tags,api,appRoles,disabledByMicrosoftStatus,' +
             'serviceManagementReference'
$apps = Get-GraphAll -Uri "$graph/v1.0/applications?`$select=$appSelect&`$top=999"
Write-Host ("  {0} app registrations found" -f $apps.Count)

Write-Host 'Retrieving service principals (used to resolve permission names and consent)...'
$spSelect = 'id,appId,displayName,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,' +
            'appOwnerOrganizationId,appRoles,oauth2PermissionScopes,passwordCredentials,keyCredentials'
$sps = Get-GraphAll -Uri "$graph/v1.0/servicePrincipals?`$select=$spSelect&`$top=999"
$spByAppId = @{}
$spById = @{}
foreach ($sp in $sps) { $spByAppId[$sp.appId] = $sp; $spById[$sp.id] = $sp }
Write-Host ("  {0} service principals found" -f $sps.Count)

Write-Host 'Retrieving delegated permission grants...'
$grants = Get-GraphAll -Uri "$graph/v1.0/oauth2PermissionGrants?`$top=999"
$grantsByClient = @{}
foreach ($g in $grants) {
    if (-not $grantsByClient.ContainsKey($g.clientId)) { $grantsByClient[$g.clientId] = [System.Collections.Generic.List[object]]::new() }
    $grantsByClient[$g.clientId].Add($g)
}

$signInByAppId = @{}
$signInAvailable = $false
if (-not $SkipSignInActivity) {
    Write-Host 'Retrieving service principal sign-in activity...'
    try {
        $acts = Get-GraphAll -Uri "$graph/beta/reports/servicePrincipalSignInActivities"
        foreach ($a in $acts) { $signInByAppId[$a.appId] = $a }
        $signInAvailable = $true
    }
    catch {
        Write-Warning "Sign-in activity unavailable (needs AuditLog.Read.All and Entra ID P1/P2): $($_.Exception.Message)"
    }
}

#endregion

#region Per-app audit ----------------------------------------------------------

$summaryRows = [System.Collections.Generic.List[object]]::new()
$permRows = [System.Collections.Generic.List[object]]::new()
$credRows = [System.Collections.Generic.List[object]]::new()

$i = 0
foreach ($app in $apps) {
    $i++
    Write-Progress -Activity 'Auditing app registrations' -Status $app.displayName -PercentComplete (($i / [math]::Max($apps.Count, 1)) * 100)

    $flags = [System.Collections.Generic.List[string]]::new()
    $sp = $spByAppId[$app.appId]

    # Owners
    $owners = @()
    try { $owners = Get-GraphAll -Uri "$graph/v1.0/applications/$($app.id)/owners" }
    catch { Write-Warning "Owners lookup failed for $($app.displayName): $($_.Exception.Message)" }
    $ownerNames = @(foreach ($o in $owners) { if ($o.userPrincipalName) { $o.userPrincipalName } else { $o.displayName } })
    if ($ownerNames.Count -eq 0) { $flags.Add('NoOwners') }

    # Federated identity credentials
    $fics = @()
    try { $fics = Get-GraphAll -Uri "$graph/v1.0/applications/$($app.id)/federatedIdentityCredentials" }
    catch { Write-Warning "Federated credential lookup failed for $($app.displayName): $($_.Exception.Message)" }

    # ---- Credentials ----
    $appCreds = @(New-CredentialRows -App $app -Location 'Application' -Passwords $app.passwordCredentials -Keys $app.keyCredentials)
    $spCreds = @()
    if ($sp) { $spCreds = @(New-CredentialRows -App $app -Location 'ServicePrincipal' -Passwords $sp.passwordCredentials -Keys $sp.keyCredentials) }
    $ficRows = @(foreach ($f in $fics) {
        [pscustomobject][ordered]@{
            AppDisplayName     = $app.displayName
            AppId              = $app.appId
            CredentialLocation = 'Application'
            CredentialType     = 'Federated credential'
            Name               = $f.name
            KeyId              = $f.id
            SecretHint         = ''
            CertUsage          = ''
            CertType           = ''
            Thumbprint         = ''
            StartDateUtc       = ''
            EndDateUtc         = ''
            Status             = 'N/A (no expiry)'
            DaysRemaining      = ''
            LifetimeDays       = ''
            ExceedsMaxLifetime = $false
            FederatedIssuer    = $f.issuer
            FederatedSubject   = $f.subject
            FederatedAudiences = (@($f.audiences) -join '; ')
        }
    })
    foreach ($c in ($appCreds + $spCreds + $ficRows)) { if ($c) { $credRows.Add($c) } }

    $secrets = @($appCreds | Where-Object { $_.CredentialType -eq 'Client secret' })
    $certs = @($appCreds | Where-Object { $_.CredentialType -eq 'Certificate' })
    $allTimed = @($appCreds + $spCreds)

    if (@($allTimed | Where-Object Status -eq 'Expired').Count) { $flags.Add('ExpiredCredentials') }
    if (@($allTimed | Where-Object Status -eq 'Expiring soon').Count) { $flags.Add('CredentialsExpiringSoon') }
    if (@($allTimed | Where-Object ExceedsMaxLifetime).Count) { $flags.Add('LongLivedCredentials') }
    if (@($secrets | Where-Object { $_.Status -in 'Active', 'Expiring soon' }).Count) { $flags.Add('ActiveClientSecrets') }
    if ($spCreds.Count) { $flags.Add('CredentialsOnServicePrincipal') }

    $nextSecret = $secrets | Where-Object { $_.Status -in 'Active', 'Expiring soon' } | Sort-Object EndDateUtc | Select-Object -First 1
    $nextCert = $certs | Where-Object { $_.Status -in 'Active', 'Expiring soon' } | Sort-Object EndDateUtc | Select-Object -First 1

    # ---- Permissions ----
    $clientAssignments = @()
    if ($sp) {
        try { $clientAssignments = Get-GraphAll -Uri "$graph/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" }
        catch { Write-Warning "App role assignment lookup failed for $($app.displayName): $($_.Exception.Message)" }
    }
    $clientGrants = @()
    if ($sp -and $grantsByClient.ContainsKey($sp.id)) { $clientGrants = @($grantsByClient[$sp.id]) }

    $matchedAssignmentIds = @{}
    $configuredDelegated = @{}
    $appPermRows = [System.Collections.Generic.List[object]]::new()

    foreach ($rra in @($app.requiredResourceAccess)) {
        if (-not $rra) { continue }
        $resSp = $spByAppId[$rra.resourceAppId]
        $resName = if ($resSp) { $resSp.displayName } else { "Unknown resource ($($rra.resourceAppId))" }

        foreach ($ra in @($rra.resourceAccess)) {
            if (-not $ra) { continue }

            if ($ra.type -eq 'Role') {
                $def = $null
                if ($resSp) { $def = @($resSp.appRoles) | Where-Object { $_.id -eq $ra.id } | Select-Object -First 1 }
                $pName = if ($def) { $def.value } else { $ra.id }
                $pDesc = if ($def) { $def.displayName } else { 'Unresolved permission ID' }
                $status = 'Not granted'; $detail = 'Admin consent required'; $grantedOn = ''

                if (-not $sp) { $status = 'Not granted'; $detail = 'No service principal in this tenant' }
                elseif ($resSp) {
                    $hit = $clientAssignments | Where-Object { $_.resourceId -eq $resSp.id -and $_.appRoleId -eq $ra.id } | Select-Object -First 1
                    if ($hit) {
                        $status = 'Granted'; $detail = 'Admin consent'
                        $grantedOn = Format-DateSafe (ConvertTo-DateSafe $hit.createdDateTime)
                        $matchedAssignmentIds[$hit.id] = $true
                    }
                }
                $appPermRows.Add((New-PermissionRow $app $resName $rra.resourceAppId 'Application' $pName $pDesc 'Yes' $status $detail $grantedOn))
            }
            else {
                $def = $null
                if ($resSp) { $def = @($resSp.oauth2PermissionScopes) | Where-Object { $_.id -eq $ra.id } | Select-Object -First 1 }
                $pName = if ($def) { $def.value } else { $ra.id }
                $pDesc = if ($def) { $def.adminConsentDisplayName } else { 'Unresolved permission ID' }
                $status = 'Not granted'; $detail = ''

                if (-not $sp) { $detail = 'No service principal in this tenant' }
                elseif ($resSp) {
                    $configuredDelegated["$($resSp.id)|$pName"] = $true
                    $resGrants = @($clientGrants | Where-Object { $_.resourceId -eq $resSp.id -and (($_.scope -split ' ') -contains $pName) })
                    $admin = @($resGrants | Where-Object consentType -eq 'AllPrincipals')
                    $user = @($resGrants | Where-Object consentType -eq 'Principal')
                    if ($admin.Count) {
                        $status = 'Granted'; $detail = 'Admin consent (all users)'
                        if ($user.Count) { $detail += "; also user consent ($($user.Count) users)" }
                    }
                    elseif ($user.Count) { $status = 'Granted (user consent only)'; $detail = "User consent ($($user.Count) users)" }
                    else { $detail = if ($def -and $def.type -eq 'Admin') { 'Admin consent required' } else { 'User or admin consent possible' } }
                }
                $appPermRows.Add((New-PermissionRow $app $resName $rra.resourceAppId 'Delegated' $pName $pDesc 'Yes' $status $detail ''))
            }
        }
    }

    # Application permissions granted to the SP but not declared in the app manifest
    foreach ($a in $clientAssignments) {
        if ($matchedAssignmentIds.ContainsKey($a.id)) { continue }
        $resSp = $spById[$a.resourceId]
        $def = $null
        if ($resSp) { $def = @($resSp.appRoles) | Where-Object { $_.id -eq $a.appRoleId } | Select-Object -First 1 }
        $pName = if ($def) { $def.value } elseif ($a.appRoleId -eq '00000000-0000-0000-0000-000000000000') { 'Default access' } else { $a.appRoleId }
        $pDesc = if ($def) { $def.displayName } else { '' }
        $resName = if ($resSp) { $resSp.displayName } else { $a.resourceDisplayName }
        $resAppId = if ($resSp) { $resSp.appId } else { '' }
        $appPermRows.Add((New-PermissionRow $app $resName $resAppId 'Application' $pName $pDesc 'No' 'Granted (not in app manifest)' 'Assigned directly to service principal' (Format-DateSafe (ConvertTo-DateSafe $a.createdDateTime))))
    }

    # Delegated permissions granted but not declared in the app manifest
    $extraDelegated = @{}
    foreach ($g in $clientGrants) {
        foreach ($s in ($g.scope -split ' ' | Where-Object { $_ })) {
            $key = "$($g.resourceId)|$s"
            if ($configuredDelegated.ContainsKey($key)) { continue }
            if (-not $extraDelegated.ContainsKey($key)) { $extraDelegated[$key] = @{ ResourceId = $g.resourceId; Scope = $s; Admin = $false; Users = 0 } }
            if ($g.consentType -eq 'AllPrincipals') { $extraDelegated[$key].Admin = $true } else { $extraDelegated[$key].Users++ }
        }
    }
    foreach ($e in $extraDelegated.Values) {
        $resSp = $spById[$e.ResourceId]
        $def = $null
        if ($resSp) { $def = @($resSp.oauth2PermissionScopes) | Where-Object { $_.value -eq $e.Scope } | Select-Object -First 1 }
        $detailParts = @()
        if ($e.Admin) { $detailParts += 'Admin consent (all users)' }
        if ($e.Users) { $detailParts += "User consent ($($e.Users) users)" }
        $resName = if ($resSp) { $resSp.displayName } else { $e.ResourceId }
        $resAppId = if ($resSp) { $resSp.appId } else { '' }
        $pDesc = if ($def) { $def.adminConsentDisplayName } else { '' }
        $appPermRows.Add((New-PermissionRow $app $resName $resAppId 'Delegated' $e.Scope $pDesc 'No' 'Granted (not in app manifest)' ($detailParts -join '; ') ''))
    }

    foreach ($r in $appPermRows) { $permRows.Add($r) }

    $grantedRows = @($appPermRows | Where-Object { $_.ConsentStatus -like 'Granted*' })
    $critGranted = @($grantedRows | Where-Object PrivilegeLevel -eq 'Critical' | ForEach-Object { "$($_.PermissionName) ($($_.PermissionType))" } | Select-Object -Unique)
    $highGranted = @($grantedRows | Where-Object PrivilegeLevel -eq 'High' | ForEach-Object { "$($_.PermissionName) ($($_.PermissionType))" } | Select-Object -Unique)
    $notGranted = @($appPermRows | Where-Object ConsentStatus -eq 'Not granted')
    $notInManifest = @($appPermRows | Where-Object ConfiguredInApp -eq 'No')

    $highest = 'None'
    foreach ($lvl in 'Critical', 'High', 'Medium', 'Low') {
        if (@($grantedRows | Where-Object PrivilegeLevel -eq $lvl).Count) { $highest = $lvl; break }
    }

    if ($critGranted.Count) { $flags.Add('CriticalPermissionGranted') }
    if ($notInManifest.Count) { $flags.Add('PermissionsGrantedOutsideManifest') }
    if ($notGranted.Count) { $flags.Add('PermissionsAwaitingConsent') }

    # ---- Audience / publisher ----
    if ($app.signInAudience -ne 'AzureADMyOrg') {
        $flags.Add('MultiTenant')
        if (-not $app.verifiedPublisher.displayName) { $flags.Add('MultiTenantUnverifiedPublisher') }
    }
    if ($app.signInAudience -like '*Personal*') { $flags.Add('PersonalAccountsAllowed') }

    # ---- Redirect URIs / auth flows ----
    $webUris = @($app.web.redirectUris | Where-Object { $_ })
    $spaUris = @($app.spa.redirectUris | Where-Object { $_ })
    $pubUris = @($app.publicClient.redirectUris | Where-Object { $_ })
    $allUris = @($webUris + $spaUris + $pubUris)

    if (@($allUris | Where-Object { $_ -match '\*' }).Count) { $flags.Add('WildcardRedirectUri') }
    if (@($allUris | Where-Object { $_ -match '^http://' -and $_ -notmatch '^http://(localhost|127\.0\.0\.1)([:/]|$)' }).Count) { $flags.Add('InsecureHttpRedirectUri') }
    if (@($allUris | Where-Object { $_ -match '\.(azurewebsites\.net|cloudapp\.net|trafficmanager\.net|blob\.core\.windows\.net)' }).Count) { $flags.Add('AzureHostedRedirectUri_CheckTakeover') }

    $implicitId = [bool]$app.web.implicitGrantSettings.enableIdTokenIssuance
    $implicitAccess = [bool]$app.web.implicitGrantSettings.enableAccessTokenIssuance
    if ($implicitAccess) { $flags.Add('ImplicitAccessTokenEnabled') }
    if ($app.isFallbackPublicClient) { $flags.Add('PublicClientFlowsEnabled') }

    # ---- Service principal / activity ----
    $lastSignIn = $null
    $daysSince = ''
    if ($signInAvailable) {
        $si = $signInByAppId[$app.appId]
        if ($si) { $lastSignIn = ConvertTo-DateSafe $si.lastSignInActivity.lastSignInDateTime }
        if ($lastSignIn) {
            $daysSince = [int]($now - $lastSignIn).TotalDays
            if ($daysSince -gt $InactiveDays) { $flags.Add('Inactive') }
        }
        else { $flags.Add('NoSignInRecorded') }
    }
    if (-not $sp) { $flags.Add('NoServicePrincipal') }
    elseif (-not $sp.accountEnabled) { $flags.Add('ServicePrincipalDisabled') }

    $created = ConvertTo-DateSafe $app.createdDateTime

    $summaryRows.Add([pscustomobject][ordered]@{
        DisplayName                   = $app.displayName
        AppId                         = $app.appId
        ApplicationObjectId           = $app.id
        ServicePrincipalObjectId      = if ($sp) { $sp.id } else { '' }
        CreatedDateUtc                = Format-DateSafe $created
        AppAgeDays                    = if ($created) { [int]($now - $created).TotalDays } else { '' }
        SignInAudience                = $app.signInAudience
        SupportedAccountTypes         = $audienceMap[[string]$app.signInAudience]
        PublisherDomain               = $app.publisherDomain
        VerifiedPublisher             = $app.verifiedPublisher.displayName
        Owners                        = $ownerNames -join '; '
        OwnerCount                    = $ownerNames.Count
        Notes                         = $app.notes
        Tags                          = (@($app.tags) -join '; ')
        ServiceManagementReference    = $app.serviceManagementReference
        DisabledByMicrosoft           = $app.disabledByMicrosoftStatus
        ServicePrincipalExists        = [bool]$sp
        ServicePrincipalEnabled       = if ($sp) { $sp.accountEnabled } else { '' }
        AssignmentRequired            = if ($sp) { $sp.appRoleAssignmentRequired } else { '' }
        LastSignInUtc                 = Format-DateSafe $lastSignIn
        DaysSinceLastSignIn           = $daysSince
        WebRedirectUris               = $webUris -join '; '
        SpaRedirectUris               = $spaUris -join '; '
        PublicClientRedirectUris      = $pubUris -join '; '
        ImplicitIdTokenEnabled        = $implicitId
        ImplicitAccessTokenEnabled    = $implicitAccess
        PublicClientFlowsEnabled      = [bool]$app.isFallbackPublicClient
        IdentifierUris                = (@($app.identifierUris) -join '; ')
        ExposedApiScopes              = (@($app.api.oauth2PermissionScopes | ForEach-Object { $_.value }) -join '; ')
        AppRolesDefined               = (@($app.appRoles | ForEach-Object { $_.value }) -join '; ')
        ConfiguredPermissionCount     = @($appPermRows | Where-Object ConfiguredInApp -eq 'Yes').Count
        ApplicationPermissionCount    = @($appPermRows | Where-Object PermissionType -eq 'Application').Count
        DelegatedPermissionCount      = @($appPermRows | Where-Object PermissionType -eq 'Delegated').Count
        GrantedPermissionCount        = $grantedRows.Count
        PermissionsNotGranted         = (@($notGranted | ForEach-Object { $_.PermissionName }) -join '; ')
        PermissionsOutsideManifest    = (@($notInManifest | ForEach-Object { $_.PermissionName }) -join '; ')
        HighestPrivilegeGranted       = $highest
        CriticalPermissionsGranted    = $critGranted -join '; '
        HighPermissionsGranted        = $highGranted -join '; '
        ClientSecretCount             = $secrets.Count
        ActiveClientSecrets           = @($secrets | Where-Object { $_.Status -in 'Active', 'Expiring soon' }).Count
        ExpiredClientSecrets          = @($secrets | Where-Object Status -eq 'Expired').Count
        NextSecretExpiryUtc           = if ($nextSecret) { $nextSecret.EndDateUtc } else { '' }
        CertificateCount              = $certs.Count
        ActiveCertificates            = @($certs | Where-Object { $_.Status -in 'Active', 'Expiring soon' }).Count
        ExpiredCertificates           = @($certs | Where-Object Status -eq 'Expired').Count
        NextCertificateExpiryUtc      = if ($nextCert) { $nextCert.EndDateUtc } else { '' }
        FederatedCredentialCount      = $ficRows.Count
        ServicePrincipalCredentialCount = $spCreds.Count
        RiskFlagCount                 = $flags.Count
        RiskFlags                     = $flags -join '; '
    })
}
Write-Progress -Activity 'Auditing app registrations' -Completed

#endregion

#region Export -----------------------------------------------------------------

if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory | Out-Null }

$summaryFile = Join-Path $OutputPath 'AppRegistrations_Summary.csv'
$permFile = Join-Path $OutputPath 'AppRegistrations_Permissions.csv'
$credFile = Join-Path $OutputPath 'AppRegistrations_Credentials.csv'

$summaryRows | Sort-Object @{ Expression = 'RiskFlagCount'; Descending = $true }, DisplayName |
    Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8
$permRows | Sort-Object AppDisplayName, ResourceName, PermissionType, PermissionName |
    Export-Csv -Path $permFile -NoTypeInformation -Encoding UTF8
$credRows | Sort-Object AppDisplayName, CredentialType, EndDateUtc |
    Export-Csv -Path $credFile -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host 'Audit complete' -ForegroundColor Green
Write-Host ("  App registrations:            {0}" -f $summaryRows.Count)
Write-Host ("  With critical perms granted:  {0}" -f @($summaryRows | Where-Object HighestPrivilegeGranted -eq 'Critical').Count)
Write-Host ("  Multitenant:                  {0}" -f @($summaryRows | Where-Object SignInAudience -ne 'AzureADMyOrg').Count)
Write-Host ("  No owners:                    {0}" -f @($summaryRows | Where-Object OwnerCount -eq 0).Count)
Write-Host ("  With expired credentials:     {0}" -f @($summaryRows | Where-Object { $_.RiskFlags -like '*ExpiredCredentials*' }).Count)
Write-Host ("  Credentials expiring <{0}d:   {1}" -f $ExpiryWarningDays, @($credRows | Where-Object Status -eq 'Expiring soon').Count)
Write-Host ''
Write-Host "Output folder: $OutputPath" -ForegroundColor Cyan
Write-Host "  $summaryFile"
Write-Host "  $permFile"
Write-Host "  $credFile"

#endregion
