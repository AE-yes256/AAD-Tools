#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Entra ID Groups Audit - exports all groups with ownership, membership counts,
    nesting info and (for M365 groups) last activity date, to CSV.

.DESCRIPTION
    Flow:
      1. Connects to Microsoft Graph interactively (delegated).
      2. Downloads the Office 365 Groups Activity Detail report (last activity date).
      3. Pages through all groups in the tenant.
      4. Uses Graph $batch requests to efficiently gather per-group counts:
         owners, direct members, transitive members, nested groups, parent groups.
      5. Derives audit flags (NoOwners, Empty, NoRecentActivity, etc.).
      6. Exports everything to a single CSV.

    Required delegated permissions (you'll be prompted to consent on first run):
      Group.Read.All, Directory.Read.All, Reports.Read.All

    NOTE: If the activity report shows obfuscated names/IDs, your tenant has
    "Display concealed user, group and site names in reports" enabled.
    Disable it under M365 Admin Center > Settings > Org settings > Reports,
    otherwise the report rows cannot be matched back to groups.

.PARAMETER OutputPath
    Path for the CSV output. Defaults to .\EntraGroupsAudit_<timestamp>.csv

.PARAMETER ActivityPeriod
    Period for the M365 groups activity report: D30, D90 or D180. Default D90.

.PARAMETER StaleDays
    Groups with no activity within this many days are flagged NoRecentActivity.
    Default 90.

.PARAMETER TenantId
    Optional tenant ID/domain if you have access to multiple tenants.

.EXAMPLE
    .\Invoke-EntraGroupsAudit.ps1 -ActivityPeriod D180 -StaleDays 180
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\EntraGroupsAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [ValidateSet('D30', 'D90', 'D180')]
    [string]$ActivityPeriod = 'D90',

    [int]$StaleDays = 90,

    [string]$TenantId
)

$ErrorActionPreference = 'Stop'

#region Connect ---------------------------------------------------------------

$scopes = @('Group.Read.All', 'Directory.Read.All', 'Reports.Read.All')
$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph @connectParams

$ctx = Get-MgContext
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Green

#endregion

#region Helper: Graph request with throttling retry ---------------------------

function Invoke-GraphWithRetry {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers,
        [object]$Body,
        [string]$OutputFilePath,
        [int]$MaxRetries = 5
    )
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $params = @{ Uri = $Uri; Method = $Method }
            if ($Headers)        { $params.Headers        = $Headers }
            if ($Body)           { $params.Body           = ($Body | ConvertTo-Json -Depth 10); $params.ContentType = 'application/json' }
            if ($OutputFilePath) { $params.OutputFilePath = $OutputFilePath }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -in 429, 503, 504 -and $attempt -lt $MaxRetries) {
                $retryAfter = 5
                try { $retryAfter = [int]($_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1) } catch {}
                Write-Warning "Throttled ($status). Waiting $retryAfter s (attempt $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $retryAfter
            }
            else { throw }
        }
    }
}

#endregion

#region Step 1: M365 Groups activity report -----------------------------------

Write-Host "`nDownloading M365 groups activity report (period: $ActivityPeriod)..." -ForegroundColor Cyan

$activityByGroupId = @{}
$reportFile = Join-Path ([System.IO.Path]::GetTempPath()) "GroupsActivity_$([guid]::NewGuid()).csv"

try {
    Invoke-GraphWithRetry -Uri "https://graph.microsoft.com/v1.0/reports/getOffice365GroupsActivityDetail(period='$ActivityPeriod')" `
                          -OutputFilePath $reportFile | Out-Null

    $reportRows = Import-Csv -Path $reportFile
    $obfuscated = 0
    foreach ($row in $reportRows) {
        $gid = $row.'Group Id'
        if ($gid -and $gid -match '^[0-9a-fA-F\-]{36}$') {
            $activityByGroupId[$gid] = $row.'Last Activity Date'
        }
        else { $obfuscated++ }
    }
    Write-Host "Activity report loaded: $($activityByGroupId.Count) groups with activity data." -ForegroundColor Green
    if ($obfuscated -gt 0) {
        Write-Warning "$obfuscated report rows had obfuscated/missing Group Ids - see note in script header about the reports privacy setting."
    }
}
catch {
    Write-Warning "Could not retrieve activity report: $($_.Exception.Message)"
    Write-Warning "Continuing without last-activity data."
}
finally {
    if (Test-Path $reportFile) { Remove-Item $reportFile -Force -ErrorAction SilentlyContinue }
}

#endregion

#region Step 2: Download all groups -------------------------------------------

Write-Host "`nRetrieving all groups from Entra ID..." -ForegroundColor Cyan

$select = @(
    'id', 'displayName', 'description', 'mail', 'mailNickname',
    'createdDateTime', 'renewedDateTime', 'expirationDateTime',
    'groupTypes', 'membershipRule', 'membershipRuleProcessingState',
    'securityEnabled', 'mailEnabled', 'onPremisesSyncEnabled',
    'visibility', 'resourceProvisioningOptions', 'isAssignableToRole'
) -join ','

$groups = [System.Collections.Generic.List[object]]::new()
$uri = "https://graph.microsoft.com/v1.0/groups?`$select=$select&`$top=999"

while ($uri) {
    $page = Invoke-GraphWithRetry -Uri $uri
    foreach ($g in $page.value) { $groups.Add($g) }
    $uri = $page.'@odata.nextLink'
    Write-Host "  Retrieved $($groups.Count) groups so far..." -ForegroundColor DarkGray
}

Write-Host "Total groups retrieved: $($groups.Count)" -ForegroundColor Green

#endregion

#region Step 3: Per-group counts via $batch -----------------------------------

# 5 count queries per group, max 20 requests per batch => 4 groups per batch.
# $count=true + $top=1 + ConsistencyLevel:eventual returns @odata.count cheaply.

Write-Host "`nGathering owner/member/nesting counts (batched)..." -ForegroundColor Cyan

$countDefs = [ordered]@{
    Owners       = 'owners'
    Members      = 'members'
    Transitive   = 'transitiveMembers'
    NestedGroups = 'members/microsoft.graph.group'
    ParentGroups = 'memberOf'
}

$counts = @{}   # groupId -> hashtable of counts
$groupsPerBatch = [math]::Floor(20 / $countDefs.Count)
$batches = [math]::Ceiling($groups.Count / $groupsPerBatch)
$batchNum = 0

for ($i = 0; $i -lt $groups.Count; $i += $groupsPerBatch) {
    $batchNum++
    Write-Progress -Activity "Gathering group counts" -Status "Batch $batchNum of $batches" `
                   -PercentComplete ([math]::Min(100, ($batchNum / $batches) * 100))

    $slice = $groups[$i..([math]::Min($i + $groupsPerBatch - 1, $groups.Count - 1))]

    $requests = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $slice) {
        $counts[$g.id] = @{}
        foreach ($key in $countDefs.Keys) {
            $requests.Add(@{
                id      = "$($g.id)|$key"
                method  = 'GET'
                url     = "/groups/$($g.id)/$($countDefs[$key])?`$count=true&`$top=1&`$select=id"
                headers = @{ ConsistencyLevel = 'eventual' }
            })
        }
    }

    $batchResponse = Invoke-GraphWithRetry -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                                           -Method POST -Body @{ requests = $requests }

    foreach ($resp in $batchResponse.responses) {
        $gid, $key = $resp.id -split '\|', 2
        if ($resp.status -eq 200) {
            $counts[$gid][$key] = [int]$resp.body.'@odata.count'
        }
        elseif ($resp.status -eq 429) {
            # Retry this single request after the suggested delay
            $wait = 5
            try { $wait = [int]$resp.headers.'Retry-After' } catch {}
            Start-Sleep -Seconds $wait
            try {
                $single = Invoke-GraphWithRetry -Headers @{ ConsistencyLevel = 'eventual' } `
                    -Uri "https://graph.microsoft.com/v1.0/groups/$gid/$($countDefs[$key])?`$count=true&`$top=1&`$select=id"
                $counts[$gid][$key] = [int]$single.'@odata.count'
            }
            catch { $counts[$gid][$key] = $null }
        }
        else {
            $counts[$gid][$key] = $null
        }
    }
}
Write-Progress -Activity "Gathering group counts" -Completed

#endregion

#region Step 4: Build output and export ---------------------------------------

Write-Host "`nBuilding audit records..." -ForegroundColor Cyan
$today = (Get-Date).Date

$results = foreach ($g in $groups) {
    $c = $counts[$g.id]

    # Group category
    $isUnified = $g.groupTypes -contains 'Unified'
    $category = if ($isUnified)                                { 'Microsoft 365' }
                elseif ($g.securityEnabled -and $g.mailEnabled) { 'Mail-enabled Security' }
                elseif ($g.securityEnabled)                     { 'Security' }
                elseif ($g.mailEnabled)                         { 'Distribution' }
                else                                            { 'Unknown' }

    $membershipType = if ($g.groupTypes -contains 'DynamicMembership') { 'Dynamic' } else { 'Assigned' }
    $teamsConnected = [bool]($g.resourceProvisioningOptions -contains 'Team')

    # Activity
    $lastActivity = $null
    $daysSinceActivity = $null
    if ($isUnified -and $activityByGroupId.ContainsKey($g.id)) {
        $raw = $activityByGroupId[$g.id]
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $lastActivity = [datetime]::Parse($raw)
            $daysSinceActivity = ($today - $lastActivity.Date).Days
        }
    }

    # Audit flags
    $flags = [System.Collections.Generic.List[string]]::new()
    if ($c.Owners -eq 0)                                   { $flags.Add('NoOwners') }
    if ($c.Transitive -eq 0)                               { $flags.Add('Empty') }
    if ($g.onPremisesSyncEnabled)                          { $flags.Add('OnPremManaged') }
    if ($isUnified) {
        if ($null -eq $lastActivity)                       { $flags.Add('NoActivityData') }
        elseif ($daysSinceActivity -gt $StaleDays)         { $flags.Add('NoRecentActivity') }
    }
    if ($g.expirationDateTime -and [datetime]$g.expirationDateTime -lt $today) { $flags.Add('Expired') }

    [pscustomobject]@{
        DisplayName           = $g.displayName
        Id                    = $g.id
        Description           = $g.description
        GroupCategory         = $category
        MembershipType        = $membershipType
        MembershipRule        = $g.membershipRule
        SecurityEnabled       = $g.securityEnabled
        MailEnabled           = $g.mailEnabled
        Mail                  = $g.mail
        TeamsConnected        = $teamsConnected
        RoleAssignable        = [bool]$g.isAssignableToRole
        Visibility            = $g.visibility
        OnPremSynced          = [bool]$g.onPremisesSyncEnabled
        CreatedDateTime       = $g.createdDateTime
        RenewedDateTime       = $g.renewedDateTime
        ExpirationDateTime    = $g.expirationDateTime
        OwnerCount            = $c.Owners
        DirectMemberCount     = $c.Members
        TransitiveMemberCount = $c.Transitive
        NestedGroupCount      = $c.NestedGroups
        ParentGroupCount      = $c.ParentGroups
        LastActivityDate      = $lastActivity
        DaysSinceActivity     = $daysSinceActivity
        Flags                 = ($flags -join ';')
    }
}

$results | Sort-Object DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8BOM

Write-Host "`nDone. Exported $($results.Count) groups to: $OutputPath" -ForegroundColor Green

# Quick summary to console
$flagged = $results | Where-Object Flags
Write-Host "`nSummary of flagged groups:" -ForegroundColor Cyan
$flagged.Flags -split ';' | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
    Format-Table @{N = 'Flag'; E = { $_.Name } }, Count -AutoSize

Disconnect-MgGraph | Out-Null

#endregion
