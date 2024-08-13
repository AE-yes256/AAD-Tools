<#
.Synopsis
A Script used to update the All_Company distribution group based of AAD_Live_Users 

.DESCRIPTION
# PowerShell script to allow for a live list of users to be added to email distribution list
# Updated to MgGraph model

.Notes 
Created   : 09-September-2022
Updated   : 22-March-2023
Version   : 1.1
Author    : AE-yes256
Disclaimer: This script is provided "AS IS" with no warranties.
#>

## Prep Connection 
try {
    "Importing Graph"
    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Groups
    "Importing Exchange"
    import-module ExchangeOnlineManagement
    "Connect to Graph"
    Connect-MgGraph -ClientID "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -TenantId "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  -CertificateThumbprint "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "Connected to Exchange"
    Connect-ExchangeOnline -CertificateThumbPrint "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -AppID "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -Organization "custodiatec.onmicrosoft.com"
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}

## Preparing addition and removal arrays
$Additions = @()
$Removals = @()


## Get live users and pull out UPN
$AAD_Live_UserID = Get-MgGroupMember -GroupId xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
$AAD_Live_UPN = $AAD_Live_UserID.AdditionalProperties.userPrincipalName

## Get excluded users and pull out UPN
$AAD_Excluded_Users = Get-MgGroupMember -GroupId xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
$AAD_Excluded_UsersUPN = $AAD_Excluded_Users.AdditionalProperties.userPrincipalName

## Get whole company mailing list
$All_Company = Get-DistributionGroupMember -Identity "All_Company" | Select-Object -expand PrimarySmtpAddress

# Compare live AAD list and banned user list - filter out users that are banned

$Clean_MailList = Compare-Object -ReferenceObject $AAD_Excluded_UsersUPN -DifferenceObject $AAD_Live_UPN -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' }

# Compare list to live mail users and export differences that need to be removed

$diff_Clean_LiveMail = Compare-Object -ReferenceObject $Clean_MailList.InputObject -DifferenceObject $All_Company -IncludeEqual
$diff_Clean_LiveMail_Removal = $diff_Clean_LiveMail | Where-Object { $_.SideIndicator -eq '=>' }
$diff_Clean_LiveMail_Addition = $diff_Clean_LiveMail | Where-Object { $_.SideIndicator -eq '<=' }
$Additions += $diff_Clean_LiveMail_Addition
$Additions
$Removals += $diff_Clean_LiveMail_Removal
$Removals


foreach ($Member in $Additions.InputObject) {
    Add-DistributionGroupMember -Identity "All_Company" -Member $Member -Confirm:$false
}
foreach ($Member in $Removals.InputObject) {
    Remove-DistributionGroupMember -Identity "All_Company" -Member $Member -Confirm:$false
}

$output = New-Object PSObject -Property @{
    'Additions' = ($Additions.InputObject | Out-String).Trim()
    'Removals'  = ($Removals.InputObject | Out-String).Trim()
}
$output | Format-List

# $output | Export-Excel -Path "$($home)\All_Company_Mail_Changes.xlsx" -AutoSize -TableName Report
