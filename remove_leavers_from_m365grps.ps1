# Get All leavers and remove them from all M365 Groups 
# Quick and dirty as i know AzureAD module is EOL... Use at your own peril

$DisabledUsers = Get-AzureADUser -All:$true | Where-Object { $_.DisplayName -match 'Leaver' -and $_.AccountEnabled -match 'false' }
$AADGroups = Get-AzureADMSGroup -Filter "groupTypes/any(c:c eq 'Unified')" -All:$true
ForEach ($Group in $AADGroups) {
    $GroupMembers = (Get-AzureADGroupMember -ObjectId $Group.id)
    ForEach ($User in $DisabledUsers) {
        If ($GroupMembers.UserPrincipalName -contains $User.UserPrincipalName) {
            Write-Output "$($User.Displayname) Is in $($Group.DisplayName)"
            Remove-AzureADGroupMember -ObjectId $Group.Id -MemberId $User.ObjectId 
            Write-Output "$($User.Displayname) was removed from $($Group.DisplayName)"
        }
        # else {
        #     Write-Output "$($User.Displayname) Not in $($Group.DisplayName)"
        # }

    }
}
