#Get owners of all guest groups
$guestID = Get-AzureADUser -All $true | Where-Object {$_.UserType -eq 'Guest'} | Select-Object -expand ObjectId
$Groups = foreach ($item in $guestID){Get-AzureADUserMembership -ObjectId $item}
$UniqueGroups=$Groups|select -Unique
$outputarray =@()
foreach ($u in $UniqueGroups) {
    $GrpOwners = [ordered] @{
        Group = $u.DisplayName
        Owners= Get-AzureADGroupOwner -objectid $u.ObjectId | Select-object -ExpandProperty userprincipalname | Out-String
    }
    $groupobj = new-object -Type PSObject -Property $GrpOwners
    $outputarray += $groupobj
}
$outputarray | Export-Csv  -NoTypeInformation -path .\Groups_owners.csv  -Encoding UTF8 -Force

