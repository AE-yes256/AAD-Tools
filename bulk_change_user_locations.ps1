$outputarray = @()
$activeusers = Get-MgGroupMember -GroupId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
foreach ($uid in $activeusers.Id) {
    # Write-Output "true"
    $query = Get-MgUser -Filter "Id eq '$($uid)'" -All -Property DisplayName, Office, Streetaddress, City, State, PostalCode, Country, AccountEnabled, Id | Select-Object DisplayName, Office, Streetaddress, City, State, PostalCode, Country, AccountEnabled, Id
    $outputarray += $query
    if ($query.Country -eq $country) {
        Update-MgUser -UserId $uid -StreetAddress $address -City $city -State $state -PostalCode $postalCode
    }
    else {
        Write-Host "false"
    }

}
