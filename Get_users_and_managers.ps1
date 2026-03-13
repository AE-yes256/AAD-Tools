Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All"

$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled

$result = foreach ($u in $users) {

    try {
        $manager = Get-MgUserManager -UserId $u.Id -ErrorAction Stop
        $managerUser = Get-MgUser -UserId $manager.Id -Property DisplayName
        $managerName = $managerUser.DisplayName
    }
    catch {
        $managerName = "No manager"
    }

    [PSCustomObject]@{
        Name      = $u.DisplayName
        UPN       = $u.UserPrincipalName
        Manager   = $managerName
        Status    = if ($u.AccountEnabled) {"Active"} else {"Disabled"}
    }
}

$result | Export-Csv users_managers_status.csv -NoTypeInformation
