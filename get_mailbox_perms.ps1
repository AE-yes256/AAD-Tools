$mailboxes = Get-DistributionGroupMember -Identity "All_Company" | select-object PrimarySmtpAddress

$outputarray = @()
foreach ($u in $mailboxes) {
    $u.PrimarySmtpAddress
    $mailboxperms = Get-EXOMailboxFolderPermission -Identity "$($u.PrimarySmtpAddress):\Calendar"
    $mailboxaccess = [ordered] @{
        Target      = $u.PrimarySmtpAddress
        AccessUser  = $mailboxperms.User.DisplayName | Out-String
        AccessPerms = $mailboxperms.AccessRights | Out-String
    }
    $mbobj = new-object -Type PSObject -Property $mailboxaccess
    $outputarray += $mbobj
}

$outputarray | Export-Csv  -NoTypeInformation -path .\mailboxperms.csv  -Encoding UTF8 -Force





