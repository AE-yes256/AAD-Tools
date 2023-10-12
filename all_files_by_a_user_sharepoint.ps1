#Parameters
$SiteURL = "https://link/to/sharepoint.com"
$ListName = "Documents"
$AuthorEmail = "user.name@company.com"
 
#Connect to PnP Online
Connect-PnPOnline -Url $SiteURL -Interactive
 
#Get all files created by a particular user from the Library
$ListItems = Get-PnPListItem -List $Listname -PageSize 2000 | where {$_.FieldValues.Author.Email -eq $AuthorEmail -and $_.FileSystemObjectType -eq "File"}
 
$Resultset = @()
#Collect documents data
$ListItems | ForEach-Object {
    $Resultset += New-Object PSObject -Property ([Ordered] @{
        Name  = $_.FieldValues.FileLeafRef
        RelativeURL = $_.FieldValues.FileRef
        CreatedBy =  $_.FieldValues.Author.Email
        CreatedOn = $_.FieldValues.Created
        ModifiedBy =  $_.FieldValues.Editor.Email
        ModifiedOn = $_.FieldValues.Modified
        FileSizeInKB = $_.FieldValues.File_x0020_Size
    })
}
#Get Result set
$Resultset
