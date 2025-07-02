# Ensure Microsoft Graph module is installed and you're connected:
Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All", "Directory.Read.All"

# Get all users with sign-in activity and additional properties
$Users = Get-MgUser -All -Property 'UserPrincipalName', 'DisplayName', 'Surname', 'Mail', 'CreationType', 'UserType', 'OnPremisesSyncEnabled', 'SignInActivity', 'AccountEnabled'

# Results array
$results = @()

foreach ($user in $Users) {
    Write-Host "`nProcessing: $($user.UserPrincipalName)"

    $result = [PSCustomObject]@{
        DisplayName           = $user.DisplayName
        Surname               = $user.Surname
        UserPrincipalName     = $user.UserPrincipalName
        Email                 = $user.Mail
        CreationType          = $user.CreationType
        UserType              = $user.UserType
        OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
        LastSignInDate        = $user.SignInActivity.LastSignInDateTime
        AccountEnabled        = $user.AccountEnabled
        MFAStatus             = "Disabled"
        EmailMethod           = $false
        Fido2Method           = $false
        AppMethod             = $false
        PasswordMethod        = $false
        PhoneMethod           = $false
        SoftwareOathMethod    = $false
        TempAccessPassMethod  = $false
        HelloForBusiness      = $false
    }

    try {
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.UserPrincipalName
        foreach ($method in $authMethods) {
            switch ($method.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.emailAuthenticationMethod" {
                    $result.EmailMethod = $true
                    $result.MFAStatus = "Enabled"
                }
                "#microsoft.graph.fido2AuthenticationMethod" {
                    $result.Fido2Method = $true
                    $result.MFAStatus = "Enabled"
                }
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                    $result.AppMethod = $true
                    $result.MFAStatus = "Enabled"
                }
                "#microsoft.graph.passwordAuthenticationMethod" {
                    $result.PasswordMethod = $true
                    if ($result.MFAStatus -ne "Enabled") {
                        $result.MFAStatus = "Disabled"
                    }
                }
                "#microsoft.graph.phoneAuthenticationMethod" {
                    $result.PhoneMethod = $true
                    $result.MFAStatus = "Enabled"
                }
                "#microsoft.graph.softwareOathAuthenticationMethod" {
                    $result.SoftwareOathMethod = $true
                    $result.MFAStatus = "Enabled"
                }
                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                    $result.TempAccessPassMethod = $true
                    $result.MFAStatus = "Enabled"
                }
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                    $result.HelloForBusiness = $true
                    $result.MFAStatus = "Enabled"
                }
            }
        }
    }
    catch {
        Write-Warning "Could not retrieve auth methods for $($user.UserPrincipalName): $_"
    }

    $results += $result
}

# Export to CSV
$results | Export-Csv -Path "C:\EntraUserMFAAndSignIn.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Export complete: C:\EntraUserMFAAndSignIn.csv"
