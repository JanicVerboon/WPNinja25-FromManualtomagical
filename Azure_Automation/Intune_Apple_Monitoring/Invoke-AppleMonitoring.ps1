
#Required -Modules Microsoft.Graph.Authentication,Microsoft.Graph.DeviceManagement.Administration,Microsoft.Graph.Beta.DeviceManagement.Enrollment,Microsoft.Graph.Devices.CorporateManagement,Microsoft.Graph.Users.Actions

function Invoke-AppleMonitoring {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $SenderMail,

        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $ReceipentMail,

        [Parameter(Mandatory = $true)]
        [int]
        [ValidateNotNullOrEmpty()]
        $treshold,

        [Parameter(Mandatory = $false)]
        [switch]
        $IncludeADETokens,

        [Parameter(Mandatory = $false)]
        [switch]
        $IncludeVPPTokens,

        [Parameter(Mandatory = $false)]
        [int]
        [ValidateNotNullOrEmpty()]
        $VPPLicenseTreshold,

        [Parameter(Mandatory = $false)]
        [switch]
        $IncludeAppleLOBApps
    )

    begin {
        $today = Get-Date
        $EmployeeEmailRecipient = @{
            EmailAddress = @{
                address = $ReceipentMail
            }
        }
        $EmployeeHtmlBody = "<p>Dear Support,</p><p>This is an Alert to notify you that the following Apple Tokens are about to expire:</p>"
    }

    process {
        $APNS = Get-MgDeviceManagementApplePushNotificationCertificate -Property Id, AppleIdentifier, ExpirationDateTime
        $apnsexpirationcheck = New-TimeSpan -Start $today -End $APNS.ExpirationDateTime
        If ($apnsexpirationcheck.days -lt $treshold) {
            $EmployeeHtmlBody += "<h4>APNS Certificate</h4><p>The Apns Certificate will expire in $($apnsexpirationcheck.days) Days. Make sure to renew it using the Apple ID: $($APNS.AppleIdentifier)</p>"
        }

        If ($IncludeADETokens.IsPresent) {
            $ADETokens = Get-MgBetaDeviceManagementDepOnboardingSetting -Property Id, AppleIdentifier, TokenExpirationDateTime, TokenName, LastSyncErrorCode,LastSuccessfulSyncDateTime -All
            $ADETokensatRisk = $ADETokens | Where-Object { ($_.TokenExpirationDateTime -lt $today.AddDays($treshold)) -or ($_.LastSyncErrorCode -eq 3) }

            If ($ADETokensatRisk) {
                $EmployeeHtmlBody += "<h4>ADE Tokens at Risk</h4><p>The following ADE Tokens are at risk, check if they haven't expired yet or if the new T&C must be accepted within Apple Business Manager</p><table border='1'><tr><th>Token Name</th><th>Token Expiration</th><th>Last Successful Sync</th></tr>"
                $ADETokensatRisk | ForEach-Object {
                    $EmployeeHtmlBody += "<tr><td>$($_.TokenName)</td><td>$($_.TokenExpirationDateTime)</td><td>$($_.LastSuccessfulSyncDateTime)</td></tr>"
                }
                $EmployeeHtmlBody += "</table>"
            }
        }

        If ($IncludeVPPTokens.IsPresent) {
            $VPPTokens = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens?$top=100" -Method GET).Value
            $VPPTokensAtrisk = $VPPTokens | Where-Object { $_.expirationDateTime -lt $today.AddDays($treshold) }

            If ($VPPTokensAtrisk) {
                $EmployeeHtmlBody += "<h4>VPP Tokens at Risk</h4><p>Please ensure that the following VPP Tokens get renewed before they expire!.</p><table border='1'><tr><th>Token Name</th><th>Expiration Time</th></tr>"
                $VPPTokensAtrisk | ForEach-Object {
                    $EmployeeHtmlBody += "<tr><td>$($_.DisplayName)</td><td>$($_.expirationDateTime)</td></tr>"
                }
                $EmployeeHtmlBody += "</table>"
            }

            If ($null -ne $VPPLicenseTreshold) {
                $AllVPPApps = Get-MgDeviceAppMgtMobileApp -Filter "isof('microsoft.graph.iosVppApp')" -All | Select-Object DisplayName, AdditionalProperties
                $VPPAppInfos = $AllVPPApps | ForEach-Object { [PSCustomObject]@{
                        Id = $_.Id
                        DisplayName = $_.DisplayName
                        VPPTokenName = $_.Additionalproperties["vppTokenOrganizationName"]
                        usedLicenseCount = $_.Additionalproperties["usedLicenseCount"]
                        totalLicenseCount = $_.Additionalproperties["totalLicenseCount"]
                        Freelicenses = $_.Additionalproperties["totalLicenseCount"] - $_.Additionalproperties["usedLicenseCount"]
                        AssociatedTokenName = $_.AdditionalProperties["vppTokenOrganizationName"]
                    }
                }
                $VPPAppsatRisk = $VPPAppInfos | Where-Object { $_.Freelicenses -LT $VPPLicenseTreshold }

                If ($VPPAppsatRisk) {
                    $EmployeeHtmlBody += "<h4>VPP Licenses</h4><p>The following VPP apps are about to run out of licenses, sign in to Apple Business Manager and acquire more licenses</p><table border='1'><tr><th>VPP App Name</th><th>Associated Token</th><th>Free Licenses</th></tr>"
                    $VPPAppsatRisk | ForEach-Object {
                        $EmployeeHtmlBody += "<tr><td>$($_.DisplayName)</td><td>$($_.AssociatedTokenName)</td><td>$($_.Freelicenses)</td></tr>"
                    }
                    $EmployeeHtmlBody += "</table>"
                }
            }
        }

        If ($IncludeAppleLOBApps.IsPresent) {
            $AllLOBApps = Get-MgDeviceAppMgtMobileApp -Filter "isof('microsoft.graph.iosLobApp') or isof('microsoft.graph.managedIOSLobApp')" -All | Select-Object Id, DisplayName, Publisher, AdditionalProperties
            $LOBAPPInfos = $AllLOBApps | ForEach-Object { [PSCustomObject]@{
                    Id = $_.Id
                    DisplayName = $_.DisplayName
                    Publisher = $_.Publisher
                    ExpirationDateTime = Get-Date $_.AdditionalProperties.expirationDateTime
                }
            }
            $LOBAppsatRisk = $LOBAPPInfos | Where-Object { $_.expirationDateTime -lt $today.AddDays($treshold) }

            If ($LOBAppsatRisk) {
                $EmployeeHtmlBody += "<h4>Apple LOB Apps at Risk</h4><p>Please ensure that the provisioning profile of the following LOB Apps get renewed.</p><table border='1'><tr><th>LOB App Name</th><th>Publisher</th><th>Expiration</th></tr>"
                $LOBAppsatRisk | ForEach-Object {
                    $EmployeeHtmlBody += "<tr><td>$($_.DisplayName)</td><td>$($_.Publisher)</td><td>$($_.ExpirationDateTime)</td></tr>"
                }
                $EmployeeHtmlBody += "</table>"
            }
        }

        $EmployeeHtmlBody += "<p>Please take action on the above mentioned issues!</p><p>Best regards</p><p>Intune Automation</p>"
        $EmployeeHtmlMsg = $EmployeeHtmlHeader + $EmployeeHtmlBody

        $EmployeeMessageBody = @{
            content = "$($EmployeeHtmlMsg)";
            ContentType = "html"
        }

        $EmployeeMessage = @{
            subject = "Alert! Apple Management requires Attention";
            toRecipients = @($EmployeeEmailRecipient);
            body = $EmployeeMessageBody;
            attachments = @($EmployeePfxAttachment)
        }

        Send-MgUserMail -UserId $SenderMail -Message $EmployeeMessage
    }
}

Connect-MgGraph -Identity -ErrorAction Stop
Invoke-AppleMonitoring -SenderMail "" -receipentmail "" -treshold 365 -IncludeADETokens -IncludeVPPTokens -VPPLicenseTreshold 50 -IncludeAppleLOBApps