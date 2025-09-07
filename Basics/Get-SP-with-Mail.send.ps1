#Requires -Module Microsoft.Graph.Authentication,Microsoft.Graph.Applications,Microsoft.Graph.Identity.SignIns

# Connect to Microsoft Graph with required permissions
Connect-MgGraph 

# Get the Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

# Get all service principals (Enterprise Apps)
$servicePrincipals = Get-MgServicePrincipal -All

# Prepare result list
$result = @()

foreach ($sp in $servicePrincipals) {
    # Check App Role Assignments (Application permissions)
    $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
    foreach ($role in $appRoles) {
        if ($role.ResourceId -eq $graphSp.Id) {
            $appRole = $graphSp.AppRoles | Where-Object { $_.Id -eq $role.AppRoleId }
            if ($appRole.Value -eq "Mail.Send") {
                $result += [PSCustomObject]@{
                    AppName     = $sp.DisplayName
                    AppId       = $sp.AppId
                    Permission  = "Application - Mail.Send"
                }
            }
        }
    }

    # Check Delegated Permissions (OAuth2PermissionGrants)
    $delegatedPerms = Get-MgOauth2PermissionGrant -Filter "ClientId eq '$($sp.Id)'" -All
    foreach ($perm in $delegatedPerms) {
        if ($perm.ResourceId -eq $graphSp.Id -and $perm.Scope -match "\bMail.Send\b") {
            $result += [PSCustomObject]@{
                AppName     = $sp.DisplayName
                AppId       = $sp.AppId
                Permission  = "Delegated - Mail.Send"
            }
        }
    }
}

# Output the results
$result | Sort-Object AppName | Format-Table -AutoSize
