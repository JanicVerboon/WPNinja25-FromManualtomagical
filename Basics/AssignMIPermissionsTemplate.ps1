#requires -module Microsoft.Graph.Authentication, Microsoft.Graph.Applications

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"
#Replace this with the Id of your Managed Identity
$managedIdentityObjectId = "<Managed Identity Object ID>"

#Add the Graph permissions that you actually require
$permissions = "DeviceManagementServiceConfig.ReadWrite.All", "Device.Read.All"

$graphApi = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$permissions = $graphApi.AppRoles | Where-Object { $_.Value -in $permissions -and $_.AllowedMemberTypes -contains "Application" }

$permissions | ForEach-Object {

    $appRoleAssignment = @{
        ServicePrincipalId = $managedIdentityObjectId
        PrincipalId        = $managedIdentityObjectId
        ResourceId         = $graphApi.Id 
        AppRoleId          = $PSItem.Id 
    }

    New-MgServicePrincipalAppRoleAssignment @appRoleAssignment
}
