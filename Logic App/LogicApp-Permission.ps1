Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"
$managedIdentityObjectId = "<Managed Identity Object ID>"

$permissions = "Machine.ReadWrite.All"
$defenderApi = Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'"
$permissions = $graphApi.AppRoles | Where-Object { $_.Value -in $permissions -and $_.AllowedMemberTypes -contains "Application" }
$permissions | ForEach-Object {
    $appRoleAssignment = @{
        ServicePrincipalId = $managedIdentityObjectId
        PrincipalId        = $managedIdentityObjectId
        ResourceId         = $defenderApi.Id 
        AppRoleId          = $PSItem.Id 
    }
    New-MgServicePrincipalAppRoleAssignment @appRoleAssignment
}
