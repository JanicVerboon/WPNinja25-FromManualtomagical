#requires -module Microsoft.Graph.Authentication,Microsoft.Graph.Applications

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"

#Replace the Managed Identity ID below
$managedIdentityObjectId = "<Managed Identity Object ID>"
$permissions = "AuditLog.Read.All","Group.ReadWrite.All"

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