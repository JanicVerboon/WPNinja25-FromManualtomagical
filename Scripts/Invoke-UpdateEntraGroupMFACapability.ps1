# Invoke-UpdateEntraGroupMFACapability.ps1

## Description

This PowerShell script automates the management of Entra ID (Azure AD) group memberships based on users' Multi-Factor Authentication (MFA) capability status. It connects to Microsoft Graph and retrieves user registration details from the Entra ID MFA report. The script then ensures that two specified Entra ID groups are kept up to date:

- One group contains all users who are MFA capable.
- The other group contains all users who are not MFA capable.

The script adds or removes users from these groups as needed, so that group membership always reflects the current MFA capability status of users. This is useful for scenarios such as applying Conditional Access policies based on MFA capability.

The script requires the Microsoft Graph PowerShell modules and appropriate permissions (such as `AuditLog.Read.All` and `Group.ReadWrite.All`). It is intended for administrators who want to automate group management for security and compliance purposes.

#Requires -Module Microsoft.Graph.Authentication,Microsoft.Graph.Reports,Microsoft.Graph.Users,Microsoft.Graph.Groups

#Permissions
# AuditLog.Read.All = To read the Authentication Report
# Group.ReadWrite.All = Read Group Members / Add & remove group members

function Add-GroupMember {
    <#
    .SYNOPSIS
        Add Member to Entra Group

    .DESCRIPTION
        Add a specific User to a specific Entra Group.

    .PARAMETER usergroup
        Entra Group where users should be added

    .PARAMETER userid
        User which should be added

    .EXAMPLE
        Add-GroupMember -usergroup 682c860e-86ad-472a-adaa-467f1fb06842 -userid 78006026-e438-4989-af40-bbf479d2465d

    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        #DeviceGroup
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $usergroup,

        #DeviceObjectId
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $userid
    )

    process {
        if ($PSCmdlet.ShouldProcess("Adding $userid to $usergroup")) {
            New-MgGroupMember -GroupId $usergroup -DirectoryObjectId $userid
        }
    }
}

function Remove-GroupMember {
    <#
    <#
    .SYNOPSIS
        Remove Member from Entra Group

    .DESCRIPTION
        Remove a specific User to a specific Entra Group.

    .PARAMETER usergroup
        Entra Group where users should be removed

    .PARAMETER userid
        User which should be removed

    .EXAMPLE
        Remve-GroupMember -usergroup 682c860e-86ad-472a-adaa-467f1fb06842 -userid 78006026-e438-4989-af40-bbf479d2465d
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        #DeviceGroup
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $usergroup,

        #DeviceObjectId
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $userid
    )

    process {
        if ($PSCmdlet.ShouldProcess("Removing $userid from $usergroup")) {
            Remove-MgGroupMemberDirectoryObjectByRef -GroupId $usergroup -DirectoryObjectId $userid
        }
    }
}

function Invoke-UpdateEntraGroupMFACapability {
    <#
    .SYNOPSIS
        Add MFA Capable or not capable users to Entra ID groups

    .DESCRIPTION
        Add all MFA capable users to a specific Entra Group and all not capable users to another Entra Group. This two groups can then can be used for example Conditional Access Policies. 
        Data is based on the Entra ID MFA Report: https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails

    .PARAMETER GroupIdMFACapable
        $GroupIdMFACapable = Entra Group which should contain all MFA Capable Group
    
    .PARAMETER GroupIdMFANotCapable
        $GroupIdMFANotCapable = Entra Group which should contain all not MFA Capable Group

    .EXAMPLE
        Invoke-UpdateEntraIDGroupMFACapability -GroupIdMFACapable "a8950f68-2243-450a-a883-a3afee393fb4" -GroupIdMFANotCapable "682c860e-86ad-472a-adaa-467f1fb06842"
    #>

    [CmdletBinding()]
    Param
    (
        #Group
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $GroupIdMFACapable,
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $GroupIdMFANotCapable
    )

    Begin {
        Try {
            Connect-MgGraph -Identity -NoWelcome
        }
        Catch {
            Throw "Couldn't Connect to Graph... Error: $_"
        } 
    }
    Process {


        # Getting all Users which are not MFA Capable based on the Entra ID MFA Report
        # https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails
        [System.Collections.Generic.HashSet[string]] $NotMFACapableUsers = [System.Collections.Generic.HashSet[string]]::new()
        Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsMfaCapable -eq $false } | ForEach-Object { $null = $NotMFACapableUsers.Add($_.Id) }

        # Getting all Users which are  MFA Capable based on the Entra ID MFA Report
        # https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails
        [System.Collections.Generic.HashSet[string]] $MFACapableUsers = [System.Collections.Generic.HashSet[string]]::new()
        Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsMfaCapable -eq $true } | ForEach-Object { $null = $MFACapableUsers.Add($_.Id) }

            
        try {
            # Get all Group Members from the MFA Capable Group
            [System.Collections.Generic.HashSet[string]] $EntraGroupMFACapable = [System.Collections.Generic.HashSet[string]]::new()
            Get-MgGroupMember -GroupId $GroupIdMFACapable -All -ErrorAction Stop | ForEach-Object { $null = $EntraGroupMFACapable.Add($_.Id) }
        }
        catch {
            Throw "Couldn't obtain the members of the groups $($GroupIdMFACapable)"
            
        }
            
        try {
            # Get all Group Members from the Not MFA Capable Group
            [System.Collections.Generic.HashSet[string]] $EntraGroupMFANotCapable = [System.Collections.Generic.HashSet[string]]::new()
            Get-MgGroupMember -GroupId $GroupIdMFANotCapable -All -ErrorAction Stop | ForEach-Object { $null = $EntraGroupMFANotCapable.Add($_.Id) }
        }
        catch {
            
            Throw "Couldn't obtain the members of the groups $($EntraGroupMFANotCapable)"
        }

        # Important: to allow null-and failsave comparison we work with hashsets and explicit type conversion to determine devices that need to be added or removed
        # https://learn.microsoft.com/en-US/dotnet/api/system.collections.generic.hashset-1?view=net-7.0
        [System.Collections.Generic.HashSet[string]] $membersToAddNotCapableGroup = [System.Collections.Generic.HashSet[string]]::new($NotMFACapableUsers)
        $membersToAddNotCapableGroup.ExceptWith($EntraGroupMFANotCapable)

        [System.Collections.Generic.HashSet[string]] $membersToAddMFACapableGroup = [System.Collections.Generic.HashSet[string]]::new($MFACapableUsers)
        $membersToAddMFACapableGroup.ExceptWith($EntraGroupMFACapable)

        [System.Collections.Generic.HashSet[string]] $membersToRemoveCapableGroup = [System.Collections.Generic.HashSet[string]]::new($EntraGroupMFACapable)
        $membersToRemoveCapableGroup.IntersectWith($NotMFACapableUsers)

        [System.Collections.Generic.HashSet[string]] $membersToRemoveNotCapableGroup = [System.Collections.Generic.HashSet[string]]::new($EntraGroupMFANotCapable)
        $membersToRemoveNotCapableGroup.IntersectWith($MFACapableUsers)
            
        Write-Warning "There are $($membersToAddNotCapableGroup.Count) users to add to the Not Capable Group and $($membersToAddMFACapableGroup.Count) users to add to the Capable Group."
        Write-Warning "There are $($membersToRemoveCapableGroup.Count) users to remove from the Capable Group and $($membersToRemoveNotCapableGroup.Count) users to remove from the not capable Group."

        # Add users to to not capable group
        $membersToAddNotCapableGroup | ForEach-Object {
            try {
                Write-Verbose "Adding user $($_) to group $($devicegroup.DisplayName) $($GroupIdMFANotCapable)"
                Add-GroupMember -usergroup $GroupIdMFANotCapable -userid $_
            }
            catch {
                Write-Warning "Couldn't add user $($_) to group $($devicegroup.DisplayName) $($GroupIdMFANotCapable)"
            }
        }

        # Add users to to capable group
        $membersToAddMFACapableGroup | ForEach-Object {
            try {
                Write-Verbose "Adding user $($_) to group $($devicegroup.DisplayName) $($GroupIdMFACapable)"
                Add-GroupMember -usergroup $GroupIdMFACapable -userid $_
            }
            catch {
                Write-Warning "Couldn't add user $($_) to group $($devicegroup.DisplayName) $($GroupIdMFACapable)"
            }
        }
        
        # Remove users from capable group
        $membersToRemoveCapableGroup | ForEach-Object {
            try {
                Write-Verbose "Removing user $($_) from group $($GroupIdMFACapable)"
                Remove-GroupMember -usergroup $GroupIdMFACapable -userid $_
            }
            catch {
                Write-Warning "Couldn't remove user $($_) from group $($GroupIdMFACapable)"
            }
        }

        # Remove users from not capable group
        $membersToRemoveNotCapableGroup | ForEach-Object {
            try {
                Write-Verbose "Removing user $($_) from group $($GroupIdMFANotCapable)"
                Remove-GroupMember -usergroup $GroupIdMFANotCapable -userid $_
            }
            catch {
                Write-Warning "Couldn't remove user $($_) from group $($GroupIdMFANotCapable)"
            }
        }
    }
}

Invoke-UpdateEntraGroupMFACapability -GroupIdMFACapable 'OBJECT ID MFA CAPABLE GROUP' -GroupIdMFANotCapable 'OBJECT ID MFA NOT CAPABLE GROUP'