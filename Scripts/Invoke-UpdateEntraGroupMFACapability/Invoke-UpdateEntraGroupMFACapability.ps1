#Requires -Module Microsoft.Graph.Authentication,Microsoft.Graph.Reports,Microsoft.Graph.Users,Microsoft.Graph.Groups
<#
.SYNOPSIS
    Synchronizes Entra ID group memberships based on the User registration details report.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves user registration details from the Entra ID MFA report.
    It ensures that two specified Entra ID groups are kept up to date:
      - One group contains all users who are MFA capable.
      - The other group contains all users who are not MFA capable.
    Users are added or removed from these groups as needed, so that group membership always reflects the current MFA capability status.
    This is useful for scenarios such as applying Conditional Access policies based on MFA capability.

    The script requires the Microsoft Graph PowerShell modules and appropriate permissions:
      - AuditLog.Read.All (to read the Authentication Report)
      - Group.ReadWrite.All (to read and modify group members)

    Author: L. Ambrozzo
    Last updated: 07.09.2025 / V1.0
#>

function Add-GroupMember {
    <#
    .SYNOPSIS
        Adds a user to an Entra ID group.

    .DESCRIPTION
        Adds a specific user to a specific Entra ID group using Microsoft Graph.

    .PARAMETER usergroup
        The Entra ID group ObjectId to which the user should be added.

    .PARAMETER userid
        The ObjectId of the user to add.

    .EXAMPLE
        Add-GroupMember -usergroup 682c860e-86ad-472a-adaa-467f1fb06842 -userid 78006026-e438-4989-af40-bbf479d2465d
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $usergroup,

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
    .SYNOPSIS
        Removes a user from an Entra ID group.

    .DESCRIPTION
        Removes a specific user from a specific Entra ID group using Microsoft Graph.

    .PARAMETER usergroup
        The Entra ID group ObjectId from which the user should be removed.

    .PARAMETER userid
        The ObjectId of the user to remove.

    .EXAMPLE
        Remove-GroupMember -usergroup 682c860e-86ad-472a-adaa-467f1fb06842 -userid 78006026-e438-4989-af40-bbf479d2465d
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $usergroup,

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
        Updates Entra ID groups based on users' MFA capability.

    .DESCRIPTION
        Adds all MFA capable users to one Entra ID group and all not MFA capable users to another.
        Ensures group membership always matches the current MFA capability status from the Entra ID MFA report.

    .PARAMETER GroupIdMFACapable
        The ObjectId of the group for MFA capable users.

    .PARAMETER GroupIdMFANotCapable
        The ObjectId of the group for users not MFA capable.

    .EXAMPLE
        Invoke-UpdateEntraGroupMFACapability -GroupIdMFACapable "a8950f68-2243-450a-a883-a3afee393fb4" -GroupIdMFANotCapable "682c860e-86ad-472a-adaa-467f1fb06842"
    #>

    [CmdletBinding()]
    Param
    (
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
        # Retrieve all users who are not MFA capable
        [System.Collections.Generic.HashSet[string]] $NotMFACapableUsers = [System.Collections.Generic.HashSet[string]]::new()
        Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsMfaCapable -eq $false } | ForEach-Object { $null = $NotMFACapableUsers.Add($_.Id) }

        # Retrieve all users who are MFA capable
        [System.Collections.Generic.HashSet[string]] $MFACapableUsers = [System.Collections.Generic.HashSet[string]]::new()
        Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsMfaCapable -eq $true } | ForEach-Object { $null = $MFACapableUsers.Add($_.Id) }

        try {
            # Get all current members of the MFA Capable group
            [System.Collections.Generic.HashSet[string]] $EntraGroupMFACapable = [System.Collections.Generic.HashSet[string]]::new()
            Get-MgGroupMember -GroupId $GroupIdMFACapable -All -ErrorAction Stop | ForEach-Object { $null = $EntraGroupMFACapable.Add($_.Id) }
        }
        catch {
            Throw "Couldn't obtain the members of the group $($GroupIdMFACapable)"
        }
            
        try {
            # Get all current members of the Not MFA Capable group
            [System.Collections.Generic.HashSet[string]] $EntraGroupMFANotCapable = [System.Collections.Generic.HashSet[string]]::new()
            Get-MgGroupMember -GroupId $GroupIdMFANotCapable -All -ErrorAction Stop | ForEach-Object { $null = $EntraGroupMFANotCapable.Add($_.Id) }
        }
        catch {
            Throw "Couldn't obtain the members of the group $($GroupIdMFANotCapable)"
        }

        # Calculate which users need to be added or removed from each group
        [System.Collections.Generic.HashSet[string]] $membersToAddNotCapableGroup = [System.Collections.Generic.HashSet[string]]::new($NotMFACapableUsers)
        $membersToAddNotCapableGroup.ExceptWith($EntraGroupMFANotCapable)

        [System.Collections.Generic.HashSet[string]] $membersToAddMFACapableGroup = [System.Collections.Generic.HashSet[string]]::new($MFACapableUsers)
        $membersToAddMFACapableGroup.ExceptWith($EntraGroupMFACapable)

        [System.Collections.Generic.HashSet[string]] $membersToRemoveCapableGroup = [System.Collections.Generic.HashSet[string]]::new($EntraGroupMFACapable)
        $membersToRemoveCapableGroup.IntersectWith($NotMFACapableUsers)

        [System.Collections.Generic.HashSet[string]] $membersToRemoveNotCapableGroup = [System.Collections.Generic.HashSet[string]]::new($EntraGroupMFANotCapable)
        $membersToRemoveNotCapableGroup.IntersectWith($MFACapableUsers)
            
        Write-Warning "There are $($membersToAddNotCapableGroup.Count) users to add to the Not Capable Group and $($membersToAddMFACapableGroup.Count) users to add to the Capable Group."
        Write-Warning "There are $($membersToRemoveCapableGroup.Count) users to remove from the Capable Group and $($membersToRemoveNotCapableGroup.Count) users to remove from the Not Capable Group."

        # Add users to the Not MFA Capable group
        $membersToAddNotCapableGroup | ForEach-Object {
            try {
                Add-GroupMember -usergroup $GroupIdMFANotCapable -userid $_
            }
            catch {
                Write-Warning "Couldn't add user $($_) to group $($GroupIdMFANotCapable)"
            }
        }

        # Add users to the MFA Capable group
        $membersToAddMFACapableGroup | ForEach-Object {
            try {
                Add-GroupMember -usergroup $GroupIdMFACapable -userid $_
            }
            catch {
                Write-Warning "Couldn't add user $($_) to group $($GroupIdMFACapable)"
            }
        }
        
        # Remove users from the MFA Capable group
        $membersToRemoveCapableGroup | ForEach-Object {
            try {
                Remove-GroupMember -usergroup $GroupIdMFACapable -userid $_
            }
            catch {
                Write-Warning "Couldn't remove user $($_) from group $($GroupIdMFACapable)"
            }
        }

        # Remove users from the Not MFA Capable group
        $membersToRemoveNotCapableGroup | ForEach-Object {
            try {
                Remove-GroupMember -usergroup $GroupIdMFANotCapable -userid $_
            }
            catch {
                Write-Warning "Couldn't remove user $($_) from group $($GroupIdMFANotCapable)"
            }
        }
    }
}

# Replace the group IDs with your actual group Object IDs
Invoke-UpdateEntraGroupMFACapability -GroupIdMFACapable 'OBJECT ID MFA CAPABLE GROUP' -GroupIdMFANotCapable 'OBJECT ID MFA NOT CAPABLE GROUP'