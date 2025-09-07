#Requires -Module Microsoft.Graph.Authentication,Microsoft.Graph.Reports,Microsoft.Graph.Users,Microsoft.Graph.Groups

#Permissions
# AuditLog.Read.All = To read the Authentication Report
# Group.ReadWrite.All = Read Group Members / Add & remove group members

function Add-GroupMember {
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
            Remove-MgGroupMemberByRef -GroupId $usergroup -DirectoryObjectId $userid
        }
    }
}

function Invoke-CARegisterSecurityInformationExclusion {

    <#
    .SYNOPSIS
    Invoke-CARegisterSecurityInformationExclusion

    .DESCRIPTION
    Adds users with MFA registered to a group, which then can be linked to be excluded from CA policies
    which block MFA registration from untrusted devices.
    The goal of this is to also nudge users which alredy have MFA to register for the Authenticator app.

    .INPUTS
    GroupId, the Azure AD Group, the user should be added to.

    .NOTES
    15.11.2023 / v 1.0 Janic Verboon
#>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        #Group
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $GroupId
    )

    # Data Collection, getting the details from the MFA report which is available at:
    # https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails
    $data = Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Select-Object Id, UserPrincipalName, UserType, Methodsregistered, IsAdmin

    #Defining the exclusionmethods, eg if a user has already registered AuthenticatorPush or the Authenticator Passwordless experience, he shouldn't be in scope
    $Exclusionmethods = 'microsoftAuthenticatorPush' , 'microsoftAuthenticatorPasswordless'

    #Creating the report object
    $report = [System.Collections.Generic.List[PSCustomObject]]::new()

    #Parsing through all users obtained from the MFA Report
    foreach ($user in $data) {

        #Checking if the user has the Authenicator with Push or Passwordless registered.
        $validation = if ($Exclusionmethods | Where-Object { $user.MethodsRegistered -contains $_ }) { $True } Else { $false }

        #Adding data to the report
        $report.Add( [PSCustomObject]@{

                Id               = $user.Id
                UPN              = $user.UserPrincipalName
                UserType         = $user.UserType
                MFAMethods       = $user.MethodsRegistered
                MFAMethodsCount  = $user.MethodsRegistered.Count
                HasAuthenticator = $validation

            })
    }

    # Important: to allow null-and failsave comparison we work with hashsets and explicit type conversion to determine devices that need to be added or removed
    # https://learn.microsoft.com/en-US/dotnet/api/system.collections.generic.hashset-1?view=net-7.0
    [System.Collections.Generic.HashSet[string]] $inScopeUsers = [System.Collections.Generic.HashSet[string]]::new()

    #Adding Users to the Scope which are of type member, don't have the Authenticator registered and have at least one MFA Method.
    Write-Output "Adding users to the Scope..."
    $report | Where-Object { (($_.Usertype -eq "member") -and ($_.HasAuthenticator -eq $False) -and ($_.MFAMethodsCount -ne 0)) } | ForEach-Object {
        $null = $inScopeUsers.Add($_.Id)
        Write-Verbose "Adding User $($_.UserPrincipalName)..."

    }
    Write-Verbose "There are $($inScopeUsers.Count) Users in Scope after adding in the users..."

    Write-Output "Checking if users must be removed from the Scope"
    #Removing Users from the Scop wich just have one Auth method and this method is a TAP or WHfB, since those either expire or can't be used.
    $report | Where-Object { ($_.MFAMethodsCount -eq 1 ) -and (($_.MFAMethods -eq "windowsHelloForBusiness") -or ($_.MFAMethods -eq "temporaryAccessPass" )) } | ForEach-Object {
        $null = $inScopeUsers.Remove($_.Id)
        Write-Verbose "Removing User $($_.UserPrincipalName)..."
    }
    Write-Verbose "There are $($inScopeUsers.Count) Users in Scope after removing the users which only have 1 method registered and this method is a TAP or WHfB"

    Write-Output "There are $($inScopeUsers.count) users in scope"

    # Getting current Members of the device group
    try {
        [System.Collections.Generic.HashSet[string]] $UserGroupMembers = [System.Collections.Generic.HashSet[string]]::new()
        Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop | ForEach-Object { $null = $UserGroupMembers.Add($_.Id) }
    } catch {
        Throw "Couldn't obtain the members of the group $($GroupId)"
    }

    # using ExceptWith to determine devices that need to be added or removed hash sets need to be copied via constructor to avoid modifying the original set
    [System.Collections.Generic.HashSet[string]] $membersToAdd = [System.Collections.Generic.HashSet[string]]::new($inScopeUsers)
    $memberstoAdd.ExceptWith($UserGroupMembers)

    [System.Collections.Generic.HashSet[string]] $membersToRemove = [System.Collections.Generic.HashSet[string]]::new($UserGroupMembers)
    $membersToRemove.ExceptWith($inScopeUsers)

    Write-Output "There are $($membersToAdd.Count) users to add and $($membersToRemove.Count) users to remove from group ($($GroupId))"

    $memberstoAdd | ForEach-Object {
        try {
            Write-Verbose "Adding user $($_) to group $($devicegroup.DisplayName)  ($($GroupId))"
            Add-GroupMember -usergroup $GroupId -userid $_
        } catch {
            Write-Error "Couldn't add device $($_) to group $($devicegroup.DisplayName)  ($($GroupId))"
        }
    }

    $membersToRemove | ForEach-Object {
        try {
            Write-Verbose "Removing user $($_) from group ($($GroupId))"
            Remove-GroupMember -usergroup $GroupId -userid $_
        } catch {
            Write-Error "Couldn't remove user $($_) from group ($($GroupId))"
        }
    }

}
Try {
    Connect-MgGraph -Identity -NoWelcome
} Catch {
    Throw "Couldn't Connect to Graph... Error: $_"
}

Invoke-CARegisterSecurityInformationExclusion -GroupId "<GroupId>"
