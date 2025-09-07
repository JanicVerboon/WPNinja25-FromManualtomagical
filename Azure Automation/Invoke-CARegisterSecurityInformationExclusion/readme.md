# Introduction

If an organization has turned on the "registration campaign" feature in Entra ID, users will be prompted to register the Authenticator app as MFA method, if the haven't registered any of these methods:
* Authenticator Push
* Authenticator Passwordless

Users who have only registered for:
* SMS
* Phone Call
* Authenticator Code (Software OATH Token)

Will be affected by the registration campaign.
But if the users are targeted by a Conditional Access Policy, which blocks the registration of Security Information, the nudge to the registration campaign will never happen.

### Example
* Organization XYZ has implemented a Conditional Access policy which requires MFA if users access any application from an unmanaged device
* Organization XYZ has implemented a Conditional Access policy which blocks the registration of security information from unmanaged devices
* User currently only has SMS & Phone registered.
* User accesses an application from an unmanaged device, since he doens't have Authenticator Push setup he should be prompted, but won't be because the second policy would block him from registering security information.
* Therefore the user won't be prompted to register a more secure MFA method, unless he would be asked to do MFA from a managed device.

# Features 

This script will do the following:
* Get the User details from the [Authentication methods user registration details report](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails/fromNav/)
* Checks which users don't have Authenticator Push or Phone Sign in setup
* Checks which of these users have at least 1 MFA method, which isn't Windows Hello or a Temporary Acess pass.
* Adds these users to a group.

This group can then be excluded from the Conditional Access Policy, which blocks the Security Information registration from untrusted devices.
On the next sign in from a unmanaged device, the user will be prompted to setup the Authenticator app. Once a user has setup the Authenticator app & this information is reflected in the report, he will be removed from the exclusion group during the next run of the script.

The only case where this script might pose a security risk is, when:
* A user only has SMS & Phone setup, therefore gets added to the group
* The admin requires re-register MFA methods
* The require re-register isn't yet reflected in the report. So the user is still in the exclusion group
* An attacker knows the credentials, accesses the users account from an unmanaged device and then gets prompted to register security information.

> [IMPORTANT]
> According to the [Microsoft Docs](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity#limitations), the update of the report data may be delayed due to latency to up to a few hours!


# Modules
The script requires the following Modules to run:
* Module Microsoft.Graph.Authentication
* Microsoft.Graph.Reports
* Microsoft.Graph.Users
* Microsoft.Graph.Groups

# Required Graph permissions

The Managed Identity of the Automation Account requires the following permissions:

| Permissions | Description |
| ----- | ------ |
| AuditLog.Read.All | To read the Authentication Report |
| Group.ReadWrite.All | To add and remove group memebers |

 The required Graph permissions can be assigned using the following [script](./Assign_ManagedIdentity_permissions.ps1) 

# Parameters 

The script supports the following Parameter

| Parameter | Mandatory | Description |
| ----- | ---- | ----- |
| GroupId | Yes | This parameter defines the Group which the script will add / remove from. This group can then also be used to exclude those users from a Conditional Access policy |
