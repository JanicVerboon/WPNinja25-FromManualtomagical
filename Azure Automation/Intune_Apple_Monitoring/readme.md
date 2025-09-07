# Introduction

This guide describes how to implement the Apple Monitoring script offered by baseVISION as part of the Intune for iOS and Android service. 
The script should be implemented using an Azure Automation account. Authentication should be performed using a system assigned managed Identity. 

# Features
The script performs the following checks: 
* Checks if the APNS certificate is about to expire
* Checks if the ADE Token is about to expire
* Checks if the ADE Token is unable to sync. new devices because the updated Terms & Conditions weren’t accepted.
* Checks if the VPP Token is about to expire
* Checks if any of the added VPP tokens are about to run out of free licenses
* Checks if the signing certificate of a iOS LOB App is about to expire

# Modules
In order that the script can run successfully, the following Modules must be added to the Automation account: 
* Microsoft.Graph.Authentication
* Microsoft.Graph.DeviceManagement.Administration
* Microsoft.Graph.Beta.DeviceManagement.Enrollment
* Microsoft.Graph.Devices.CorporateManagement
* Microsoft.Graph.Users.Actions

# Required Graph permissions

| Permission | Description |
| ---- | ----- |
| DeviceManagementManagedDevices.Read.All | Required to read the Apple APNS certificate information
|  DeviceManagementServiceConfig.Read.All | Required to read the ADE Token & VPP Token information |
| DeviceManagementApps.Read.All | Required to read VPP apps & LOB Apps |

The required Graph permissions can be assigned using the following prepared [script](./Assign_ManagedIdentityPermissions.ps1)

Additionally the Managed Identity must be allowed to send mails. 
This can be achieved using the following code:

```powershell
# This script lists all running processes
Connect-ExchangeOnline
#Replace the AppId & Object ID with the values of your Managed Identity, we also recommend to use the same DisplayName as your ManagedIdentity
New-ServicePrincipal -AppId <AppId> -ObjectId <ObjectId> -DisplayName "%DisplayName%"

#Define a group whose members are allowed to send mails and create a role assignment based on it: 
New-ManagementRoleAssignment -App <AppID> -Role "Application Mail.Send" -RecipientGroupScope <groupid>
```
> More information about this topic can be found in [Jan Bakkers excellent blog post](https://janbakker.tech/a-love-story-about-role-based-access-control-for-applications-in-exchange-online-managed-identities-entra-id-admin-units-and-graph-api/)

#Paramters

The script supports the following paramters:$

| Parameter | Mandatory | Description | 
| ----- | ----- | ---- |
| $SenderMail | Yes | Defines which mailbox should send the mail |
| $ReceipientMail | Yes | Defines which mailbox should receive the mail | 
| $threshold | Yes | Defines how many days before expiration the IT admin is alerted about: APNS Expiration, VPP Token Expiration | ADE Token Expiration | LOB APP expiration |
| $InlcudeADETokens | No | If this parameter is present, ADE Tokens will also be monitored |
| $IncludeVPPTokens | No | If this parameter is present, VPP Tokens will also be monitored. |
| $VPPLicenseTreshold | No | Defines the minimum amount of free VPP licenses which must be free to not trigger an alert. |
| $IncludeAppleLOBApps | No | If this parameter is present, Apple LOB Apps will also be monitored. |

# Implementation 

Implement the base [script](./Invoke-AppleMonitoring.ps1) as an Azure Automation runbook on your Automation account. 
Ensure that:
* The required Modules have been installed
* The Managed Identity has the permissions outlined in the permissions chapter assigned
* The script is running with the desired parameters
