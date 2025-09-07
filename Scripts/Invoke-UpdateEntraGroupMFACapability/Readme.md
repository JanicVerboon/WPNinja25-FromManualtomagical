# Invoke-UpdateEntraGroupMFACapability
This script connects to Microsoft Graph and retrieves user registration details from the Entra ID MFA report. It ensures that two specified Entra ID groups are kept up to date:
- One group contains all users who are MFA capable.
- The other group contains all users who are not MFA capable.

Users are added or removed from these groups as needed, so that group membership always reflects the current MFA capability status.This is useful for scenarios such as applying Conditional Access policies based on MFA capability e.g. Identity Protection Policies.

---

## Prerequisites

Ensure the following Microsoft Graph modules are installed:

- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Reports`
- `Microsoft.Graph.Users`
- `Microsoft.Graph.Groups`

---

## Required Permissions

The script requires the following Microsoft Graph API permissions:

- `AuditLog.Read.All` – To read the Authentication Report
- `Group.ReadWrite.All` – To read and modify group members
---



## Script adoption
Update the group ID on line 225 for both Entra groups, which should update automatically.

```powershell
Invoke-UpdateEntraGroupMFACapability -GroupIdMFACapable 'OBJECT ID MFA CAPABLE GROUP' -GroupIdMFANotCapable 'OBJECT ID MFA NOT CAPABLE GROUP'
