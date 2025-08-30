# MDE Settings Management Automation
This Bicep template deploys an Azure Logic App (playbook) that connects to Microsoft Defender for Endpoint (MDE) via a managed identity connection.
  The playbook runs a scheduled query against MDE, parses the results, and tags machines that meet specific criteria.
  - The template assumes an existing API connection for MDE (System Assigned Managed Identity).
  - The playbook is deployed in a disabled state by default.
  - The workflow includes: Recurrence trigger, Advanced Hunting query, JSON parsing, and conditional tagging of devices.

# Prequisites
- MDE API-Connection deployed 

# Deployment Steps
1. Deploy MDE API-Connection 
2. Deploy Logic App 
3. Assign Permission to System-Assigned Managed Identity of the Logic App

# Deployment
## Deploy MDE API-Connection
![Deploy MDE API-Connection](/Media/MDE-APIConnection-Deployment.gif)

# Deploy Logic App

**Important**:
- The Logic app needs to be deployed in the same resource group as the API-Connection.
- Adapt the Advanced Hunting to your needs (naming convention etc.)
- After you enable the Logic App it will run and apply the tag to the device in the output. 
- We do not make any guarantees or warranties, either expressed or implied. Please evaluate and test any implementation in your own environment before relying on it in production.


![Deploy Logic App](/Media/MDE-SettingsManagement-Automation-Deployment.gif)

# Assign Permission to System-Assigned Managed Identity of the Logic App
Update the script with the Object ID of the System-Assigned Managed Identity of the Logic App and run the script [LogicApp-Permission.ps1](/Logic%20App/LogicApp-Permission.ps1)