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
Go to the Azure Portal (https://portal.azure.com) and open "Deploy a custom template" or use the direct link https://portal.azure.com/#create/Microsoft.Template

