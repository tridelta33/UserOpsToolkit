# UserOpsToolkit

UserOpsToolkit is a PowerShell script that automates routine desktop support activities entirely from the keyboard. It combines environment awareness, modular task functions, and activity logging so technicians can complete common account and computer management tasks without using graphical tools.

## Features

- **Environment aware** prompts the operator to choose Azure (Entra ID) or on-premises Active Directory, then loads the appropriate modules.
- **Modular functions** implement discrete tasks such as account lookup, password resets, enabling accounts/computers, and computer lookups. New tasks can be added easily by following the existing function pattern.
- **Parameter-driven** execution allows calling the script non-interactively or piping values in for automation scenarios.
- **Credential security** relies on `Get-Credential` instead of hard-coded secrets.
- **Comprehensive logging** records every action in `%LOCALAPPDATA%\UserOpsToolkit\UserOpsToolkit.log` with optional session transcripts.

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- RSAT Active Directory module for on-premises actions.
- AzureAD, Az.Accounts, or Microsoft.Graph modules for Azure/Entra operations.

## Usage

```powershell
# Download the script and run from a PowerShell session
./UserOpsToolkit.ps1 -Operation AccountLookup -UserPrincipalName user@contoso.com

# Specify the environment explicitly and start a transcript for auditing
./UserOpsToolkit.ps1 -Operation PasswordReset -Environment Azure -UserPrincipalName user@contoso.com -StartTranscript

# Run interactively: the script will prompt for environment, identity, and required details
./UserOpsToolkit.ps1
```

### Supported operations

- `AccountLookup`
- `PasswordReset`
- `EnableAccount`
- `EnableComputer`
- `ComputerLookup`

Each operation logs its actions, prompting for credentials or additional input when required. Future functionality can be added by defining new `Invoke-*` functions following the existing structure and extending the operation switch statement near the bottom of the script.
