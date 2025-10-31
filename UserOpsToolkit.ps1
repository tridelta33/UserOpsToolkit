<#!
.SYNOPSIS
    UserOpsToolkit automates routine desktop support actions from the keyboard.
.DESCRIPTION
    Provides modular functions for lookups and account management across Azure AD and
    on-premises Active Directory. The script is environment aware, supports
    parameterized operations, and records activity logs for auditing.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('AccountLookup','PasswordReset','EnableAccount','EnableComputer','ComputerLookup')]
    [string]$Operation,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$SamAccountName,

    [Parameter()]
    [string]$ComputerName,

    [Parameter()]
    [ValidateSet('Azure','AzureAD','Entra','AD','ActiveDirectory')]
    [string]$Environment,

    [switch]$StartTranscript
)

#region Configuration
$script:ToolkitConfig = [ordered]@{
    LogDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'UserOpsToolkit'
    LogFile      = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'UserOpsToolkit\UserOpsToolkit.log'
}

if (-not (Test-Path -Path $script:ToolkitConfig.LogDirectory)) {
    New-Item -Path $script:ToolkitConfig.LogDirectory -ItemType Directory -Force | Out-Null
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path $script:ToolkitConfig.LogFile -Value $entry
    Write-Verbose $entry
}
#endregion Configuration

#region Utility Functions
function Select-ToolkitEnvironment {
    [CmdletBinding()] param(
        [Parameter()] [string]$Environment
    )

    if ([string]::IsNullOrWhiteSpace($Environment)) {
        Write-Host 'Select environment (Azure/AD):' -ForegroundColor Cyan
        $Environment = Read-Host 'Enter Azure for Entra ID or AD for on-premises Active Directory'
    }

    switch -Regex ($Environment) {
        '^(Azure|AzureAD|Entra)$' {
            return 'Azure'
        }
        '^(AD|ActiveDirectory)$' {
            return 'AD'
        }
        default {
            Write-Log -Message "Unrecognized environment value '$Environment'." -Level 'ERROR'
            throw "Unsupported environment selection: $Environment"
        }
    }
}

function Initialize-ToolkitEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Azure','AD')]
        [string]$Environment
    )

    Write-Log -Message "Initializing environment: $Environment"

    switch ($Environment) {
        'Azure' {
            $modules = @('AzureAD','Az.Accounts','Microsoft.Graph.Users')
            $loaded = $false
            foreach ($module in $modules) {
                if (Get-Module -ListAvailable -Name $module) {
                    try {
                        Import-Module -Name $module -ErrorAction Stop | Out-Null
                        Write-Log -Message "Loaded module $module"
                        $loaded = $true
                    }
                    catch {
                        Write-Log -Message "Failed to import module $module. $_" -Level 'WARN'
                    }
                }
            }

            if (-not $loaded) {
                $msg = 'No Azure modules were available. Install AzureAD, Az, or Microsoft.Graph modules.'
                Write-Log -Message $msg -Level 'ERROR'
                throw $msg
            }

            if (-not (Get-AzureSessionState)) {
                Write-Host 'A credential is required for Azure operations.' -ForegroundColor Yellow
                $credential = Get-Credential -Message 'Enter credentials with rights to manage Azure users.'
                Connect-AzureDirectory -Credential $credential
            }
        }
        'AD' {
            if (Get-Module -ListAvailable -Name 'ActiveDirectory') {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Log -Message 'Loaded ActiveDirectory module.'
            }
            else {
                $msg = 'The ActiveDirectory module is not available. Install RSAT tools or import the module.'
                Write-Log -Message $msg -Level 'ERROR'
                throw $msg
            }
        }
    }
}

function Get-AzureSessionState {
    [CmdletBinding()] param()

    if (Get-Command -Name 'Get-AzureADContext' -ErrorAction SilentlyContinue) {
        return [bool](Get-AzureADContext -ErrorAction SilentlyContinue)
    }
    elseif (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue) {
        return [bool](Get-AzContext -ErrorAction SilentlyContinue)
    }
    elseif (Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue) {
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue

        if ($null -eq $mgContext) {
            return $false
        }

        if ($mgContext.PSObject.Properties.Name -contains 'IsConnected') {
            return [bool]$mgContext.IsConnected
        }

        if ($mgContext.PSObject.Properties.Name -contains 'Account') {
            return ($null -ne $mgContext.Account)
        }

        if ($mgContext.PSObject.Properties.Name -contains 'Scopes') {
            return (($mgContext.Scopes | Where-Object { $_ }) -ne $null)
        }

        return $false
    }

    return $false
}

function Connect-AzureDirectory {
    [CmdletBinding()]
    param(
        [Parameter()] [pscredential]$Credential
    )

    if (Get-Command -Name 'Connect-AzureAD' -ErrorAction SilentlyContinue) {
        Connect-AzureAD -Credential $Credential -ErrorAction Stop
        Write-Log -Message 'Connected via Connect-AzureAD.'
    }
    elseif (Get-Command -Name 'Connect-AzAccount' -ErrorAction SilentlyContinue) {
        Connect-AzAccount -Credential $Credential -ErrorAction Stop | Out-Null
        Write-Log -Message 'Connected via Connect-AzAccount.'
    }
    elseif (Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue) {
        Connect-MgGraph -Credential $Credential -Scopes 'User.ReadWrite.All','Directory.AccessAsUser.All' -ErrorAction Stop | Out-Null
        Write-Log -Message 'Connected via Connect-MgGraph.'
    }
    else {
        $msg = 'No Azure connection command is available (Connect-AzureAD, Connect-AzAccount, or Connect-MgGraph).'
        Write-Log -Message $msg -Level 'ERROR'
        throw $msg
    }
}

function Convert-SecureStringToPlainText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.SecureString]$SecureString
    )

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        if ($ptr -ne [System.IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

function Resolve-UserIdentity {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [string]$SamAccountName
    )

    if ($UserPrincipalName) { return $UserPrincipalName }
    if ($SamAccountName) { return $SamAccountName }

    Write-Host 'No user identity supplied. Provide either a UPN or sAMAccountName.' -ForegroundColor Yellow
    $inputValue = Read-Host 'Enter user principal name or sAMAccountName'
    if (-not $inputValue) {
        throw 'An identity is required for this operation.'
    }
    return $inputValue
}
#endregion Utility Functions

#region Operation Implementations
function Invoke-AccountLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Azure','AD')]$Environment,
        [Parameter(Mandatory)][string]$Identity
    )

    Write-Log -Message "Performing account lookup for $Identity in $Environment"

    switch ($Environment) {
        'Azure' {
            if (Get-Command -Name 'Get-AzureADUser' -ErrorAction SilentlyContinue) {
                return Get-AzureADUser -ObjectId $Identity -ErrorAction Stop
            }
            elseif (Get-Command -Name 'Get-MgUser' -ErrorAction SilentlyContinue) {
                return Get-MgUser -UserId $Identity -ErrorAction Stop
            }
            else {
                throw 'No Azure user lookup cmdlet was found (Get-AzureADUser or Get-MgUser).'
            }
        }
        'AD' {
            return Get-ADUser -Identity $Identity -Properties * -ErrorAction Stop
        }
    }
}

function Invoke-PasswordReset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Azure','AD')]$Environment,
        [Parameter(Mandatory)][string]$Identity
    )

    $securePassword = Read-Host 'Enter the new password' -AsSecureString
    Write-Log -Message "Resetting password for $Identity in $Environment"

    switch ($Environment) {
        'Azure' {
            if (Get-Command -Name 'Set-AzureADUserPassword' -ErrorAction SilentlyContinue) {
                Set-AzureADUserPassword -ObjectId $Identity -Password $securePassword -ForceChangePasswordNextLogin $true -ErrorAction Stop
            }
            elseif (Get-Command -Name 'Update-MgUser' -ErrorAction SilentlyContinue) {
                $plainPassword = Convert-SecureStringToPlainText -SecureString $securePassword
                Update-MgUser -UserId $Identity -PasswordProfile @{ Password = $plainPassword; ForceChangePasswordNextSignIn = $true } -ErrorAction Stop
            }
            else {
                throw 'No Azure password reset cmdlet is available.'
            }
        }
        'AD' {
            Set-ADAccountPassword -Identity $Identity -NewPassword $securePassword -Reset -ErrorAction Stop
            Set-ADUser -Identity $Identity -ChangePasswordAtLogon $true -ErrorAction Stop
        }
    }
}

function Invoke-EnableAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Azure','AD')]$Environment,
        [Parameter(Mandatory)][string]$Identity
    )

    Write-Log -Message "Enabling account $Identity in $Environment"

    switch ($Environment) {
        'Azure' {
            if (Get-Command -Name 'Set-AzureADUser' -ErrorAction SilentlyContinue) {
                Set-AzureADUser -ObjectId $Identity -AccountEnabled $true -ErrorAction Stop
            }
            elseif (Get-Command -Name 'Update-MgUser' -ErrorAction SilentlyContinue) {
                Update-MgUser -UserId $Identity -AccountEnabled:$true -ErrorAction Stop
            }
            else {
                throw 'No Azure account enable cmdlet is available.'
            }
        }
        'AD' {
            Enable-ADAccount -Identity $Identity -ErrorAction Stop
        }
    }
}

function Invoke-EnableComputer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Azure','AD')]$Environment,
        [Parameter(Mandatory)][string]$Identity
    )

    Write-Log -Message "Enabling computer $Identity in $Environment"

    switch ($Environment) {
        'Azure' {
            throw 'Computer enablement is not supported in Azure from this toolkit. Use Intune or Azure portal.'
        }
        'AD' {
            Enable-ADAccount -Identity $Identity -ErrorAction Stop
        }
    }
}

function Invoke-ComputerLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Azure','AD')]$Environment,
        [Parameter(Mandatory)][string]$Identity
    )

    Write-Log -Message "Performing computer lookup for $Identity in $Environment"

    switch ($Environment) {
        'Azure' {
            if (Get-Command -Name 'Get-MgDevice' -ErrorAction SilentlyContinue) {
                return Get-MgDevice -Filter "displayName eq '$Identity'" -ErrorAction Stop
            }
            elseif (Get-Command -Name 'Get-AzureADDevice' -ErrorAction SilentlyContinue) {
                return Get-AzureADDevice -SearchString $Identity -ErrorAction Stop
            }
            else {
                throw 'No Azure device lookup cmdlet is available.'
            }
        }
        'AD' {
            return Get-ADComputer -Identity $Identity -Properties * -ErrorAction Stop
        }
    }
}
#endregion Operation Implementations

#region Execution Flow
if ($StartTranscript) {
    try {
        Start-Transcript -Path (Join-Path $script:ToolkitConfig.LogDirectory 'UserOpsToolkitTranscript.txt') -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log -Message "Unable to start transcript. $_" -Level 'WARN'
    }
}

try {
    $selectedEnvironment = Select-ToolkitEnvironment -Environment $Environment
    Initialize-ToolkitEnvironment -Environment $selectedEnvironment

    if (-not $Operation) {
        Write-Host 'No operation was specified. Available operations:' -ForegroundColor Cyan
        'AccountLookup','PasswordReset','EnableAccount','EnableComputer','ComputerLookup' | ForEach-Object { Write-Host " - $_" }
        $Operation = Read-Host 'Enter the operation to perform'
    }

    $identity = Resolve-UserIdentity -UserPrincipalName $UserPrincipalName -SamAccountName $SamAccountName

    switch ($Operation) {
        'AccountLookup' {
            $result = Invoke-AccountLookup -Environment $selectedEnvironment -Identity $identity
            Write-Log -Message 'Account lookup completed.'
            $result | Format-List *
        }
        'PasswordReset' {
            Invoke-PasswordReset -Environment $selectedEnvironment -Identity $identity
            Write-Log -Message 'Password reset completed.'
            Write-Host 'Password reset successfully.' -ForegroundColor Green
        }
        'EnableAccount' {
            Invoke-EnableAccount -Environment $selectedEnvironment -Identity $identity
            Write-Log -Message 'Account enabled successfully.'
            Write-Host 'Account enabled.' -ForegroundColor Green
        }
        'EnableComputer' {
            $computerId = if ($ComputerName) { $ComputerName } else { $identity }
            Invoke-EnableComputer -Environment $selectedEnvironment -Identity $computerId
            Write-Log -Message 'Computer enabled successfully.'
            Write-Host 'Computer enabled.' -ForegroundColor Green
        }
        'ComputerLookup' {
            $computerId = if ($ComputerName) { $ComputerName } else { $identity }
            $result = Invoke-ComputerLookup -Environment $selectedEnvironment -Identity $computerId
            Write-Log -Message 'Computer lookup completed.'
            $result | Format-List *
        }
        default {
            throw "Unsupported operation: $Operation"
        }
    }
}
catch {
    Write-Log -Message $_ -Level 'ERROR'
    Write-Error $_
}
finally {
    if ($StartTranscript) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            Write-Log -Message "Unable to stop transcript. $_" -Level 'WARN'
        }
    }
}
#endregion Execution Flow
