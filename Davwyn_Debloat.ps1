[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)][ValidatePattern('^(Online|.:\\)$')][String]$Target,
        [Parameter(Mandatory=$false)][Bool]$Debloat
    )

# TODO:
# - Add Suggestion Tag to Bloatlists to give user a hint on what to do with the item (Remove/Keep/Disable)
# - Add Auto parameter to skip prompts. It will need to pass -Auto to functions like SponsoredAppx removal selection.
# - Possibly add JSON export and import option for full auto
# - Look for more CoPilot removal options

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -NoExit -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

$ScriptVersion = "3.0.0"
$ScriptVersionDate = "Oct 3, 2025"

$border = "=" * 40
$borderSmall = "-" * 40

Write-Host "`n`n$border" -ForegroundColor Cyan
Write-Host "Script Version: $ScriptVersion"
Write-Host "Script Modified Date: $ScriptVersionDate"
Write-Host $border -ForegroundColor Cyan

# Credits
# Stefan Kanthak https://skanthak.hier-im-netz.de/ten.html The 10 Commandments for Windows™ 10 (plus an 11th for Windows™ 11)
# Chris Redit https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html - Registry Hive Mounting Functions

if( $Host -and $Host.UI -and $Host.UI.RawUI ) {
    $rawUI = $Host.UI.RawUI
    $oldSize = $rawUI.BufferSize
    $typeName = $oldSize.GetType( ).FullName
    $newSize = New-Object $typeName ($oldSize.Width, 5000)
    $rawUI.BufferSize = $newSize
}

Add-Type -AssemblyName PresentationCore, PresentationFramework
$ErrorActionPreference = 'Continue'
$LogFolder = $PSScriptRoot

If (!(Test-Path $LogFolder)) {
    Write-Host "The folder '$LogFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    New-Item -Path "$LogFolder" -ItemType Directory
    Write-Host "The folder $LogFolder was successfully created."
}
Start-Transcript -OutputDirectory $LogFolder

#region Script-wide Variables
## General Variables
New-Variable -Name MountDir -Scope Script
New-Variable -Name TargetWindowsVersion -Scope Script
New-Variable -Name WarningLog -Scope Script -Value @()
New-Variable -Name ErrorLog -Scope Script -Value @()
## Lists of Packages/Capabilities/Services
New-Variable -Name AppxPackages -Scope Script
New-Variable -Name AppxProvisionedPackages -Scope Script
New-Variable -Name WindowsCapabilities -Scope Script
## Removal Lists
New-Variable -Name Appx_RemovalList -Scope Script -Value @()
New-Variable -Name WindowsCapabilities_RemovalList -Scope Script -Value @()
New-Variable -Name Services_RemovalList -Scope Script -Value @()

#endregion

#region Helper Functions
function Start-Pause {
    Write-Host "Press any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function LogError {
    param (
        [string]$Message
    )
    $script:ErrorLog += $Message
    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function LogWarning {
    param (
        [string]$Message
    )
    $script:WarningLog += $Message
    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}

function Exit-Script {
    param (
        [bool]$Success = $true
    )
    Dismount-RegistryHives
    if ($Success) {
        Write-Host "`n$border" -ForegroundColor Green
        Write-Host "SCRIPT COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "$border`n" -ForegroundColor Green
        if ( $WarningLog.Count -gt 0 ) {
            Write-Host "Warning Log:" -ForegroundColor Magenta
            $WarningLog | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        } else {
            Write-Host "No warnings were logged during the script execution." -ForegroundColor Green
        }
        if ( $ErrorLog.Count -gt 0 ) {
            Write-Host "Error Log:" -ForegroundColor Magenta
            $ErrorLog | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        } else {
            Write-Host "No errors were logged during the script execution." -ForegroundColor Green
        }
        $ExitCode = 0
    } else {
        Write-Host "`n$border" -ForegroundColor Red
        Write-Host "SCRIPT ENDED WITH ERRORS" -ForegroundColor Red
        Write-Host "$border`n" -ForegroundColor Red
        if ( $WarningLog.Count -gt 0 ) {
            Write-Host "Warning Log:" -ForegroundColor Yellow
            $WarningLog | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        }
        if ( $ErrorLog.Count -gt 0 ) {
            Write-Host "Error Log:" -ForegroundColor Yellow
            $ErrorLog | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        }
        $ExitCode = 1
    }
    Stop-Transcript
    Start-Pause
    Exit $ExitCode
}
function Stop-AbortScript {
    param (
        [string]$Message
    )
    LogError "Abort: $Message"
    Write-Host "`n$border" -ForegroundColor Red
    if ($null -ne $Message) {
        Write-Host "ABORTING SCRIPT:`n$Message" -ForegroundColor Red
    } else {
        Write-Host "ABORTING SCRIPT" -ForegroundColor Red
    }
    Write-Host "$border`n" -ForegroundColor Red
    Exit-Script -Success $false
}

function Stop-CompleteScript {
    Write-Host "SCRIPT COMPLETED SUCCESSFULLY" -ForegroundColor Green
    Stop-Transcript
    Start-Pause
    Exit 0
}

function Read-PromptUser {
    param (
        [string]$Title,
        [string]$Message,
        [string]$SuggestedAction,
        [string]$DefaultResponse,
        [string[]]$ValidResponses,
        [string]$InfoText
    )

    # Add Suggested Action if provided
    if (![string]::IsNullOrWhiteSpace($SuggestedAction)) {
        $Message += "`n`n[ Suggested Action: $SuggestedAction ]`n"
    }

    # Filter out reserved options we add explicitly
    $filteredResponses = @()
    foreach ($r in $ValidResponses) {
        if ($null -ne $r -and $r -ne '' -and $r -notin @('Info', 'Skip')) {
            $filteredResponses += $r
        }
    }

    # Build working responses and menu
    $workingResponses = @()
    $menuLines = @()
    $indexToResponse = @{}

    # Numbered options
    for ($i = 0; $i -lt $filteredResponses.Count; $i++) {
        $num = $i + 1
        $menuLines += ("{0}) {1}" -f $num, $filteredResponses[$i])
        $workingResponses += $filteredResponses[$i]
        $indexToResponse["$num"] = $filteredResponses[$i]  # map string of number to response
    }

    # Always add Skip
    $menuLines += "S) Skip"
    $workingResponses += "Skip"

    # Add Info if provided
    if ($InfoText) {
        $menuLines += "I) Info"
        $workingResponses += "Info"
    }

    # Determine default token and how we'll render it
    $defaultToken = $null
    if ($DefaultResponse) {
        # Only allow defaults that exist in our working set (case-insensitive)
        foreach ($wr in $workingResponses) {
            if ($wr -and ($wr.ToString().ToLower() -eq $DefaultResponse.ToLower())) {
                $defaultToken = $wr
                break
            }
        }
    }

    # Compose prompt header
    Write-Host ("`n{0}" -f $Title) -ForegroundColor Cyan
    if ($Message) { Write-Host $Message }

    # Helper to show the menu with an optional default hint
    function Show-Menu {
        param([string]$DefaultHint)
        foreach ($line in $menuLines) { Write-Host $line }
        if ($DefaultHint) {
            Write-Host ("[Press Enter for default: {0}]" -f $DefaultHint) -ForegroundColor DarkGray
        } else {
            Write-Host "[Select a number, 'S' to skip, or 'I' for info]" -ForegroundColor DarkGray
        }
    }

    # Main input loop
    do {
        # Show menu (include default hint if we have one)
        Show-Menu -DefaultHint:$defaultToken

        # Read user input (trim to simplify matching)
        $UserChoice = Read-Host "Enter choice"

        # Handle Enter for default when available
        if ([string]::IsNullOrWhiteSpace($UserChoice)) {
            if ($defaultToken) {
                if ($defaultToken -eq 'Info') {
                    Write-Host "`n$InfoText`n" -ForegroundColor Yellow
                    continue
                } elseif ($defaultToken -eq 'Skip') {
                    Write-Host "`"$Title`" skipped." -ForegroundColor Cyan
                    Start-Sleep 1
                    return 'Skip'
                } else {
                    Write-Host "`"$Title`" $defaultToken selected." -ForegroundColor Cyan
                    Start-Sleep 1
                    return $defaultToken
                }
            } else {
                Write-Host "No default available. Please choose a valid option." -ForegroundColor Red
                continue
            }
        }

        # Normalize input
        $UserChoiceNorm = $UserChoice.Trim()

        # Info processing
        if ($UserChoiceNorm -match '^(I|i)$') {
            if ($InfoText) {
                Write-Host "`n$InfoText`n" -ForegroundColor Yellow
            } else {
                Write-Host "Info is not available." -ForegroundColor Yellow
            }
            continue
        }

        # Skip processing
        if ($UserChoiceNorm -match '^(S|s)$') {
            Write-Host ("`"{0}`" skipped." -f $Title) -ForegroundColor Cyan
            return 'Skip'
        }

        # Numeric selection processing
        if ($UserChoiceNorm -match '^\d+$') {
            # Verify number is within range
            if ($indexToResponse.ContainsKey($UserChoiceNorm)) {
                Write-Host "`"$Title`" $($indexToResponse[$UserChoiceNorm]) selected." -ForegroundColor Cyan
                Start-Sleep 1
                return $indexToResponse[$UserChoiceNorm]
            } else {
                Write-Host ("Invalid number '{0}'. Please choose between 1 and {1} or S for Skip." -f $UserChoiceNorm, $filteredResponses.Count) -ForegroundColor Red
                continue
            }
        }

        # Anything else is invalid
        Write-Host ("Invalid entry '{0}'. Please select a number, 'S' to Skip, or 'I' for Info." -f $UserChoiceNorm) -ForegroundColor Red

    } while ($true)
}

function Write-Header {
    param (
        [string]$Text,
        [switch]$Large,
        [switch]$Notice
    )
    
    # Get the length of text before any newline character
    $textLength = if ($Text.Contains("`n")) {
        $Text.Split("`n")[0].Length
    } else {
        $Text.Length
    }
    
    # Create borders based on text length (add padding)
    $borderLength = [Math]::Max($textLength + 8, 20)
    $largeHeaderBorder = "=" * $borderLength
    $largeSpacer = " = "
    $headerBorder = "-" * $borderLength
    $spacer = " - "
    
    if ($Large) {
        Write-Host "`n`n$largeHeaderBorder" -ForegroundColor Cyan
        Write-Host "$largeSpacer $Text $largeSpacer" -ForegroundColor Magenta
        Write-Host "$largeHeaderBorder" -ForegroundColor Cyan
    } elseif ($Notice) {
        Write-Host "`n$headerBorder" -ForegroundColor Yellow
        Write-Host "$spacer $Text $spacer" -ForegroundColor Yellow
        Write-Host "$headerBorder`n" -ForegroundColor Yellow        
    } else {
        Write-Host "`n`n$headerBorder" -ForegroundColor Cyan
        Write-Host "$spacer $Text $spacer" -ForegroundColor Green
        Write-Host "$headerBorder" -ForegroundColor Cyan
    }    
}

function Get-WindowsVersion {
    param (
        [string]$Target = "Online"
    )

    try {
        if ($Target -eq "Online") {
            # For online OS, use Get-ComputerInfo which works in both PowerShell versions
            $osInfo = Get-ComputerInfo -Property WindowsProductName, OsVersion
            $windowsVersion = $osInfo.OsVersion
        }
        else {
            # Get Windows image information from ntoskrnl.exe in the offline image
            $imageInfo = (Get-Item "$MountDir\System32\ntoskrnl.exe").VersionInfo.ProductVersion
            if ($imageInfo -match '(\d+)\.(\d+)\.(\d+)\.(\d+)') {
                $windowsVersion = $imageInfo
            } else {
                Stop-AbortScript -Message "Unable to parse Windows version from ntoskrnl.exe"
            }
        }
        return $windowsVersion
    }
    catch {
        LogError "Failed to determine Windows version: $_"
        return $null
    }
}

function Set-RegistryValue {
    param (
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$PropertyType,
        [switch]$Remove
    )

    # helper map for accepted type names/aliases
    $typeMap = @{
        'string'       = 'String'
        'sz'           = 'String'
        'expandstring' = 'ExpandString'
        'expandsz'     = 'ExpandString'
        'multistring'  = 'MultiString'
        'multisz'      = 'MultiString'
        'binary'       = 'Binary'
        'dword'        = 'DWord'
        'uint32'       = 'DWord'
        'int'          = 'DWord'
        'int32'        = 'DWord'
        'qword'        = 'QWord'
        'uint64'       = 'QWord'
        'int64'        = 'QWord'
        'long'         = 'QWord'
    }
    Write-Host ""
    if ($Remove) {
        # Remove the specified registry value
        if ($Name) {
            try {
                if (Test-Path -Path $Path) {
                    $props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
                    if ($props.PSObject.Properties.Name -contains $Name) {
                        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
                        Write-Host "Removed registry property: Path='$Path', Name='$Name'" -ForegroundColor Gray
                    } else {
                        Write-Host "Registry property not found, nothing to remove: Path='$Path', Name='$Name'" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "Registry path not found, nothing to remove: Path='$Path'" -ForegroundColor Gray
                }
            } catch {
                LogError "Set-RegistryValue: Failed to remove registry property. $_"
            }
            return
        } else {
            try {
                if (Test-Path -Path $Path) {
                    Remove-Item -Path $Path -Force -ErrorAction Stop
                    Write-Host "Removed registry key: Path='$Path'" -ForegroundColor Gray
                } else {
                    Write-Host "Registry path not found, nothing to remove: Path='$Path'" -ForegroundColor Gray
                    return
                }
            } catch {
                LogError "Set-RegistryValue: Failed to remove registry key. $_"
            }
            return
        }
    }
    
    if ($null -ne $Value) {
        # If Type explicitly provided, validate/normalize and take priority
        if ($PropertyType) {
            $key = ($PropertyType.ToString()).Replace(' ','').ToLower()
            if ($typeMap.ContainsKey($key)) {
                $PropertyType = $typeMap[$key]
            } else {
                LogError "Set-RegistryValue: Unrecognized Type '$PropertyType'. Valid types: $($typeMap.Values | Sort-Object -Unique -Join ', ')"
            }
        } else {
            # Auto-select only for string or supported integer types; otherwise require explicit Type
            if ($Value -is [string]) {
                $PropertyType = 'String'
            } elseif ($Value -is [int] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [short] -or $Value -is [int16]) {
                # 16/32-bit integers map to DWord
                $PropertyType = 'DWord'
            } elseif ($Value -is [long] -or $Value -is [int64] -or $Value -is [uint64]) {
                # 64-bit integers map to QWord
                $PropertyType = 'QWord'
            } else {
                LogError "Set-RegistryValue: Type must be specified when Value is not a string or a recognized integer size (Int16/Int32/Int64)."
            }
        }

        # Create Registry key if it does not exist
        if (!(Test-Path $Path -ErrorAction SilentlyContinue)) {
            New-Item -Path $Path -Force | Out-Null
        }

        try {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Stop | Out-Null
            Write-Host "Set registry value: Path='$Path', Name='$Name', Value='$Value', Type='$PropertyType'" -ForegroundColor Gray
        } catch {
            LogError "Set-RegistryValue: Failed to set registry value. $_"
        }
    } else {
        LogError "Set-RegistryValue: Value cannot be null."
    }
}

Function Import-RegistryHive
{
# Thanks to Chris Redit
# https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)]$File,
        # check the registry key name is not an invalid format
        [String][Parameter(Mandatory=$true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        # check the PSDrive name does not include invalid characters
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    # check whether the drive name is available
    $TestDrive = Get-PSDrive -Name $Name -EA SilentlyContinue
    if ($null -ne $TestDrive)
    {
        #throw [Management.Automation.SessionStateException] "A drive with the name '$Name' already exists."
        Stop-AbortScript -Message "Import-RegistryHive: A drive with the name '$Name' already exists."
    }

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait

    if ($Process.ExitCode)
    {
        #throw [Management.Automation.PSInvalidOperationException] "The registry hive '$File' failed to load. Verify the source path or target registry key."
        Stop-AbortScript -Message "Import-RegistryHive: The registry hive '$File' failed to load. Verify the source path or target registry key."
    }

    try
    {
        # validate patten on $Name in the Params and the drive name check at the start make it very unlikely New-PSDrive will fail
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
    }
    catch
    {
        #throw [Management.Automation.PSInvalidOperationException] "A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually."
        Stop-AbortScript -Message "Import-RegistryHive: A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually."
    }
}

Function Remove-RegistryHive
{
# Thanks to Chris Redit
# https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    # set -ErrorAction Stop as we never want to proceed if the drive doesnt exist
    $Drive = Get-PSDrive -Name $Name -EA Stop
    # $Drive.Root is the path to the registry key, save this before the drive is removed
    $Key = $Drive.Root

    # remove the drive, the only reason this should fail is if the reasource is busy
    Remove-PSDrive $Name -EA Stop

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode)
    {
        # if "reg unload" fails due to the resource being busy, the drive gets added back to keep the original state
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
        Write-Host "The registry key '$Key' could not be unloaded, the key may still be in use." -ForegroundColor DarkYellow
        #throw [Management.Automation.PSInvalidOperationException] "The registry key '$Key' could not be unloaded, the key may still be in use."
    }
}

Function Mount-RegistryHives {
    Write-Host "`nMounting the registry..." -ForegroundColor Yellow
    if ($Target -eq "Online") {
        #Mount Registry Roots
        try {
            #if (!(Get-PSDrive -Name Reg_HKLM_COMPONENTS)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\COMPONENTS -Name Reg_HKLM_COMPONENTS -Scope Global -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKLM_SOFTWARE -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\SOFTWARE -Name Reg_HKLM_SOFTWARE -Scope Global -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKLM_SYSTEM -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\SYSTEM -Name Reg_HKLM_SYSTEM -Scope Global -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKDefaultUser -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$env:SystemDrive\Users\Default\NTUSER.DAT" -Key "HKLM\TEMP_HKDefaultUser" -Name Reg_HKDefaultUser -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKCU -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_CURRENT_USER -Name Reg_HKCU -Scope Global -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKCR -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name Reg_HKCR -Scope Global -ErrorAction Stop}
        } catch {
            Stop-AbortScript -Message "Failed to mount registry hives for online target. Error: $_"
        }

    } elseif ((Test-Path $Target -PathType Container) -and (Test-Path "$Target`\Windows")) {
        try {
            #if (!(Get-PSDrive -Name Reg_HKLM_COMPONENTS -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Windows\System32\config\COMPONENTS" -Key "HKLM\TEMP_HKLM_COMPONENTS" -Name Reg_HKLM_COMPONENTS -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKLM_SOFTWARE -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Windows\System32\config\SOFTWARE" -Key "HKLM\TEMP_HKLM_SOFTWARE" -Name Reg_HKLM_SOFTWARE -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKLM_SYSTEM -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Windows\System32\config\SYSTEM" -Key "HKLM\TEMP_HKLM_SYSTEM" -Name Reg_HKLM_SYSTEM -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKDefaultUser -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Users\Default\NTUSER.DAT" -Key "HKLM\TEMP_HKDefaultUser" -Name Reg_HKDefaultUser -ErrorAction Stop}
            if (!(Get-PSDrive -Name Reg_HKCU -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\TEMP_HKDefaultUser -Name Reg_HKCU -Scope Global -ErrorAction Stop} #Although redundant, this prevents errors for any tasks that try to write to HKEY_Current_USER
            if (!(Get-PSDrive -Name Reg_HKCR -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\TEMP_HKLM_SOFTWARE\Classes -Name Reg_HKCR -Scope Global -ErrorAction Stop}
        } catch {
            Stop-AbortScript -Message "Failed to mount registry hives for offline target. Error: $_"
        }
    }
}

Function Dismount-RegistryHives {
    Write-Host "`nPlease wait`nUnmounting the registry..." -ForegroundColor Yellow
    # Garbage Collect to free any handles to registry hives
    [System.GC]::Collect()

    $RegDrives = @("Reg_HKCR","Reg_HKCU","Reg_HKLM_SOFTWARE","Reg_HKLM_SYSTEM","Reg_HKDefaultUser")
    $UnmountAttempts = 1
    While (Compare-Object -ReferenceObject $(Get-PSDrive | ForEach-Object -MemberName Name) -DifferenceObject $RegDrives -IncludeEqual -ExcludeDifferent) {
        Write-Host "Attempt: $UnmountAttempts" -ForegroundColor Gray
        if ($UnmountAttempts -ge 5) {
            Write-Host "-----------------------------" -ForegroundColor Red
            LogError "Error: Failed to unmount registry objects: $(Get-PSDrive -Name "Reg_*"). You may need to open Regedit.exe and look for keys labeled Reg_ under HKEY_Local_Machine and manually unload them."
            Write-Host "-----------------------------" -ForegroundColor Red

            Break
        }
        $UnmountAttempts++
        Start-Sleep 4
        if ($Target -eq "Online") {
            #UnMount Registry Roots
            if (Get-PSDrive -Name Reg_HKCR -ErrorAction SilentlyContinue) {Remove-PSDrive -Name Reg_HKCR}
            if (Get-PSDrive -Name Reg_HKCU -ErrorAction SilentlyContinue) {Remove-PSDrive -Name Reg_HKCU}
            #if (Get-PSDrive -Name Reg_HKLM_COMPONENTS -ErrorAction SilentlyContinue) {Remove-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\COMPONENTS -Name Reg_HKLM_COMPONENTS -Scope Global -ErrorAction Stop}
            if (Get-PSDrive -Name Reg_HKLM_SOFTWARE -ErrorAction SilentlyContinue) {Remove-PSDrive -Name Reg_HKLM_SOFTWARE}
            if (Get-PSDrive -Name Reg_HKLM_SYSTEM -ErrorAction SilentlyContinue) {Remove-PSDrive -Name Reg_HKLM_SYSTEM}
            if (Get-PSDrive -Name Reg_HKDefaultUser -ErrorAction SilentlyContinue) {Remove-RegistryHive -Name Reg_HKDefaultUser -ErrorAction Continue}
        

        } elseif ((Test-Path $Target -PathType Container) -and (Test-Path "$Target`\Windows")) {
            if (Get-PSDrive -Name Reg_HKCR -ErrorAction SilentlyContinue) {Remove-PSDrive -Name Reg_HKCR}
            if (Get-PSDrive -Name Reg_HKCU -ErrorAction SilentlyContinue) {Remove-PSDrive -Name Reg_HKCU}
            #if (Get-PSDrive -Name Reg_HKLM_COMPONENTS -ErrorAction SilentlyContinue) {Remove-RegistryHive -Name Reg_HKLM_COMPONENTS}
            if (Get-PSDrive -Name Reg_HKLM_SOFTWARE -ErrorAction SilentlyContinue) {Remove-RegistryHive -Name Reg_HKLM_SOFTWARE -ErrorAction Continue}
            if (Get-PSDrive -Name Reg_HKLM_SYSTEM -ErrorAction SilentlyContinue) {Remove-RegistryHive -Name Reg_HKLM_SYSTEM -ErrorAction Continue}
            if (Get-PSDrive -Name Reg_HKDefaultUser -ErrorAction SilentlyContinue) {Remove-RegistryHive -Name Reg_HKDefaultUser -ErrorAction Continue}
        }
    }
}

Function Take-Ownership {
#Huge thanks to Jason Eberhardt for making this possible without the need of 3rd party tools to change Access Control List objects in Windows Registry from TrustedInstaller!
#This script was slightly edited to grant FullControl beyond just TakeOwnership

<#
.SYNOPSIS 
 Give ownership of a file or folder to the specified user.

.DESCRIPTION
 Give the current process the SeTakeOwnershipPrivilege" and "SeRestorePrivilege" rights which allows it
 to reset ownership of an object.  The script will then set the owner to be the specified user.

.PARAMETER Path (Required)
 The path to the object on which you wish to change ownership.  It can be a file or a folder.

.PARAMETER User (Required)
 The user whom you want to be the owner of the specified object.  The user should be in the format
 <domain>\<username>.  Other user formats will not work.  For system accounts, such as System, the user
 should be specified as "NT AUTHORITY\System".  If the domain is missing, the local machine will be assumed.

.PARAMETER Recurse (switch)
 Causes the function to parse through the Path recursively.

.INPUTS
 None. You cannot pipe objects to Take-Ownership

.OUTPUTS
 None

.NOTES
 Name:    Take-Ownership.ps1
 Author:  Jason Eberhardt
 Date:    2017-07-20

Example:
Take-Ownership -Path "Registry::HKCR\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}" -User "Administrator" -Recurse -Verbose
#>
    [CmdletBinding(SupportsShouldProcess=$false)]
    Param([Parameter(Mandatory=$true, ValueFromPipeline=$false)] [ValidateNotNullOrEmpty()] [string]$Path,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)] [ValidateNotNullOrEmpty()] [string]$User,
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)] [switch]$Recurse)

    Begin {
    $AdjustTokenPrivileges=@"
using System;
using System.Runtime.InteropServices;

  public class TokenManipulator {
    [DllImport("kernel32.dll", ExactSpelling = true)]
      internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
      internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
      public int Count;
      public long Luid;
      public int Attr;
    }

    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static bool AddPrivilege(string privilege) {
      bool retVal;
      TokPriv1Luid tp;
      IntPtr hproc = GetCurrentProcess();
      IntPtr htok = IntPtr.Zero;
      retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
      tp.Count = 1;
      tp.Luid = 0;
      tp.Attr = SE_PRIVILEGE_ENABLED;
      retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
      retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
      return retVal;
    }

    public static bool RemovePrivilege(string privilege) {
      bool retVal;
      TokPriv1Luid tp;
      IntPtr hproc = GetCurrentProcess();
      IntPtr htok = IntPtr.Zero;
      retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
      tp.Count = 1;
      tp.Luid = 0;
      tp.Attr = SE_PRIVILEGE_DISABLED;
      retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
      retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
      return retVal;
    }
  }
"@
  }

  Process {
    $Item=Get-Item $Path
    Write-Verbose "Giving current process token ownership rights"
    Add-Type $AdjustTokenPrivileges -PassThru > $null
    [void][TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege") 
    [void][TokenManipulator]::AddPrivilege("SeRestorePrivilege") 

    # Change ownership
    $Account=$User.Split("\")
    if ($Account.Count -eq 1) { $Account+=$Account[0]; $Account[0]=$env:COMPUTERNAME }
    $Owner=New-Object System.Security.Principal.NTAccount($Account[0],$Account[1])
    Write-Verbose "Change ownership to '$($Account[0])\$($Account[1])'"

    $Provider=$Item.PSProvider.Name
    if ($Item.PSIsContainer) {
      switch ($Provider) {
        "FileSystem" { $ACL=[System.Security.AccessControl.DirectorySecurity]::new() }
        "Registry"   { $ACL=[System.Security.AccessControl.RegistrySecurity]::new()
                       # Get-Item doesn't open the registry in a way that we can write to it.
                       switch ($Item.Name.Split("\")[0]) {
                         "HKEY_CLASSES_ROOT"   { $rootKey=[Microsoft.Win32.Registry]::ClassesRoot; break }
                         "HKEY_LOCAL_MACHINE"  { $rootKey=[Microsoft.Win32.Registry]::LocalMachine; break }
                         "HKEY_CURRENT_USER"   { $rootKey=[Microsoft.Win32.Registry]::CurrentUser; break }
                         "HKEY_USERS"          { $rootKey=[Microsoft.Win32.Registry]::Users; break }
                         "HKEY_CURRENT_CONFIG" { $rootKey=[Microsoft.Win32.Registry]::CurrentConfig; break }
                       }
                       $Key=$Item.Name.Replace(($Item.Name.Split("\")[0]+"\"),"")
                       $Item=$rootKey.OpenSubKey($Key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership) }
        default { throw "Unknown provider:  $($Item.PSProvider.Name)" }
      }
      $ACL.SetOwner($Owner)
      Write-Verbose "Setting owner on $Path"
      $Item.SetAccessControl($ACL)
      $Rule = New-Object System.Security.AccessControl.RegistryAccessRule($Owner, 'FullControl', 'ContainerInherit', 'None', 'Allow')
      $ACL.AddAccessRule($Rule)
      $Item.SetAccessControl($ACL)
      if ($Provider -eq "Registry") { $Item.Close() }

      if ($Recurse.IsPresent) {
        # You can't set ownership on Registry Values
        if ($Provider -eq "Registry") { $Items=Get-ChildItem -Path $Path -Recurse -Force | Where-Object { $_.PSIsContainer } }
        else { $Items=Get-ChildItem -Path $Path -Recurse -Force }
        $Items=@($Items)
        for ($i=0; $i -lt $Items.Count; $i++) {
          switch ($Provider) {
            "FileSystem" { $Item=Get-Item $Items[$i].FullName
                           if ($Item.PSIsContainer) { $ACL=[System.Security.AccessControl.DirectorySecurity]::new() }
                           else { $ACL=[System.Security.AccessControl.FileSecurity]::new() } }
            "Registry"   { $Item=Get-Item $Items[$i].PSPath
                           $ACL=[System.Security.AccessControl.RegistrySecurity]::new()
                           # Get-Item doesn't open the registry in a way that we can write to it.
                           switch ($Item.Name.Split("\")[0]) {
                             "HKEY_CLASSES_ROOT"   { $rootKey=[Microsoft.Win32.Registry]::ClassesRoot; break }
                             "HKEY_LOCAL_MACHINE"  { $rootKey=[Microsoft.Win32.Registry]::LocalMachine; break }
                             "HKEY_CURRENT_USER"   { $rootKey=[Microsoft.Win32.Registry]::CurrentUser; break }
                             "HKEY_USERS"          { $rootKey=[Microsoft.Win32.Registry]::Users; break }
                             "HKEY_CURRENT_CONFIG" { $rootKey=[Microsoft.Win32.Registry]::CurrentConfig; break }
                           }
                           $Key=$Item.Name.Replace(($Item.Name.Split("\")[0]+"\"),"")
                           $Item=$rootKey.OpenSubKey($Key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership) }
            default { throw "Unknown provider:  $($Item.PSProvider.Name)" }
          }
          $ACL.SetOwner($Owner)
          Write-Verbose "Setting owner on $($Item.Name)"
          $Item.SetAccessControl($ACL)
          if ($Provider -eq "Registry") { $Item.Close() }
        }
      } # Recursion
    }
    else {
      if ($Recurse.IsPresent) { Write-Warning "Object specified is neither a folder nor a registry key.  Recursion is not possible." }
      switch ($Provider) {
        "FileSystem" { $ACL=[System.Security.AccessControl.FileSecurity]::new() }
        "Registry"   { throw "You cannot set ownership on a registry value"  }
        default { throw "Unknown provider:  $($Item.PSProvider.Name)" }
      }
      $ACL.SetOwner($Owner)
      Write-Verbose "Setting owner on $Path"
      $Item.SetAccessControl($ACL)
      $Rule = New-Object System.Security.AccessControl.RegistryAccessRule($Owner, 'FullControl', 'ContainerInherit', 'None', 'Allow')
      $ACL.AddAccessRule($Rule)
      $Item.SetAccessControl($ACL)
    }
  }
}
#endregion

#region Major Functions
function Get-PackagesCapabilities {
    #Get Appx Packages, Appx Provisioned Packages and Windows Capabilities
    Write-Host "`nGetting Appx Packages, AppxProvisionedPackages, and Windows Capabilities..." -ForegroundColor White -BackgroundColor DarkGreen
    if ($Target -eq "Online") {
        $Script:AppxPackages = Get-AppxPackage -AllUsers
        $Script:AppxProvisionedPackages = Get-AppxProvisionedPackage -Online
        $Script:WindowsCapabilities = Get-WindowsCapability -Online | Where-Object {($_.State -notin @('NotPresent', 'Removed'))}
    } else {
        New-Item -Path "$MountDir`\Scratch" -ItemType Directory -Force
        $Script:AppxProvisionedPackages = Get-AppxProvisionedPackage -Path $MountDir
        $Script:WindowsCapabilities = Get-WindowsCapability -Path $Target | Where-Object {($_.State -notin @('NotPresent', 'Removed'))}
    }
}

function Get-BloatRemovalSelection {
    param (
        [Parameter(Mandatory=$true)][PSCustomObject[]]$SelectionList,
        [switch]$Auto
    )
    $RemovalList = @()
    foreach ($bloatItem in $SelectionList) {
        $itemName = $bloatItem.Item
        $itemDesc = $bloatItem.Desc
        Write-Host "`n$borderSmall`n" -ForegroundColor Cyan
        Write-Host "`n$itemName" -ForegroundColor Yellow
        Write-Host "$itemDesc" -ForegroundColor Cyan
        if ($itemSuggest) { Write-Host "$ItemSuggest" -ForegroundColor Green }
        if ($Auto) {
            $response = "Remove"
        } else {    
            $response = Read-PromptUser -Title "Remove Bloatware Item" -Message "Do you want to remove the following item?" -SuggestedAction "$($bloatItem.Suggested)" -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will add this item to the removal list to be uninstalled. Selecting 'Skip' will skip this item."
        }
        if ($response -eq "Remove") {
            $RemovalList += $itemName
            Write-Host "`n$itemName added to removal list.`n" -ForegroundColor Green
        }
    }
    return $RemovalList
}

function Get-AppxSponsoredRemovalSelection {
    param (
        [switch]$Auto
    )
    foreach ($Bloat in $Script:BloatlistAppxSponsored) {
        if (($Script:AppxPackages | Where-Object Name -like $Bloat) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $Bloat)) {
            Write-Output $Bloat
            $SponsoredInstalled += $Bloat
        }
    }
    if ($SponsoredInstalled) {
        if ($Auto) {
            $response = "Remove"
        } else {
            $response = Read-PromptUser -Title "Remove Sponsored Appx Apps" -Message "The following sponsored apps were detected as installed:`n$($SponsoredInstalled -join ", ")`nDo you want to remove ALL these sponsored apps?" -DefaultResponse "Remove" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will add ALL these sponsored apps to the removal list to be uninstalled. Selecting 'Skip' will skip removing these apps."
        }
        if ($response -eq "Remove") {$Script:Appx_RemovalList += $SponsoredInstalled}
    } else {
        Write-Host "`nIt seems you have no sponsored apps installed." -ForegroundColor Green
    }
}

function Get-BloatServicesSelection {
    param (
        [Parameter(Mandatory=$true)][PSCustomObject[]]$SelectionList
    )
    $ActiveServices = @()
    foreach ($ServiceBloat in $SelectionList) {
        if ($Target -eq "Online") {
            $Service = Get-Service | Where-Object { $_.Name -eq $ServiceBloat.Item }
            if ($Service) {
                if ($Service.StartType -ne "Disabled") {
                    $ActiveServices += $ServiceBloat
                    Write-Host "`nFound active bloat service: $($ServiceBloat.Item)" -ForegroundColor White
                } else {
                    Write-Host "`nBloat service $($ServiceBloat.Item) is already disabled." -ForegroundColor Green
                }
            } else {
                Write-Host "`nBloat service $($ServiceBloat.Item) not found on system." -ForegroundColor Gray
            }
        } else {
            # Offline target - check registry for service start type
            $registryPath = "Reg_HKLM_SYSTEM:\ControlSet001\Services\$($Bloat.Item)"
            if (Test-Path $registryPath -ErrorAction SilentlyContinue) {
                $serviceStartType = Get-ItemProperty -Path $registryPath -Name "Start" -ErrorAction SilentlyContinue
                if ($serviceStartType.Start -ne 4) {
                    $ActiveServices += $Bloat
                    Write-Host "`nFound active bloat service: $($ServiceBloat.Item)" -ForegroundColor White
                } else {
                    Write-Host "`nBloat service $($ServiceBloat.Item) is already disabled in offline system." -ForegroundColor Green
                }
            } else {
                Write-Host "`nBloat service $($ServiceBloat.Item) not found in offline system." -ForegroundColor Gray
            }
        }
    }
    $RemovalList = @()
    if ($ActiveServices.Count -eq 0) {
        Write-Host "`nNo bloat services detected for this section. Continuing...`n" -ForegroundColor Green
        return $RemovalList
    } else {
        Write-Header -Text "The following questions will prompt you to select which Windows Service you want to disable.`nThis list contains services you may want to keep so review each one carefully." -Notice
        foreach ($bloatItem in $ActiveServices) {
            $itemName = $bloatItem.Item
            $itemDesc = $bloatItem.Desc
            Write-Host "`n$borderSmall`n" -ForegroundColor Cyan
            Write-Host "`n$itemName" -ForegroundColor Yellow
            Write-Host "$itemDesc" -ForegroundColor Cyan
            if ($itemSuggest) { Write-Host "$ItemSuggest" -ForegroundColor Green }
            $response = Read-PromptUser -Title "Disable Bloatware Service" -Message "Do you want to disable the following service?" -SuggestedAction "$($bloatItem.Suggested)" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will add this service to the removal list to be disabled. Selecting 'Skip' will skip this service."
            if ($response -eq "Disable") {
                $RemovalList += $itemName
                Write-Host "`n$itemName added to removal list.`n" -ForegroundColor Green
            } else {
                Write-Host "`n$itemName skipped.`n" -ForegroundColor Magenta
            }
        }
    }
    return $RemovalList
}

function Remove-AppxBloat {
    param (
        [Parameter(Mandatory=$true)][string[]]$RemovalList
    )
    Write-Host "`nRemoving selected Appx Packages..." -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "`nPackages to remove: $($RemovalList -join ', ')`n" -ForegroundColor Yellow
    foreach ($packageName in $RemovalList) {
        Write-Host "Removing Appx Package: $packageName" -ForegroundColor Yellow
        if ($Target -eq "Online") {
            # Remove Appx apps installed for all users
            try {
                Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "$packageName" } | ForEach-Object {
                    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop
                }
            } catch {
                Write-Host "Failed to remove Appx Package: $packageName. Error: $_" -ForegroundColor Red
            }
            # Remove Appx Provisioned Packages
            try {
                Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "$packageName" } | ForEach-Object {
                    Remove-AppxProvisionedPackage -PackageName $_.PackageName -Online -ErrorAction Stop
                }
            } catch {
                Write-Host "Failed to remove Appx Provisioned Package: $packageName. Error: $_" -ForegroundColor Red
            }
        } else {
            try {
                Get-AppxProvisionedPackage -Path $MountDir | Where-Object { $_.DisplayName -like "$packageName" } | ForEach-Object {
                    Remove-AppxProvisionedPackage -PackageName $_.PackageName -Path $MountDir -ErrorAction Stop
                }
            } catch {
                Write-Host "Failed to remove Appx Provisioned Package: $packageName. Error: $_" -ForegroundColor Red
            }
        }
    }
    Write-Host "`nAppx Package removal process completed." -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Remove-BloatWindowsCapability {
    param (
        [Parameter(Mandatory=$true)][string[]]$RemovalList
    )
    Write-Host "`nRemoving selected Windows Capabilities..." -ForegroundColor White -BackgroundColor DarkGreen
        Write-Host "`Capabilities to remove: $($RemovalList -join ', ')`n" -ForegroundColor Yellow
    foreach ($Capability in $RemovalList) {
        Write-Host "Removing Capability: $Capability" -ForegroundColor Yellow
        if ($Target -eq "Online") {
            # Remove Appx apps installed for all users
            try {
                Remove-WindowsCapability -Name "$Capability" -Online -ErrorAction Stop
            } catch {
                Write-Host "Failed to remove capability: $packageName. Error: $_" -ForegroundColor Red
            }
        } else {
            try {
                Remove-WindowsCapability -Name "$Capability" -Path "$Target" -ErrorAction Stop
            } catch {
                Write-Host "Failed to remove capability: $packageName. Error: $_" -ForegroundColor Red
            }
        }
    }
    Write-Host "`nWindows Capability removal process completed." -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Remove-BloatServices {
    param (
        [Parameter(Mandatory=$true)][string[]]$RemovalList
    )
    Write-Host "`nRemoving selected Services..." -ForegroundColor Green
    Write-Host "`nServices to remove: $($RemovalList -join ', ')`n" -ForegroundColor Yellow
    foreach ($Bloat in $RemovalList) {
        if ($Target -eq "Online") {
            Write-Host "`nTrying to disable $Bloat ..."
            try {
                $Service = Get-Service | Where-Object { $_.Name -eq $Bloat }
                if($Service.Status -match "Run") {
                    Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                }
                $Service | Set-Service -StartupType Disabled -Verbose -ErrorAction Stop
                Write-Host "`n$($Service.DisplayName) service stopped and disabled." -ForegroundColor Green
            } catch {
                Write-Host "Failed to stop/disable service: $($Bloat). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "`nTrying to disable $Bloat ..."
            try {
                $registryPath = "Reg_HKLM_SYSTEM:\ControlSet001\Services\$Bloat"
                if (Test-Path $registryPath) {
                    New-ItemProperty $registryPath Start -Value 4 -PropertyType Dword -Force -ErrorAction Stop
                    Write-Host "`n$($Service.DisplayName) service disabled." -ForegroundColor Green
                } else {
                    Write-Host "Service $Bloat not found in offline registry." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Failed to disable service: $($Bloat). Error: $_" -ForegroundColor Red
            }
        }
    }
    
    foreach ($servicePattern in $RemovalList) {
        if ($Target -eq "Online") {
            $services = Get-Service | Where-Object { $_.Name -like $servicePattern }
            foreach ($service in $services) {
                try {
                    Write-Host "Stopping and disabling service: $($service.Name)" -ForegroundColor Yellow
                    Stop-Service -Name $service.Name -Force -ErrorAction Stop
                    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop
                } catch {
                    Write-Host "Failed to stop/disable service: $($service.Name). Error: $_" -ForegroundColor Red
                }
            }
        } else {
            # Offline target service removal logic can be implemented here if needed
            Write-Host "Service removal for offline targets is not implemented." -ForegroundColor Red
        }
    }
    Write-Host "`nService removal process completed." -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Bloatware_Xbox {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Xbox Apps Removal Selection"
    $response = $null
    $XboxPackages = @(
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        #"Microsoft.XboxGameCallableUI" #Cannot be removed
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.GamingServices"
        "Microsoft.GamingApp"
    )
    $InstalledXboxPackages = @()
    foreach ($package in $XboxPackages) {
        if (($Script:AppxPackages | Where-Object Name -like $package) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $package)) {
            $InstalledXboxPackages += $package
        }
    }
    $XboxServices = @(
        "XblAuthManager"
        "XblGameSave"
        "xboxgip"
        "XboxGipSvc"
        "XboxNetApiSvc"
    )
    $XboxKeys = @(
        #Remove Background Tasks
        "Reg_HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "Reg_HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "Reg_HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "Reg_HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

        #Windows Protocol Keys
        "Reg_HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "Reg_HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
    )
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "Xbox Appx Packages" -Message "`nDo you want to remove ALL Xbox apps?`nWarning: Removing Xbox features can break non-Xbox games that use Xbox functions such as game controller features." -SuggestedAction "Skip, ONLY remove if you have no intention to play video games. Some games may rely on Xbox components." -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will remove Xbox apps and functionality. Selecting 'Skip' will skip removing these apps."
    }
    if ($response -eq "Remove") {
        if ($InstalledXboxPackages -gt 0) { Remove-AppxBloat -RemovalList $InstalledXboxPackages}
        Remove-BloatServices -RemovalList $XboxServices
        Write-Host "`nRemoving Xbox related Registry Keys..." -ForegroundColor Green
        foreach ($regKey in $XboxKeys) {
            Set-RegistryValue -Path $regKey -Remove
        }
        Write-Host "`nRemoving Game DVR..." -ForegroundColor Green
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord
        
        Write-Host "`nDisabling Xbox Game Save Task..." -ForegroundColor Green
        if ($Target -eq "Online") {
            Get-ScheduledTask  XblGameSaveTaskLogon -ErrorAction SilentlyContinue | Disable-ScheduledTask
            Get-ScheduledTask  XblGameSaveTask -ErrorAction SilentlyContinue | Disable-ScheduledTask
        } else {
            if (Test-Path "$Target`\Windows\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTaskLogon" -ea SilentlyContinue) {
                [xml]$Task = Get-Content "$Target`\Windows\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTaskLogon"
                $Task.Task.Settings.Enabled = "false"
            }
            if (Test-Path "$Target`\Windows\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTask" -ea SilentlyContinue) {
                [xml]$Task = Get-Content "$Target`\Windows\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTask"
                $Task.Task.Settings.Enabled = "false"
            }
        }
        Write-Host "`nXbox App and components removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_Teams {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Microsoft Teams Removal Selection"
    $response = $null
    $TeamsPackages = @(
        "Microsoft.Messaging"
        "MicrosoftTeams"
        "MSTeams"
		"microsoft.windowscommunicationsapps"
    )
    $InstalledTeamsPackages = @()
    foreach ($package in $TeamsPackages) {
        if (($Script:AppxPackages | Where-Object Name -like $package) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $package)) {
            $InstalledTeamsPackages += $package
        }
    }
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "Microsoft Teams" -Message "`nDo you want to remove Microsoft Teams Apps?" -SuggestedAction "Remove, unless you need Teams for Work or School. You can always reinstall it." -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will remove Microsoft Teams apps. Selecting 'Skip' will skip removing these apps."
    }
    if ($response -eq "Remove") {
        if ($InstalledTeamsPackages -gt 0) { Remove-AppxBloat -RemovalList $InstalledTeamsPackages }
        Write-Host "`nSetting Registry settings to block Teams/Chat from reappearing..." -ForegroundColor White
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Chat" -Name "ChatIcon" -Value 3 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -PropertyType DWord
        if (Test-path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications") {
            if ($Target -eq "Online") {
                Take-Ownership -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications" -User "BUILTIN\Administrators" -Verbose
            }
            Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications" -Name "ConfigureChatAutoInstall" -Value 0 -PropertyType DWord -ea SilentlyContinue;
        }
        Write-Host "`nDisabling Meet Now"
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\MeetNow" -Name "AllowMeetNow" -Value 0 -PropertyType DWord
        Write-Host "`nTeams/Chat removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_CortanaCopilot {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Cortana & Copilot Removal Selection"
    $response = $null
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "Cortana & Copilot" -Message "`nDo you want to remove Cortana and Copilot Apps from the system?" -SuggestedAction "Remove, if you don't want AI Assistant Apps" -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will attempt to remove Cortana and Copilot. Selecting 'Skip' will not remove apps."
    }
    if ($response -eq "Remove") {
        # Cortana Removal
        Write-Host "`nRemoving/Disabling Cortana..." -ForegroundColor White -BackgroundColor DarkGreen
        Remove-AppxBloat -RemovalList "Microsoft.549981C3F5F10"
        Write-Host "`nSetting Registry settings to block Cortana from reappearing..."
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -PropertyType DWord
        Write-Host "`nDisabling Cortana..."
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0 -PropertyType DWord
        # Remove Corana Consent
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -PropertyType Dword
        
        # Copilot Removal
        # ToDo: Add Copilot Removal Steps
        Remove-AppxBloat -RemovalList "Microsoft.Copilot"
        Write-Host "`nCortana & CoPilot Removed/Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_CopilotRecall {
    param (
        [switch]$Auto
    )
    Write-Header -Text "CoPilot Recall Removal Selection"
    $response = $null
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "Copilot Recall" -Message "`nDo you want to remove Copilot Recall App from the system?`nRecall takes screenshots of your screen and keylogs your activities. Considered a highly exploitable service and heavy bloat." -SuggestedAction "Remove, for Privacy and Performance." -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will attempt to remove Copilot Recall. Selecting 'Skip' will not remove the app."
    }
    if ($response -eq "Remove") {
        Write-Host "`nRemoving Copilot Recall..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -PropertyType Dword -Value 1
        Set-RegistryValue -Path "Reg_HKCU:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -PropertyType Dword -Value 1
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -PropertyType Dword -Value 1
        if ($Target -eq "Online") {
            Get-WindowsOptionalFeature -Online | Where-Object {$_.State -notin @('Disabled';'DisabledWithPayloadRemoved') -and ($_.FeatureName -like "Recall")} | Disable-WindowsOptionalFeature -Online -Remove -NoRestart -ErrorAction 'Continue'
        } else {
            Get-WindowsOptionalFeature -Path $Target | Where-Object {$_.State -notin @('Disabled';'DisabledWithPayloadRemoved') -and ($_.FeatureName -like "Recall")} | Disable-WindowsOptionalFeature -Path $Target -Remove -ErrorAction 'Continue'
        }
        Write-Host "`nCopilot Recall Removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_MicrosoftEdge {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Microsoft Edge Removal Selection"
    $response = $null
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "Microsoft Edge" -Message "`nDo you want to remove Microsoft Edge Browser from the system?" -SuggestedAction "Remove, if you prefer using a different web browser." -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will attempt to remove Microsoft Edge. Selecting 'Skip' will not remove the browser."
    }
    if ($response -eq "Remove") {
        Write-Host "`nRemoving Microsoft Edge..." -ForegroundColor White -BackgroundColor DarkGreen
        # Edge Removal using installer
        if ($Target -eq "Online") {
            $EdgePath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application"
            if (Test-Path $EdgePath) {
                $EdgeVersion = Get-ChildItem $EdgePath | Where-Object { $_.PSIsContainer } | Sort-Object Name -Descending | Select-Object -First 1
                $EdgeInstallerPath = Join-Path -Path $EdgePath -ChildPath "$($EdgeVersion.Name)\Installer\setup.exe"
                if (Test-Path $EdgeInstallerPath) {
                    Write-Host "`nUninstalling Edge version $($EdgeVersion.Name) using installer..." -ForegroundColor Yellow
                    Start-Process -FilePath $EdgeInstallerPath -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
                    Write-Host "`nMicrosoft Edge uninstallation process completed." -ForegroundColor Green
                } else {
                    Write-Host "`nEdge installer not found at expected path: $EdgeInstallerPath" -ForegroundColor Red
                }
            } else {
                Write-Host "`nMicrosoft Edge not found on the system using installer method." -ForegroundColor Green
            }
        }
        # Edge Removal using direct method
        Write-Host "`nAttempting direct removal of Microsoft Edge..." -ForegroundColor Yellow
        if ($Target -eq "Online") {
            Write-Host "`nTerminating Microsoft Edge processes..."
            Get-Process -Name "*Edge*" | Stop-Process -Force
            taskkill /f /im msedge.exe | Out-Null
        }
        if (Test-Path "$MountDir`Program Files (x86)\Microsoft\Edge"){
            Write-Host "`nTaking ownership and renaming Edge Program Files folder to disable it..."
            takeown /f "$MountDir`Program Files (x86)\Microsoft\Edge"
            icacls "$MountDir`Program Files (x86)\Microsoft\Edge" /grant Administrators:F /T /C | Out-Null
            Rename-Item -Path "$MountDir`Program Files (x86)\Microsoft\Edge" -NewName "Edge_Disabled"
        }
        if (Test-Path "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate"){
            Write-Host "`nTaking ownership and renaming EdgeUpdate Program Files folder to disable it..."
            takeown /f "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate"
            icacls "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate" /grant Administrators:F /T /C | Out-Null
            Rename-Item -Path "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate" -NewName "EdgeUpdate_Disabled"
        }
        Write-Host "`nRemoving Desktop shortcuts for Microsoft Edge..."
        if (Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk") {
            Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -Force
        }
        if (Test-Path "C:\Users\Default\Desktop\Microsoft Edge.lnk") {
            Remove-Item "C:\Users\Default\Desktop\Microsoft Edge.lnk" -Force
        }
        if (Test-Path "C:\Users\Public\Desktop\Microsoft Edge.lnk") {
            Remove-Item "C:\Users\Public\Desktop\Microsoft Edge.lnk" -Force
        }
        Write-Host "`nRemoving Edge Update Orchestrator Rigstry Key..."
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\EdgeUpdate" -Remove
        Write-Host "`nSetting Registry settings to block Edge Pre-Launch and Preloading..."
        Set-RegistryValue -Path 'Reg_HKLM_SOFTWARE:\Policies\Microsoft\Microsoft Edge\Main' -Name 'AllowPrelaunch' -Value 0 -PropertyType DWord
        Set-RegistryValue -Path 'Reg_HKLM_SOFTWARE:\Policies\Microsoft\Microsoft Edge\TabPreloader' -Name 'AllowTabPreloading' -Value 0 -PropertyType DWord
        Write-Host "`nMicrosoft Edge removal process completed." -ForegroundColor White -BackgroundColor DarkCyan
    }
    $Script:EdgeRemoveResponse = $response
}

function Bloatware_StartMenuTaskbar {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Clean Start Menu and Taskbar"
    $response = $null
    if ($Auto) {
        $response = "Clean"
    } else {
        $response = Read-PromptUser -Title "Clean Start Menu" -Message "`nDo you want to clean the Start Menu by removing default pinned items for new users?`nWhen cleaned only Settings and Explorer will be pinned." -SuggestedAction "Clean the Start Menu to make it less distracting for new users." -DefaultResponse "Skip" -ValidResponses @("Clean") -InfoText "Selecting 'Clean' will remove pinned items from the Start Menu. Selecting 'Skip' will not change settings."
    }
    if ($response -eq "Clean") {
        Write-Host "`nSetting Registry settings to clean Start Menu..." -ForegroundColor White -BackgroundColor DarkGreen
        if ($TargetWindowsVersion -eq "10") {
            $startlayout=@"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
    <StartLayoutCollection>
        <defaultlayout:StartLayout GroupCellWidth="6">
        <start:Group Name="">
            <start:Tile Size="2x2" Column="4" Row="0" AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
            <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
        </start:Group>
        </defaultlayout:StartLayout>
    </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
            $startlayout | Out-File $ENV:TEMP\StartLayout.xml
            try {
                Import-StartLayout -LayoutPath $ENV:TEMP\StartLayout.xml -MountPath $MountDir -Verbose -ErrorAction Stop
            } catch {
                LogError "Failed to Import a clean Start Menu Layout. Error: $_"
            }
            Start-Sleep 1
            Remove-Item $ENV:TEMP\StartLayout.xml -Force -ErrorAction Continue
        }
        if ($TargetWindowsVersion -eq "11+") {
            $W11StartLayout= '{"pinnedList":[{"packagedAppId":"windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"},{"desktopAppLink":"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\File Explorer.lnk"}]}'
            if(!(Test-Path -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start")) {  New-Item "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start" -force -ea SilentlyContinue }
            New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start" -Name "ConfigureStartPins" -Value $W11StartLayout -PropertyType String -Force
        }
        Write-Host "`nStart menu cleaned for new users." -ForegroundColor White -BackgroundColor DarkCyan
        $taskbarlayout=@"
<LayoutModificationTemplate xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" Version="1">
    <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
        <taskbar:TaskbarPinList>
            <taskbar:DesktopApp DesktopApplicationID="Microsoft.Windows.Explorer" />
        </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
    </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
    
    $taskbarlayout | Out-File $ENV:SystemRoot\TaskbarLayout.xml
    if(!(Test-Path -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer")) {  New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -force -ea SilentlyContinue }
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Value "$ENV:SystemRoot\TaskbarLayout.xml" -PropertyType String -Force
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Value 1 -PropertyType Dword -Force
    Write-Host "`nTaskbar cleaned for new users." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_StartMenuSuggestedApps {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Disable Suggested Apps in Start Menu"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Start Menu Suggested Apps" -Message "`nDo you want to disable Suggested Apps in the Start Menu?`nSuggested apps can be distracting and may slow down Start Menu performance." -SuggestedAction "Disable Suggested Apps for a cleaner Start Menu experience." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Hide' will set registry to disable Suggested Apps. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Suggested Apps..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -PropertyType DWord
        Write-Host "`nSuggested Apps disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_StartMenuSuggestedSites {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Disable Suggested Websites in Start Menu"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Disable Start Menu Suggested Websites" -Message "`nDo you want to disable Suggested Websites in the Start Menu?`nSuggested Websites can be distracting and may slow down Start Menu performance." -SuggestedAction "Disable Suggested Websites for a cleaner Start Menu experience." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Suggested Websites. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Suggested Websites..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -PropertyType DWord
        Write-Host "`nSuggested Websites disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_Widgets {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Widgets"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Widgets" -Message "`nDo you want to disable Widgets from the Taskbar?`nDisabling widgets can improve system performance.`nWidgets are items like Weather, News, Stocks, etc. that sit on the Taskbar." -SuggestedAction "Disable, if you don't use Widgets." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Widgets. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Widgets..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -PropertyType DWord

        #Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -PropertyType DWord
        #Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -PropertyType DWord

        #Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -PropertyType DWord
        #Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -PropertyType DWord

        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" -Name "value" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -PropertyType DWord
        Write-Host "`nWidgets disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_BlockBloatReinstall {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Bloatware"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Block Bloatware Reinstallation and Bloatware Keys" -Message "`nDo you want to apply registry settings to block unwanted Consumer Features and Suggested Apps from reinstalling?" -SuggestedAction "Block bloatware from reinstalling." -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will apply registry settings to block bloatware reinstallation. Selecting 'Skip' will skip this step."
    }
    if ($response -eq "Block") {
        Write-Host "`nApplying registry settings to block unwanted Consumer Features and Suggested Apps..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -PropertyType DWord

        $ContentFeatures = @(
            'ContentDeliveryAllowed';
            'FeatureManagementEnabled';
            'OEMPreInstalledAppsEnabled';
            'PreInstalledAppsEnabled';
            'PreInstalledAppsEverEnabled';
            'SilentInstalledAppsEnabled';
            'SoftLandingEnabled';
            'SubscribedContentEnabled';
            'SubscribedContent-310093Enabled';
            'SubscribedContent-338387Enabled';
            'SubscribedContent-338388Enabled';
            'SubscribedContent-338389Enabled';
            'SubscribedContent-338393Enabled';
            'SubscribedContent-353698Enabled';
            'SubscribedContent-353696Enabled';
            'SubscribedContent-353694Enabled';
            'SystemPaneSuggestionsEnabled';
        )
        foreach ($feature in $ContentFeatures) {
            Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $feature -Value 0 -PropertyType DWord
            Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $feature -Value 0 -PropertyType DWord
        }
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name DisableTailoredExperiencesWithDiagnosticData -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name DisableTailoredExperiencesWithDiagnosticData -Value 1 -PropertyType DWord
        Write-Host "`nBloatware blocked from reinstalling." -ForegroundColor White -BackgroundColor DarkCyan

        Write-Host "`nDisabling Mixed Reality if applicable to allow removal" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" FirstRunSucceeded -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Holographic" FirstRunSucceeded -Value 0 -PropertyType Dword
        Remove-BloatServices -RemovalList "MixedRealityOpenXRSvc"

        Write-Host "`nRemoving Bloatware registry keys..." -ForegroundColor White -BackgroundColor DarkBlue
        $BloatRegistryKeys = @(
        #Remove Background Tasks
        "Reg_HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "Reg_HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "Reg_HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "Reg_HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #Windows File
        "Reg_HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "Reg_HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "Reg_HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "Reg_HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #Scheduled Tasks to delete
        "Reg_HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        #Windows Protocol Keys
        "Reg_HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "Reg_HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #Windows Share Target
        "Reg_HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
    foreach ($RegKey in $BloatRegistryKeys) {
        Set-RegistryValue -Path $RegKey -Remove
    }

        Write-Host "`nBloatware reinstallation blocking complete." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_AdsInExplorer {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Ads from File Explorer"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Ads from File Explorer" -Message "`nDo you want to remove ads and suggestions from File Explorer?" -SuggestedAction "Block, for better privacy and less distractions." -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will set registry to remove ads from File Explorer. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Block") {
        Write-Host "`nSetting Registry settings to remove ads from File Explorer..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -PropertyType DWord
        Write-Host "`nAds blocked from File Explorer." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_MicrosoftMaps {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Remove Microsoft Maps"
    $response = $null
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "Microsoft Maps" -Message "`nDo you want to remove the Microsoft Maps app from the system?" -SuggestedAction "Remove if you don't use Microsoft Maps app" -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will remove Microsoft Maps. Selecting 'Skip' will skip removing this app."
    }
    if ($response -eq "Remove") {
        Remove-AppxBloat -RemovalList "Microsoft.WindowsMaps"
        Remove-BloatServices -RemovalList "MapsBroker"
        Write-Host "`nDisabling Auto Map Downloading/Updating"
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -PropertyType Dword -Value 0

        Write-Host "`nMicrosoft Maps removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_RemoteDesktopServices {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Remote Desktop Services"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Remote Desktop Services" -Message "`nDo you want to disable Remote Desktop Services hosting?`nThis will prevent you from allowing other computers from connecting to your PC using Microsoft RDP and other services. It might also affect Quick Assist" -SuggestedAction "Disable, remove if you don't use Remote Desktop" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will remove Remote Desktop Services. Selecting 'Skip' will skip."
    }
    if ($response -eq "Disable") {
        $RemoteDesktopServices = @(
            "UmRdpService"
            "TermService"
            "SessionEnv"
            "RasMan"
            "RasAuto"
        )
        Remove-BloatServices -RemovalList $RemoteDesktopServices
        Write-Host "`nRemote Desktop Services Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_SmartCardServices {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Smart Card Services"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Smart Card Services" -Message "`nDo you want to disable Smart Card Services?`nThis will prevent the use of physical smart cards for authentication on this PC.`nTypically home users don't use SmartCard devices to log into their PCs." -SuggestedAction "Disable, if you don't use Smart Cards" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will remove Smart Card Services. Selecting 'Skip' will skip."
    }
    if ($response -eq "Disable") {
        $SmartCardServices = @(
            "SCPolicySvc"
            "ScDeviceEnum"
            "SCardSvr"
        )
        Remove-BloatServices -RemovalList $SmartCardServices
        Write-Host "`nSmart Card Services Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Bloatware_BingStartMenuSearch {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Bing Search in Start Menu"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Bing Search in Start Menu" -Message "`nDo you want to disable Bing from doing online searches when searching in the Start Menu?" -SuggestedAction "Disable, for privacy and performance" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable Bing search integration in the Start Menu. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaInAAD" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchHighlights" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "DoNotUseWebResults" -Value 1 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Value 0 -PropertyType DWord
    Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType Dword
    Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType Dword
    }
}

function Bloatware_OneDrive {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Remove OneDrive"
    $response = $null
    if ($Auto) {
        $response = "Remove"
    } else {
        $response = Read-PromptUser -Title "OneDrive" -Message "`nDo you want to remove OneDrive from the system?" -SuggestedAction "Remove, if you don't use OneDrive for cloud storage" -DefaultResponse "Skip" -ValidResponses @("Remove") -InfoText "Selecting 'Remove' will remove OneDrive. Selecting 'Skip' will skip removing this app."
    }
    if ($response -eq "Remove") {
        Remove-AppxBloat -RemovalList "Microsoft.OneDrive"
        Write-Host "`nSetting Registry settings to block OneDrive from reappearing..." -ForegroundColor White
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Remove
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Remove
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($Target -eq "Online") {
            Get-Process -Name "*OneDrive*" | Stop-Process -Force
            taskkill /f /im OneDrive.exe | Out-Null
            Write-Host "Attempting to run OneDriveSetup.exe /Uninstall ..."
        }
        if (Test-Path "$MountDir`Windows\System32\OneDriveSetup.exe") {
            if ($Target -eq "Online"){
                if (($sid -ne 'S-1-5-18') -and ($ENV:Username -ine "DefaultUser0")) {
                    Write-Host "Attempting to run OneDriveSetup.exe /Uninstall ..."
                    Start-Process "$env:SystemDrive\Windows\System32\OneDriveSetup.exe" -ArgumentList "/Uninstall" -Wait
                } else {
                    Write-Host "System user detected. OneDriveSetup.exe /Uninstall is not nessary for this user. Skipping..."
                }
                Start-Sleep 2
                }
            takeown /f $MountDir`Windows\System32\OneDriveSetup.exe
            icacls $MountDir`Windows\System32\OneDriveSetup.exe /grant Administrators:F /C
            Rename-Item -Path "$MountDir`Windows\System32\OneDriveSetup.exe" -NewName "OneDriveSetup_Disabled.exe"
        }
        if (Test-Path "$MountDir`Windows\SysWOW64\OneDriveSetup.exe") {
            if ($Target -eq "Online"){
                if (($sid -ne 'S-1-5-18') -and ($ENV:Username -ine "DefaultUser0")) {
                    Write-Host "Attempting to run OneDriveSetup.exe /Uninstall ..."
                    Start-Process "$env:SystemDrive\Windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/Uninstall" -Wait
                } else {
                    Write-Host "System user detected. OneDriveSetup.exe /Uninstall is not nessary for this user. Skipping..."
                }
                Start-Sleep 2
            }
            takeown /f $MountDir`Windows\SysWOW64\OneDriveSetup.exe
            icacls $MountDir`Windows\SysWOW64\OneDriveSetup.exe /grant Administrators:F /C
            Rename-Item -Path "$MountDir`Windows\SysWOW64\OneDriveSetup.exe" -NewName "OneDriveSetup_Disabled.exe"
        }
        Write-Host "`nOneDrive removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableFastStartup {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Fast Startup"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Fast Startup" -Message "`nDo you want to disable Fast Startup?`nFast Startup can cause issues with some hardware and drivers during boot." -SuggestedAction "Disable, for better system stability." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Fast Startup. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Fast Startup..." -ForegroundColor White -BackgroundColor DarkGreen
        if ($Target -eq "Online") {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType Dword
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType Dword
        }
        Write-Host "`nFast Startup disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_BlockAutomaticBitlocker {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Automatic Bitlocker Encryption"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Automatic BitLocker Encryption" -Message "`nDo you want to block Windows from automatically encrypting your drive with Bitlocker?`nThis will not disable Bitlocker functionality you can always encrypt on demand. This just prevents Windows from doing it without asking. It will not un-encrypt an already encrypted drive." -SuggestedAction "Block Automatic BitLocker encryption and manually encrypt on your own terms." -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will set registry to block Automatic BitLocker encryption. Selecting 'Skip' will not change BitLocker settings."
    }
    if ($response -eq "Block") {
        Write-Host "`nSetting Registry settings to block Automatic BitLocker Encryption..." -ForegroundColor White -BackgroundColor DarkGreen
        if ($Target -eq "Online") {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\BitLocker" -Name "PreventDeviceEncryption" -Value 1 -PropertyType Dword
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\BitLocker" -Name "PreventDeviceEncryption" -Value 1 -PropertyType Dword
        }
        Write-Host "`nAutomatic BitLocker encryption blocked." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_AlignTaskbarIconsLeft {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Align Taskbar Icons"
    $response = $null
    if ($Auto) {
        $response = "Left"
    } else {
        $response = Read-PromptUser -Title "Align Taskbar Icons" -Message "`nDo you want to align the Taskbar icons to the left side of the screen or center?" -SuggestedAction "Align Taskbar icons to the left for a more familiar experience." -DefaultResponse "Skip" -ValidResponses @("Left", "Center") -InfoText "Selecting 'Left' will set registry to align Taskbar icons to the left. Selecting 'Center' will not change this setting."
    }
    if ($response -eq "Left") {
        Write-Host "`nSetting Registry settings to align Taskbar to the left..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -PropertyType Dword
        Write-Host "`nTaskbar aligned to the left." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Center") {
        Write-Host "`nSetting Registry settings to align Taskbar to the center..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1 -PropertyType Dword
        Write-Host "`nTaskbar aligned to the center." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_HideTaskbarRecentSearchHover {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Hide Recent Searches in Taskbar on Hover"
    $response = $null
    if ($Auto) {
        $response = "Hide"
    } else {
        $response = Read-PromptUser -Title "Recent Searches on Taskbar Hover" -Message "`nDo you want to stop recent search history from opening when hovering over the Search icon in the Taskbar?" -SuggestedAction "Hide recent searches for better privacy and less distractions." -DefaultResponse "Skip" -ValidResponses @("Hide") -InfoText "Selecting 'Hide' will set registry to hide recent searches on hover. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Hide") {
        Write-Host "`nSetting Registry settings to hide recent searches on hover..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSh" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSh" -Value 0 -PropertyType DWord
        Write-Host "`nRecent searches hidden on hover." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_TaskbarSearchBarToIcon {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Change Taskbar Search Bar"
    $response = $null
    if ($Auto) {
        $response = "Icon"
    } else {
        $response = Read-PromptUser -Title "Change Search Bar" -Message "`nDo you want to hide the Search Bar, Change it to an Icon, or make it a full sized bar?" -SuggestedAction "Icon or Hide, the search bar for a cleaner Taskbar." -DefaultResponse "Skip" -ValidResponses @("Icon", "Hide", "Bar") -InfoText "Selecting 'Icon' will set registry to change Search bar to icon, Hide will hide the Search Bar, and selecting 'Bar' will make it a full sized bar. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Hide") {
        Write-Host "`nSetting Registry settings to change Search bar to hidden..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarModeCache" -Value 0 -PropertyType Dword
        Write-Host "`nSearch bar changed to icon." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Icon") {
        Write-Host "`nSetting Registry settings to change Search bar to icon..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarModeCache" -Value 1 -PropertyType Dword
        Write-Host "`nSearch bar changed to icon." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Bar") {
        Write-Host "`nSetting Registry settings to change Search bar to bar..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 2 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 2 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarModeCache" -Value 2 -PropertyType Dword
        Write-Host "`nSearch bar changed to bar." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_StartMenuMorePinnedItems {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Start Menu More Pinned Items / No Recommended Items"
    $response = $null
    if ($Auto) {
        $response = "Pins"
    } else {
        $response = Read-PromptUser -Title "Start Menu Pins instead of Reccomendations?" -Message "`nDo you want to claim more space in the Start Menu to pinned apps instead of Recommended items?" -SuggestedAction "Pins, to see more pins instead of recommendations." -DefaultResponse "Skip" -ValidResponses @("Pins") -InfoText "Selecting 'Pins' will set registry to increase pinned items in Start Menu. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Pins") {
        Write-Host "`nSetting Registry settings to more Start Menu pinned items..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -PropertyType Dword
        Write-Host "`nStart Menu pinned items set to more pins." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_ClassicContextMenu {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Enable Classic Context Menu"
    $response = $null
    if ($Auto) {
        $response = "Classic"
    } else {
        $response = Read-PromptUser -Title "Enable Classic Context Menu" -Message "`nDo you want to enable the classic context menu instead of the new Windows 11 style context menu?" -SuggestedAction "Classic, if you prefer classic context menu." -DefaultResponse "Skip" -ValidResponses @("Classic") -InfoText "Selecting 'Classic' will set registry to enable classic context menu. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Classic") {
        Write-Host "`nSetting Registry settings to enable Classic Context Menu..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -Value "" -PropertyType String
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -Value "" -PropertyType String
        Write-Host "`nClassic Context Menu enabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableClipboardSuggestions {
    param (
        [switch]$Auto
    )
    if ($TargetWindowsVersion -ne "11+") { return }
    Write-Header -Text "Disable Clipboard Suggestions"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Disable Clipboard Suggestions" -Message "`nClipboard Suggestions is a feature where whenever you go to paste Text, instead of pasting normally, Windows asks you if you'd like to do transformative things to the text including using AI.`nDo you want to disable Clipboard suggestions and history?" -SuggestedAction "Disable for better privacy and less distractions." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Clipboard suggestions. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Clipboard suggestions..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Name "Disabled" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Name "Disabled" -Value 1 -PropertyType DWord
        Write-Host "`nClipboard suggestions disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_EnableLongPathSupport {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Enable Long Folder Paths"
    $response = $null
    if ($Auto) {
        $response = "Enable"
    } else {
        $response = Read-PromptUser -Title "Long Path Support" -Message "`nDo you want to enable Long Path support in Windows?`nThis allows applications to access folder paths longer than 260 characters." -SuggestedAction "Enable Long Path support for better compatibility with modern applications." -DefaultResponse "Skip" -ValidResponses @("Enable", "Disable") -InfoText "Selecting 'Enable' will set registry to enable Long Path support, or 'Disable' to revert to not having Long Path support. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Enable") {
        Write-Host "`nSetting Registry settings to enable Long Path Support..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LongPathsEnabled" -Value 1 -PropertyType Dword
        Write-Host "`nLong Path support enabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Long Path Support..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LongPathsEnabled" -Value 0 -PropertyType Dword
        Write-Host "`nLong Path support disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableLastAccessTime {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Last Access Time"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Last Access Time" -Message "`nDo you want to disable the Last Access Time property on files and folders?`nDisabling this can improve performance on systems and reduce disk reads/writes.`nFile Created & Modified dates will remain." -SuggestedAction "Disable Last Access Time updates for better performance." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Last Access Time updates. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Last Access Time..." -ForegroundColor White -BackgroundColor DarkGreen
        if ($Target -eq "Online") {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 80000001 -PropertyType Dword
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 80000001 -PropertyType Dword
        }
        #FSUtil Method: & fsutil.exe behavior set disableLastAccess 1
        Write-Host "`nLast Access Time disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableEdgeFirstRunExperience {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Edge First Run Experience"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Edge First Run Experience" -Message "`nDo you want to disable the Microsoft Edge First Run Experience?`nThis prevents Edge from showing the welcome and setup screens on first launch." -SuggestedAction "Disable Edge First Run Experience for a smoother user experience." -DefaultResponse "Skip" -ValidResponses @("Disable", "Enable") -InfoText "Selecting 'Disable' will set registry to disable Edge First Run Experience, or 'Enable' will re-enable if it was disabled. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Edge First Run Experience..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -PropertyType DWord
        Write-Host "`nEdge First Run Experience disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Enable") {
        Write-Host "`nSetting Registry settings to enable Edge First Run Experience..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 0 -PropertyType DWord
        Write-Host "`nEdge First Run Experience enabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_BlockEdgePDF {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Microsoft Edge Default PDF Handler"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Edge as Default PDF Viewer" -Message "`nDo you want to block Microsoft Edge from being the default PDF viewer?" -SuggestedAction "Block, if you prefer using a different PDF viewer." -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will set registry to block Edge as default PDF viewer. Selecting 'Skip' will not change default PDF viewer settings."
    }
    if ($response -eq "Block") {
        Write-Host "`nSetting Registry settings to block Edge as Default PDF Viewer..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCR:\.pdf\OpenWithProgIDs" -Name "MSEdgePDF" -Remove
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge" -Name "AlwaysOpenPdfExternally" -Value 1 -PropertyType DWord
        Write-Host "`nMicrosoft Edge removed from being default PDF viewer." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_EnableVerboseBSOD {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Verbose Blue Screen of Death (BOSD)"
    $response = $null
    if ($Auto) {
        $response = "Enable"
    } else {
        $response = Read-PromptUser -Title "Verbose Blue Screen of Death (BOSD)" -Message "`nDo you want to enable Verbose Blue Screen of Death (BOSD) messages?`nThis provides more detailed information during a system crash which can be useful for troubleshooting." -SuggestedAction "Enable Verbose BOSD for better troubleshooting information." -DefaultResponse "Skip" -ValidResponses @("Enable", "Disable") -InfoText "Selecting 'Enable' will set registry to enable Verbose BOSD, or 'Disable' will revert back to not showing it. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Enable") {
        Write-Host "`nSetting Registry settings to enable Verbose Blue Screen of Death (BOSD)..." -ForegroundColor White -BackgroundColor DarkGreen
        if ($Target -eq "Online") {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Value 1 -PropertyType Dword
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\CrashControl" -Name "DisplayParameters" -Value 1 -PropertyType Dword
        }
        Write-Host "`nVerbose Blue Screen of Death (BOSD) enabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Verbose Blue Screen of Death (BOSD)..." -ForegroundColor White -BackgroundColor DarkGreen
        if ($Target -eq "Online") {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Value 0 -PropertyType Dword
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
            Set-RegistryValue -Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\CrashControl" -Name "DisplayParameters" -Value 0 -PropertyType Dword
        }
        Write-Host "`nVerbose Blue Screen of Death (BOSD) disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_EnableVerboseStartupShutdown {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Enable Verbose Startup and Shutdown"
    $response = $null
    if ($Auto) {
        $response = "Enable"
    } else {
        $response = Read-PromptUser -Title "Verbose Startup and Shutdown Messages" -Message "`nDo you want to enable Verbose Startup and Shutdown messages?`nThis provides more detailed information during system startup and shutdown which can be useful for troubleshooting." -SuggestedAction "Enable Verbose Startup and Shutdown messages for better troubleshooting information." -DefaultResponse "Skip" -ValidResponses @("Enable", "Disable") -InfoText "Selecting 'Enable' will set registry to enable Verbose Startup and Shutdown messages, or 'Disable' to revert bak to not showing it. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Enable") {
        Write-Host "`nSetting Registry settings to enable Verbose Startup and Shutdown messages..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -PropertyType Dword
        Write-Host "`nVerbose Startup and Shutdown messages enabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Verbose Startup and Shutdown messages..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 0 -PropertyType Dword
        Write-Host "`nVerbose Startup and Shutdown messages disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableStickyKeysShortcut {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Sticky Keys Shortcut"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Sticky Keys Shortcut" -Message "`nDo you want to disable the Sticky Keys shortcut (pressing Shift key 5 times)?`nThis prevents the Sticky Keys prompt from appearing when the Shift key is pressed multiple times." -SuggestedAction "Disable Sticky Keys shortcut to avoid accidental activation." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Sticky Keys shortcut. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Sticky Keys shortcut..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -PropertyType String
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -PropertyType String
        Write-Host "`nSticky Keys shortcut disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableFilterKeysShortcut {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Filter Keys Shortcut"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Filter Keys Shortcut" -Message "`nDo you want to disable the Filter Keys shortcut (holding down the right Shift key for 8 seconds)?`nThis prevents the Filter Keys prompt from appearing when the right Shift key is held down." -SuggestedAction "Disable Filter Keys shortcut to avoid accidental activation." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Filter Keys shortcut. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Filter Keys shortcut..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Control Panel\Accessibility\FilterKeys" -Name "Flags" -Value "122" -PropertyType String
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Control Panel\Accessibility\FilterKeys" -Name "Flags" -Value "122" -PropertyType String
        Write-Host "`nFilter Keys shortcut disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_DisableToggleKeysShortcut {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Toggle Keys Shortcut"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Toggle Keys Shortcut" -Message "`nDo you want to disable the Toggle Keys shortcut (holding down the Num Lock key for 5 seconds)?`nThis prevents the Toggle Keys prompt from appearing when the Num Lock key is held down." -SuggestedAction "Disable Toggle Keys shortcut to avoid accidental activation." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable Toggle Keys shortcut. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable Toggle Keys shortcut..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -PropertyType String
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -PropertyType String
        Write-Host "`nToggle Keys shortcut disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_ShowHideSystemTrayIcons {
    Write-Header -Text "Show or Hide System Tray Icons by Default"
    $response = $null
    
    $response = Read-PromptUser -Title "Show or Hide Tray Icons by Default" -Message "`nDo you want to Show All System Tray icons by default, Hide them (default), or Skip changing anything?" -SuggestedAction "Hide if you want a clean taskbar or Show if you want to always see all icons.." -DefaultResponse "Skip" -ValidResponses @("Show", "Hide") -InfoText "Selecting 'Show' will show hidden tray icons by default. Selecting 'Hide' will hide icons by default which is usual Windows behavior. Selecting 'Skip' will not change this setting."
    if ($response -eq "Show") {
        Write-Host "`nSetting Registry settings to show hidden tray icons by default..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0 -PropertyType DWord
        Write-Host "`nHidden tray icons will now be shown by default." -ForegroundColor White -BackgroundColor DarkCyan
    } elseif ($response -eq "Hide") {
        Write-Host "`nSetting Registry settings to hide tray icons by default..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 1 -PropertyType DWord
        Write-Host "`nTray icons will now be hidden by default." -ForegroundColor White -BackgroundColor DarkCyan
    } else {
        Write-Host "`nSkipping Tray Icon visibility changes." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_ShowHideFileExtensions {
    Write-Header -Text "Show or Hide File Extensions"
    $response = $null
    
    $response = Read-PromptUser -Title "Show or Hide File Extensions" -Message "`nDo you want to Show File Extensions for known file types, Hide them (default), or Skip changing anything?" -SuggestedAction "Show if you want better visibility of file types for security." -DefaultResponse "Skip" -ValidResponses @("Show", "Hide") -InfoText "Selecting 'Show' will show file extensions for known file types. Selecting 'Hide' will hide them which is usual Windows behavior. Selecting 'Skip' will not change this setting."
    if ($response -eq "Show") {
        Write-Host "`nSetting Registry settings to show file extensions..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -PropertyType DWord
        Write-Host "`nFile extensions will now be shown." -ForegroundColor White -BackgroundColor DarkCyan
    } elseif ($response -eq "Hide") {
        Write-Host "`nSetting Registry settings to hide file extensions..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -PropertyType DWord
        Write-Host "`nFile extensions will now be hidden." -ForegroundColor White -BackgroundColor DarkCyan
    } else {
        Write-Host "`nSkipping File Extension visibility changes." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_ShowHideDetailedFileOperations {
    Write-Header -Text "Show or Hide Detailed File Operations"
    $response = $null
    
    $response = Read-PromptUser -Title "Show or Hide Detailed File Operation Dialogs" -Message "`nDo you want to Show detailed information in file operation dialogs (copy, move, delete) such as Speed, Item, and ETA; Hide them only showing a progress bar (default), or Skip changing anything?" -SuggestedAction "Show if you want to see detailed information during file operations." -DefaultResponse "Skip" -ValidResponses @("Show", "Hide") -InfoText "Selecting 'Show' will show file detailed operation dialogs. Selecting 'Hide' will show just a progress bar in a neat small window. Selecting 'Skip' will not change this setting."
    if ($response -eq "Show") {
        Write-Host "`nSetting Registry settings to show detailed file operation dialogs..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1
        Write-Host "`nFile operation dialogs will now be shown." -ForegroundColor White -BackgroundColor DarkCyan
    } elseif ($response -eq "Hide") {
        Write-Host "`nSetting Registry settings to show minimal file operation dialogs..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 0
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 0
        Write-Host "`nFile operation dialogs will now be hidden." -ForegroundColor White -BackgroundColor DarkCyan
    } else {
        Write-Host "`nSkipping File Operation dialog visibility changes." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Tweak_SelectDefaultExplorerLocation {
    Write-Header -Text "Select Default Explorer Location"
    $response = $null
    
    $response = Read-PromptUser -Title "Default Folder for Explorer" -Message "`nWhenever you open Windows File Explorer you are taken to a folder by default.`nWould you like the default folder to be:`nSelect (PC) for: This PC - Shows your drives like C:\`nSelect (QUICK) for: Quick Access (default) - Your recently used files and folders`nSelect (Downloads) for: Downloads - Your Downloads folder.`nSelect 'Skip' to not change the current setting." -SuggestedAction "Choose your preferred option or simply Skip." -DefaultResponse "Skip" -ValidResponses @("PC", "Quick", "Downloads") -InfoText "Selecting 'PC' will set File Explorer to open to This PC. Selecting 'Quick' will set File Explorer to open to Quick Access. Selecting 'Downloads' will set File Explorer to open to Downloads folder. Selecting 'Skip' will not change this setting."
    if ($response -eq "PC") {
        Write-Host "`nSetting Registry settings to open File Explorer to This PC..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -PropertyType DWord
        Write-Host "`nFile Explorer will now open to This PC." -ForegroundColor White -BackgroundColor DarkCyan
    } elseif ($response -eq "Quick") {
        Write-Host "`nSetting Registry settings to open File Explorer to Quick Access..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 2 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 2 -PropertyType DWord
        Write-Host "`nFile Explorer will now open to Quick Access." -ForegroundColor White -BackgroundColor DarkCyan
    } elseif ($response -eq "Downloads") {
        Write-Host "`nSetting Registry settings to open File Explorer to Downloads folder..." -ForegroundColor White -BackgroundColor DarkGreen
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 3 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 3 -PropertyType DWord
        Write-Host "`nFile Explorer will now open to Downloads folder." -ForegroundColor White -BackgroundColor DarkCyan
    } else {
        Write-Host "`nSkipping File Explorer default folder changes." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_BlockTelemetry {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Telemetry and Data Collection"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Telemetry and Data Collection" -Message "`nDo you want to block Telemetry and Data Collection features in Windows?`nThis will set various registry settings to limit data collection and telemetry sent to Microsoft." -SuggestedAction "Block Telemetry for better privacy." -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will set registry to block Telemetry and Data Collection. Selecting 'Skip' will not change these settings."
    }
    if ($response -eq "Block") {
        Write-Host "`nDisabling Advertising ID" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -PropertyType Dword
        
        Write-Host "`nDisabling Advertising via Bluetooth" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Value 0 -PropertyType Dword
        
        Write-Host "`nBlocking Input Data Harvesting" -ForegroundColor White -BackgroundColor DarkBlue
        # Current User
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -PropertyType DWord
        # Default User
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -PropertyType DWord
        
        Write-Host "`nSetting No-Advertizing Info Policy" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -PropertyType Dword

        Write-Host "`nStopping the Windows Feedback Experience program" -ForegroundColor White -BackgroundColor DarkBlue
        # Current User
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Siuf\Rules" PeriodInNanoSeconds -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Siuf\Rules" NumberOfSIUFInPeriod -Value 0 -PropertyType Dword
        # Default User
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Siuf\Rules" PeriodInNanoSeconds -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Siuf\Rules" NumberOfSIUFInPeriod -Value 0 -PropertyType Dword

        Write-Host "`nDisabling Wi-Fi Sense" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -PropertyType Dword

        Write-Host "`nDisabling live tiles" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" NoTileApplicationNotification -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" NoTileApplicationNotification -Value 1 -PropertyType Dword

        Write-Host "`nTurning off Data Collection" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\DataCollection" AllowTelemetry -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DataCollection" AllowTelemetry -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" AllowTelemetry -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat" AITEnable -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -PropertyType DWord

        Write-Host "`nDisabling People icon on Taskbar" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" PeopleBand -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" PeopleBand -Value 0 -PropertyType Dword

        Write-Host "`nRestricting Windows Update P2P only to local network..." -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -PropertyType Dword
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -PropertyType Dword

        Write-Host "`nDisabling Handwriting Error Reports" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -PropertyType Dword -Value 1

        Write-Host "`nDisabling Sharing of Handwriting Data" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -PropertyType Dword -Value 1

        # Disable Customer Experience Improvement Program
        Write-Host "`nDisable Customer Experience Improvement Program" -ForegroundColor White -BackgroundColor DarkBlue
        if ($Target -eq "Online") {
            Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
        } else {
            if (Test-Path "$Target`\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ea SilentlyContinue) {
                [xml]$Task = Get-Content "$Target`\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
                $Task.Task.Settings.Enabled = "false"
            }
        }

        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -PropertyType DWord

        #Disable Windows User Feedback Task
        if ($Target -eq "Online") {
            Get-ScheduledTask  DmClient | Disable-ScheduledTask
            Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask
        } else {
            if (Test-Path "$Target`\Windows\System32\Tasks\Microsoft\Windows\Feedback\Siuf\DmClient" -ea SilentlyContinue) {
                [xml]$Task = Get-Content "$Target`\Windows\System32\Tasks\Microsoft\Windows\Feedback\Siuf\DmClient"
                $Task.Task.Settings.Enabled = "false"
            }
            if (Test-Path "$Target`\Windows\System32\Tasks\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ea SilentlyContinue) {
                [xml]$Task = Get-Content "$Target`\Windows\System32\Tasks\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
                $Task.Task.Settings.Enabled = "false"
            }
        }

        Write-Host "`nDisable nag to finish setting up the device" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -PropertyType DWord

        Write-Host "`nDisable Windows Tracking App Usage" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType DWord

        Write-Host "`nDisable use of diagnostic data for tailor-made user experiences" -ForegroundColor White -BackgroundColor DarkBlue
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -PropertyType DWord

        Write-Host "`nTelemetry and data collection blocking applied." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_BlockUserAccountActivity {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Storing User Account Activity"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Storing User Activity History" -Message "`nDo you want to disable Storing User Activity History tracking on this PC?`nThis will prevent Windows from tracking your activities across apps and services." -SuggestedAction "Disable User Activity History for better privacy." -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will set registry to disable User Activity History. Selecting 'Skip' will not change this setting."
    }
    if ($response -eq "Disable") {
        Write-Host "`nSetting Registry settings to disable User Activity History..." -ForegroundColor White -BackgroundColor DarkGreen
        
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "PublishUserActivities" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "UploadUserActivities" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "PublishUserActivities" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "UploadUserActivities" -Value 0 -PropertyType DWord
        Write-Host "`nUser Activity History disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_BlockAppUserAccountAccess {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Apps from Accessing User Account Information"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Apps accessing User Account Information" -Message "`nDo you want to block apps from accessing user account information?`nBy default any app can read your Username, Email Address, Profile Picture, and more without asking." -SuggestedAction "Block, for privacy" -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will block apps from accessing user account information. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Block") {
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny" -PropertyType String
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny" -PropertyType String

        # System Level Policy
        #Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny" -PropertyType String

        Write-Host "`nBlocked Apps from accessing User Account Information." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_BlockAppDiagnosticAccess {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Block Apps from Accessing Diagnostic Information"
    $response = $null
    if ($Auto) {
        $response = "Block"
    } else {
        $response = Read-PromptUser -Title "Apps accessing Diagnostic Information" -Message "`nDo you want to block apps from accessing diagnostic information?`nBy default any app can read your diagnostic data without asking." -SuggestedAction "Block, for privacy" -DefaultResponse "Skip" -ValidResponses @("Block") -InfoText "Selecting 'Block' will block apps from accessing diagnostic information. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Block") {
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -PropertyType String
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -PropertyType String

        # System Level Policy
        #Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -PropertyType String

        Write-Host "`nBlocked Apps from accessing Diagnostic Information." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_DisableErrorReporting {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Windows Error Reporting"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Error Reporting" -Message "`nDo you want to disable Windows Error Reporting?`nThis will prevent Windows from sending error reports to Microsoft." -SuggestedAction "Disable, for privacy" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable Windows Error Reporting. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -PropertyType DWord
        Remove-BloatServices -RemovalList "WerSvc"
        Remove-AppxBloat -RemovalList "Microsoft.WindowsFeedbackHub"
        Write-Host "`nWindows Error Reporting Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_DisableTextMessageCloudBackup {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Text Message Cloud Backup"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Text Message Cloud Backup" -Message "`nDo you want to disable text message cloud backup?`nBy default Windows can back up your text messages to the cloud if you use the Your Phone app." -SuggestedAction "Disable, for privacy" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable text message cloud backup. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -PropertyType Dword
        Write-Host "`nText Message Cloud Backup Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_DisableClipboardCloudSync {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Cloud Clipboard Sync"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Clipboard Cloud Sync" -Message "`nDo you want to disable clipboard cloud sync?`nBy default Windows can sync your clipboard history across devices using your Microsoft account." -SuggestedAction "Disable, for privacy" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable clipboard cloud sync. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Clipboard" -Name "EnableCloudClipboard" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Clipboard" -Name "EnableCloudClipboard" -Value 0 -PropertyType DWord
        Write-Host "`nClipboard Cloud Sync Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_DisableClipboardHistory {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Clipboard History"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Clipboard History" -Message "`nDo you want to disable clipboard history?`nBy default Windows can save your clipboard history locally.`nYou can access it using Winkey + V" -SuggestedAction "Disable, for privacy" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable clipboard history. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 0 -PropertyType DWord
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 0 -PropertyType DWord
        # System Level Policy
        #Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -PropertyType DWord
        Write-Host "`nClipboard History Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_DisableWindowsSpotlight {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Windows Spotlight"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Windows Spotlight" -Message "`nDo you want to disable Windows Spotlight?`nWindows Spotlight displays images and ads on the lock screen." -SuggestedAction "Disable, for privacy" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable Windows Spotlight. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -PropertyType Dword -Value 0
        Set-RegistryValue -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -PropertyType Dword -Value 0
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType Dword -Value 1
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType Dword -Value 1
        Set-RegistryValue -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -PropertyType Dword -Value 1
        
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -PropertyType Dword -Value 0
        Set-RegistryValue -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -PropertyType Dword -Value 0
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType Dword -Value 1
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType Dword -Value 1
        Set-RegistryValue -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -PropertyType Dword -Value 1
        
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -PropertyType DWord -Value 2
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent" -Name "IncludeEnterpriseSpotlight" -PropertyType DWord -Value 0
        Write-Host "`nWindows Spotlight Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

function Privacy_DisableCameraAtLogon {
    param (
        [switch]$Auto
    )
    Write-Header -Text "Disable Camera at Logon"
    $response = $null
    if ($Auto) {
        $response = "Disable"
    } else {
        $response = Read-PromptUser -Title "Disable Camera at Logon" -Message "`nDo you want to disable camera access at logon?`nBy default Windows can use the camera at the logon screen for features like Windows Hello.`nAnswering 'Disable' will disable the Camera from being usable at the logon screen." -SuggestedAction "Disable, for privacy" -DefaultResponse "Skip" -ValidResponses @("Disable") -InfoText "Selecting 'Disable' will disable camera access at logon. Selecting 'Skip' will leave it enabled."
    }
    if ($response -eq "Disable") {
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -PropertyType DWord
        Write-Host "`nCamera access at logon Disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

#endregion

#region Bloatlists
$Script:BloatlistAppxPossible = @(
    @{Item="Microsoft.MicrosoftSolitaireCollection";Desc="Modern online version of Solitaire with ads and optional sign-in. Not the classic Solitaire. Can be reinstalled from the Store.";Suggested="Remove unless you play it."},
    @{Item="Microsoft.3DBuilder";Desc="Legacy 3D modeling and printing app. Allows basic editing and repair of 3D files like STL and OBJ.";Suggested="Remove, it's deprecated."},
    @{Item="Microsoft.Microsoft3DViewer";Desc="Viewer for 3D model files (e.g., FBX, OBJ, STL). Includes basic animation and mixed reality features.";Suggested="Harmless, just a 3D model viewer. Remove to save space."},
    @{Item="Microsoft.Print3D";Desc="Deprecated 3D printing app. Replaced by 3D Builder. Known for security vulnerabilities.";Suggested="Remove, it's deprecated and insecure."},
    @{Item="Microsoft.RemoteDesktop";Desc="Remote Desktop client for connecting to other PCs. Being replaced by the Windows App.";Suggested="Skip (Keep) only if you use Windows Remote Desktop."},
    @{Item="Microsoft.GetHelp";Desc="Basic support app for Windows troubleshooting. Some SARA tool features moved here.";Suggested="Remove unless new to Windows and need help."},
    @{Item="Microsoft.WindowsAlarms";Desc="Clock app with alarm, timer, and stopwatch features. Preinstalled on most Windows versions.";Suggested="Skip (Keep), provides basic timer and alarm functions."},
    @{Item="Microsoft.WindowsCamera";Desc="Simple camera app for taking photos and videos using your webcam.";Suggested="Skip (Keep), it's a very basic camera app."},
    @{Item="Microsoft.YourPhone";Desc="Phone Link app to sync Android phone with PC. Shows texts, calls, and notifications. Runs background services.";Suggested="Remove for privacy, Skip (Keep) if you want to sync phone."},
    @{Item="Microsoft.OutlookForWindows";Desc="New Outlook client replacing Mail and Calendar apps. Can run alongside classic Outlook.";Suggested="Skip (Keep) if you use Outlook, otherwise remove."},
    @{Item="Microsoft.PowerAutomateDesktop";Desc="Automation tool for creating desktop workflows. Part of Power Platform.";Suggested="Remove unless you use it for automation tasks."},
    @{Item="MicrosoftWindows.CrossDevice";Desc="Enables cross-device experiences like clipboard sync and app continuation across Windows devices.";Suggested="Remove for privacy, Skip (Keep) if you use cross-device features."},
    @{Item="Microsoft.MicrosoftStickyNotes";Desc="Sticky Notes app for quick notes on desktop. Syncs across devices via Microsoft account.";Suggested="Skip (Keep) if you use Sticky Notes, otherwise remove."},
    @{Item="Microsoft.Office.OneNote";Desc="Note-taking app for organizing text, drawings, and media. Syncs with Office 365.";Suggested="Skip (Keep) if you use OneNote, otherwise remove."},
    @{Item="Microsoft.Whiteboard";Desc="Collaborative whiteboard app for drawing and brainstorming in real-time with others.";Suggested="Remove unless you use it for collaboration."}
) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

$Script:BloatlistAppxSponsored = @(
    # Sponsored/featured Appx Packages
    "Clipchamp.Clipchamp"
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Spotify*"
    "*Minecraft*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
    "*Disney*"
    "*PicsArt-PhotoStudio*"
    "*Netflix*"
    "*PolarrPhotoEditorAcademicEdition*"
    "*LinkedInforWindows*"
    "*AutodeskSketchBook*"
    "*MarchofEmpires*"
    "*Plex*"
    "*iHeartRadio*"
    "*FarmVille*"
    "*Duolingo*"
    "*CyberLinkMediaSuiteEssentials*"
    "*DrawboardPDF*"
    "*Fitbit*"
    "*Asphalt8Airborne*"
    "*Keeper*"
    "*COOKINGFEVER*"
    "*CaesarsSlotsFreeCasino*"
    "*Shazam*"
    "*SlingTV*"
    "*NYTCrossword*"
    "*PhototasticCollage*"
    "*TuneInRadio*"
    "*WinZipUniversal*"
    "*XING*"
    "*RoyalRevolt2*"
    "*king.com*"
    "*McAfeeSecurity*"
    "*AdobeCreativeCloudExpress*"
    "*PrimeVideo*"
    "*TikTok*"
)

$Script:BloatlistAppxJunk = @(
    @{Item="MicrosoftWindows.Client.WebExperience";Desc="Provides Widgets on the taskbar. Loads web content continuously, even when hidden. Can impact performance.";Suggested="Remove for better performance and privacy."},
    @{Item="*Microsoft.BingWeather*";Desc="Weather app that uses your location to show forecasts. Sends location data to Microsoft.";Suggested="Remove for privacy."},
    @{Item="Microsoft.MinecraftUWP";Desc="Minecraft Bedrock Edition for Windows. Requires a license. Can be reinstalled from the Store.";Suggested="Remove if you don't play Minecraft Bedrock Edition."},
    #@{Item="Microsoft.MicrosoftEdgeDevToolsClient";Desc="Developer tools for Microsoft Edge. Remove only if Edge is removed."}, #Cannot be removed
    @{Item="Microsoft.Windows.DevHome";Desc="Developer dashboard for managing projects, system info, and GitHub integration. Not useful for non-developers.";Suggested="Remove unless you are a developer."},
    @{Item="Microsoft.Advertising.Xaml";Desc="Provides APIs for displaying ads in UWP apps. Used by some Store apps.";Suggested="Remove for privacy."},
    @{Item="Microsoft.Appconnector";Desc="Legacy connector for cross-device app experiences. Mostly obsolete.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.BingFinance";Desc="Finance app showing market data, news, and personal finance tools.";Suggested="Remove unless you use it."},
    @{Item="Microsoft.BingNews";Desc="News aggregator app showing headlines from various sources. Sends usage data to Microsoft.";Suggested="Remove for privacy and performance."},
    @{Item="Microsoft.BingSports";Desc="Sports news app with scores, schedules, and updates.";Suggested="Remove unless you use it."},
    @{Item="Microsoft.BingTranslator";Desc="Translation app for text, speech, and images. Uses Microsoft cloud services.";Suggested="Remove, there's better alternatives."},
    @{Item="Microsoft.BingFoodAndDrink";Desc="Deprecated app with recipes and cooking tips. No longer maintained.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.BingHealthAndFitness";Desc="Obsolete app with fitness tracking and health tips. No longer supported.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.BingTravel";Desc="Travel app with guides, booking tools, and recommendations. Deprecated.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.WindowsReadingList";Desc="Legacy app for saving articles and content to read later. No longer supported.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.FreshPaint";Desc="Digital painting app with realistic brushes and canvas effects.";Suggested="Remove unless you use it."},
    @{Item="Microsoft.Getstarted";Desc="Introductory app with tutorials for new Windows users. Safe to remove.";Suggested="Remove unless you're new to Windows."},
    @{Item="Microsoft.MicrosoftOfficeHub";Desc="Launcher for Office web-based apps and services. Mostly redundant if you use office desktop apps.";Suggested="Remove unless you use Office web apps and prefer it just going to the website."},
    @{Item="Microsoft.MicrosoftPowerBIForWindows";Desc="Power BI desktop app for viewing and analyzing business data.";Suggested="Remove unless you use Power BI for business."},
    @{Item="Microsoft.NetworkSpeedTest";Desc="Simple app to test internet speed. No longer maintained.";Suggested="Remove, there are better alternatives."},
    @{Item="Microsoft.News";Desc="Modern version of Bing News. Aggregates headlines and articles.";Suggested="Remove for privacy and performance."},
    @{Item="Microsoft.Office.Lens";Desc="Document scanning app that saves to PDF or image formats.";Suggested="Remove unless you use it for scanning documents."},
    @{Item="Microsoft.Office.Sway";Desc="Web-based presentation app. Deprecated and rarely used.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.OneConnect";Desc="Obsolete app for connecting to social and messaging services. Safe to remove.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.People";Desc="Contact manager app. Syncs with email and social accounts.";Suggested="Remove for privacy. It's very invasive."},
    @{Item="Microsoft.SkypeApp";Desc="Skype UWP app for messaging and calls. Can be replaced with desktop version.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.Office.Todo.List";Desc="Microsoft To Do app for task and list management.";Suggested="Remove unless you use it for task management."},
    #@{Item="Microsoft.WindowsFeedbackHub";Desc="App for submitting feedback to Microsoft."}, #Moved to Privacy_DisableErrorReporting function
    #@{Item="Microsoft.WindowsMaps";Desc="Maps and navigation app with offline support."}, #Moved to Bloatware_MicrosoftMaps function
    @{Item="Microsoft.WindowsPhone";Desc="Legacy app for syncing with Windows Phone devices. Deprecated.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.WindowsSoundRecorder";Desc="Basic voice recording app. Can be replaced with third-party tools.";Suggested="Remove, there are better alternatives."},
    @{Item="Microsoft.ZuneMusic";Desc="Legacy music app. Replaced by Groove and Media Player.";Suggested="Remove, there are better alternatives."},
    @{Item="Microsoft.ZuneVideo";Desc="Legacy video app. Replaced by Movies & TV.";Suggested="Remove, there are better alternatives."},
    @{Item="Microsoft.CommsPhone";Desc="Phone dialer component for calling features. Rarely used.";Suggested="Remove unless you use calling features and need it for accessibility."},
    @{Item="Microsoft.Wallet";Desc="Digital wallet app for storing payment cards. Deprecated.";Suggested="Remove, it's obsolete."},
    @{Item="Microsoft.MixedReality.Portal";Desc="Portal for setting up and managing VR headsets. Safe to remove if not using VR.";Suggested="Remove, it's obsolete."},
    @{Item="MicrosoftCorporationII.MicrosoftFamily";Desc="Family safety and parental control features for Microsoft accounts.";Suggested="Remove unless you use Family Safety features."},
    @{Item="Microsoft.BingSearch";Desc="Provides Bing search integration in Windows. Can be removed for privacy.";Suggested="Remove for privacy and performance."}
    #@{Item="Microsoft.Copilot";Desc="Launcher for Windows Copilot. Opens web-based assistant in a web browser."} #Moved to Bloatware_CortanaCopilot function
) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

$Script:BloatlistWindowsCapabilities = @(
    @{Item="Browser.InternetExplorer";Desc="Legacy Internet Explorer browser. Deprecated and insecure. Remove unless needed for legacy apps.";Suggested="Remove for security."},
    @{Item="Media.WindowsMediaPlayer";Desc="Classic Windows Media Player. Useful for legacy media formats. Safe to remove if unused.";Suggested="Remove unless you use it for legacy media playback."},
    @{Item="Microsoft.Wallpapers.Extended";Desc="Adds extra wallpapers and themes. Minimal impact. Remove to save disk space.";Suggested="Remove to save disk space."},
    @{Item="Hello.Face";Desc="Facial recognition login via Windows Hello. Requires IR-capable camera. Remove if not using Windows Hello.";Suggested="Remove for privacy if not using Windows Hello."},
    @{Item="Language.Handwriting";Desc="Enables handwriting input with pen or touch. Remove if not using tablet or stylus features.";Suggested="Remove unless you use a tablet or stylus for handwritten input."},
    @{Item="Language.OCR";Desc="Optical Character Recognition for extracting text from images. Required for tools like PowerToys Text Extractor.";Suggested="Skip (Keep), many tools rely on OCR."},
    @{Item="Language.Speech";Desc="Speech recognition for dictation and voice commands. Used by some video games. Remove if not using voice input.";Suggested="Skip (Keep), needed for voice to text, voice commands, and some games."},
    @{Item="Language.TextToSpeech";Desc="Text-to-Speech voices (e.g., Microsoft David, Zira). Used by Narrator, video games, and accessibility tools. Remove if not needed.";Suggested="Skip (Keep), needed for Narrator, some accessibility tools, apps, and games."}
) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

$Script:BloatlistServices = @(
    #@{Item="WSearch";Desc="Windows Search. Needed to find files in the Start Menu and File Explorer. Disable only if you have a search alternative."},
    @{Item="DiagTrack";Desc="Connected User Experiences and Telemetry. Sends diagnostic and usage data to Microsoft. Disable for privacy and performance.";Suggested="Disable for privacy and performance."},
    @{Item="icssvc";Desc="Windows Mobile Hotspot Service. Enables sharing your internet connection. Disable if not using hotspot features.";Suggested="Disable if not using hotspot features."},
    @{Item="WbioSrvc";Desc="Windows Biometric Service. Required for fingerprint or facial recognition login. Disable if not using biometrics.";Suggested="Disable if not using biometrics."},
    #@{Item="MixedRealityOpenXRSvc";Desc="Deprecated Mixed Reality VR system."}, #Handled elsewhere to remove Mixed Reality
    @{Item="WMPNetworkSvc";Desc="Windows Media Player Network Sharing. Shares media libraries over the network. Disable if not using WMP streaming.";Suggested="Disable if not using WMP streaming."},
    @{Item="wisvc";Desc="Windows Insider Service. Supports Insider builds. Disable if not enrolled in the Insider Program.";Suggested="Disable, Insider Program provides unstable bleeding-edge updates."},
    #@{Item="WerSvc";Desc="Error Reporting"}, #Handled in Privacy_DisableErrorReporting function
    @{Item="WalletService";Desc="Hosts objects for Wallet apps. Legacy feature. Safe to disable.";Suggested="Disable, it's obsolete."},
    @{Item="SysMain";Desc="SysMain (formerly SuperFetch). Preloads frequently used apps into RAM.";Suggested="Skip (Keep) if you have ANY hard-disk drives. Disable only if you have ALL SSD storage."},
    #@{Item="svsvc";Desc="Spot Verifier. Verifies file system integrity during restore operations. Disable if not using System Restore."},
    #@{Item="SCPolicySvc";Desc="Smart Card Removal Policy"}, #Handled in Bloatware_SmartCardServices function
    #@{Item="ScDeviceEnum";Desc="Smart Card Device Enumeration Service"}, #Handled in Bloatware_SmartCardServices function
    #@{Item="SCardSvr";Desc="Smart Card"}, #Handled in Bloatware_SmartCardServices function
    @{Item="RetailDemo";Desc="Retail Demo Service. Used in store demo units. Disable unless device is in retail demo mode.";Suggested="Disable, this is useless."},
    #@{Item="UmRdpService";Desc="Remote Desktop Services UserMode Port Redirector"}, #Handled in Bloatware_RemoteDesktopServices function
    #@{Item="TermService";Desc="Remote Desktop Services"}, #Handled in Bloatware_RemoteDesktopServices function
    #@{Item="SessionEnv";Desc="Remote Desktop Configuration"}, #Handled in Bloatware_RemoteDesktopServices function
    #@{Item="RasMan";Desc="Remote Access Connection Manager"}, #Handled in Bloatware_RemoteDesktopServices function
    #@{Item="RasAuto";Desc="Remote Access Auto Connection Manager"}, #Handled in Bloatware_RemoteDesktopServices function
    #@{Item="TroubleshootingSvc";Desc="Recommended Troubleshooting Service"},
    #@{Item="wercplsupport";Desc="Problem Reports Control Panel Support"},
    #@{Item="PrintNotify";Desc="Printer Extensions and Notifications"},
    @{Item="PhoneSvc";Desc="Manages telephony state. Legacy service for dial-up and modem support. Disable if not using telephony features.";Suggested="Disable, unless you have edge-case need for it."},
    @{Item="SEMgrSvc";Desc="Secure Element and NFC Manager. Used for mobile payments. Disable if not using NFC or Wallet features.";Suggested="Disable unless you use your computer as a cash register."},
    @{Item="WpcMonSvc";Desc="Parental Controls monitoring. Disable if not using Family Safety features.";Suggested="Disable unless you use Family Safety features."},
    #@{Item="CscService";Desc="Offline Files"},
    #@{Item="InstallService";Desc="Microsoft Store Install Service"},
    @{Item="SmsRouter";Desc="SMS Router Service. Legacy messaging support. Safe to disable.";Suggested="Disable, it's obsolete."},
    #@{Item="smphost";Desc="Microsoft Storage Spaces SMP"},
    #@{Item="NgcCtnrSvc";Desc="Microsoft Passport Container"},
    #@{Item="MsKeyboardFilter";Desc="Microsoft Keyboard Filter"},
    #@{Item="cloudidsvc";Desc="Microsoft Cloud Identity Service"},
    #@{Item="wlidsvc";Desc="Microsoft Account Sign-in Assistant"},
    #@{Item="*diagnosticshub*";Desc="Microsoft (R) Diagnostics Hub Standard Collector Service"},
    @{Item="lfsvc";Desc="Geolocation Service. Provides location data to apps.";Suggested="Skip (Keep) if you want any location-based features including for web browsers. Disable for privacy without location features."},
    #@{Item="fhsvc";Desc="File History Service"},
    @{Item="Fax";Desc="Fax Service. Legacy support for fax devices. Disable if not using fax hardware.";Suggested="Disable unless you use a fax machine with your PC."},
    #@{Item="embeddedmode";Desc="Embedded Mode"},
    #@{Item="MapsBroker";Desc="Downloaded Maps Manager"}, #Handled by Bloatware_MicrosoftMaps function
    #@{Item="TrkWks";Desc="Distributed Link Tracking Client"},
    #@{Item="WdiSystemHost";Desc="Diagnostic System Host"},
    #@{Item="WdiServiceHost";Desc="Diagnostic Service Host"},
    #@{Item="DPS";Desc="Diagnostic Policy Service"},
    #@{Item="diagsvc";Desc="Diagnostic Execution Service"},
    @{Item="DusmSvc";Desc="Data Usage Manager. Tracks network usage. Disable if not monitoring data usage.";Suggested="Disable unless you need to monitor data usage with your internet provider."}
) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }
#endregion

#region Main Script Logic
# Assume 'Online' if no target is specified, meaning the currentling running OS.
if (!$Target) {
    $Target = "Online"
    Write-Host "Debloat defaulting to debloating currently running OS."
}

if ($Target -eq "Online"){
    $MountDir = "$env:SystemDrive\"
    # Verify that the MountDir is a valid Windows path, if not abort.
    if (!(Test-Path "$MountDir\Windows")) {
        Stop-AbortScript -Message "Script attempted to find the running instance of Windows at $MountDir but it does not appear to be a valid path for the currently running Windows OS."
    }
} else {
    # Normalize target to a drive root (accept "D:" or "D:\")
    $t = $Target.Trim()
    if ($t -match '^[A-Za-z]:\\?$') {
        # Ensure a single trailing backslash (e.g. "D:\")
        $driveRoot = $t.Substring(0,1) + ':\'
        if (-not (Test-Path $driveRoot -PathType Container)) {
            Stop-AbortScript -Message "Drive '$driveRoot' does not exist or is not accessible."
        }
        if (-not (Test-Path (Join-Path $driveRoot 'Windows'))) {
            Stop-AbortScript -Message "The drive root '$driveRoot' does not contain a Windows installation (missing 'Windows' folder)."
        }
        $MountDir = $driveRoot
    } else {
        Stop-AbortScript -Message "Invalid target. Target must be a root drive letter (for example 'D:' or 'D:\'). Provided: '$Target'"
    }
}

$WindowsVersionInfo = Get-WindowsVersion -Target $Target
if ($null -eq $WindowsVersionInfo) {
    Stop-AbortScript -Message "Unable to determine Windows version information for target $Target."
} else { 
    $buildVersion = [int]($WindowsVersionInfo.Split('.')[2])  # Extract the build number (e.g., 26100)

    $TargetWindowsVersion = switch($buildVersion) {
        {$_ -ge 10240 -and $_ -le 19045} { "10" }
        {$_ -ge 22000} { "11+" }
        default { "Unsupported Windows version" }
    }
    Write-Host "Detected Windows Version:`n$TargetWindowsVersion [ $WindowsVersionInfo ]`n"
}

if ($TargetWindowsVersion -eq "Unsupported Windows version") {
    Stop-AbortScript -Message "The detected Windows version is not supported by this script."
} else {
    Write-Host "Proceeding with debloating for Windows build $TargetWindowsVersion."
}

Write-Host "`nGathering Appx Packages and Windows Capabilities..." -ForegroundColor White -BackgroundColor DarkGreen
Get-PackagesCapabilities

Write-Host "`nMounting Registry Hives..." -ForegroundColor White -BackgroundColor DarkGreen
Mount-RegistryHives -MountDir $MountDir

#region Removal and Change Selections
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (($sid -eq 'S-1-5-18') -or ($Target -ne "Online")) {
    Write-Header -Text "Bypass Microsoft NRO Nags Selection" -Large
    Write-Host "`n*Note: This option only works if the debloat script is run before OOBE has completed. It will do no harm and have no impact if enabled after setup.*`n" -ForegroundColor Yellow
    $BypassNROResponse = Read-PromptUser -Title "Bypass Microsoft NRO Nags" -Message "`nDo you want to bypass Microsoft nags to set up a Microsoft account and Privacy questions during the Out-Of-Box Experience?`nThis will also allow you to create a Local User Account." -SuggestedAction "Bypass, for privacy and control of your PC." -DefaultResponse "Skip" -ValidResponses @("Bypass") -InfoText "Selecting 'Bypass' will set registry values to bypass Microsoft nags during OOBE. Selecting 'Skip' will leave them enabled."
    if ($BypassNROResponse -eq "Bypass") {
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\OOBE" -Name "BypassNRO" -PropertyType DWord -Value 1
        Set-RegistryValue -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisablePrivacyExperience" -PropertyType DWord -Value 1
        Write-Host "`nMicrosoft NRO Nags Bypassed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Write-Header -Text "Appx Bloatware Removal Selection" -Large


# Build list of possible Appx Bloatware to remove from user selection
Write-Header -Text "Possible Bloatware Apps"
# Make selection by checking list of bloat against installed packages
Write-Host "`nBuilding list of detected bloatware...`n" -ForegroundColor Magenta
Start-Sleep -Seconds 2
$BloatSelectionList = @()
foreach ($Bloat in $Script:BloatlistAppxPossible) {
    if (($Script:AppxPackages | Where-Object Name -like ($Bloat.Item)) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like ($Bloat.Item))) {
        Write-Output "Detected: $($Bloat.Item)"
        $BloatSelectionList += $Bloat
    }
}
if ($BloatSelectionList.Count -gt 0) {
    Write-Header -Text "The following questions will prompt you to select which Appx apps you want to remove.`nThis list contains apps you may want to keep so review each one carefully." -Notice
    # Collect user selections for possible bloatware and add to removal list
    $NewRemovalItems = Get-BloatRemovalSelection -SelectionList $BloatSelectionList
    if ($NewRemovalItems) {$Script:Appx_RemovalList += $NewRemovalItems}
    # Clear temporary variable
    $NewRemovalItems = $null
} else {
    Write-Host "`nNo bloat items detected for this section. Continuing...`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}


# Build list of likely Appx Bloatware to remove from user selection
Write-Header -Text "Junky Bloatware Apps"
# Make selection by checking list of bloat against installed packages
Write-Host "`nBuilding list of detected bloatware...`n" -ForegroundColor Magenta
Start-Sleep -Seconds 2
$BloatSelectionList = @()
foreach ($Bloat in $Script:BloatlistAppxJunk) {
    if (($Script:AppxPackages | Where-Object Name -like ($Bloat.Item)) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like ($Bloat.Item))) {
        Write-Output "Detected: $($Bloat.Item)"
        $BloatSelectionList += $Bloat
    }
}
if ($BloatSelectionList.Count -gt 0) {
    Write-Header -Text "The following questions will prompt you to select which Appx apps you want to remove.`nThis list contains apps that are generally considered junk and safe to remove for most users." -Notice
    # Collect user selections for possible bloatware and add to removal list
    $NewRemovalItems = Get-BloatRemovalSelection -SelectionList $BloatSelectionList
    if ($NewRemovalItems) {$Script:Appx_RemovalList += $NewRemovalItems}
    # Clear temporary variable
    $NewRemovalItems = $null
} else {
    Write-Host "`nNo bloat items detected for this section. Continuing...`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Check if user wants to remove Sponsored Appx Bloatware and add to list if so
Write-Header -Text "Sponsored Bloatware Apps"
Write-Header -Text "`The following section will offer to remove ALL Sponsored apps in one go.`nGenerally you will want to answer 'Remove' and if you want any of the apps just later install it from the Windows Store." -Notice
Get-AppxSponsoredRemovalSelection

# Proceed to remove selected Appx Bloatware
Write-Header -Text "Removing Selected Appx Bloatware"
Start-Sleep -Seconds 3
if ($Script:Appx_RemovalList.Count -gt 0) {
    Remove-AppxBloat -RemovalList $Script:Appx_RemovalList
} else {
    Write-Host "`nNo Appx Packages selected for removal." -ForegroundColor Green
}

# Capability Bloatware Removal Selection
Write-Header -Text "Windows Capability Bloatware Removal Selection" -Large
# Make selection by checking list of bloat against installed capabilities
Write-Host "`nBuilding list of detected bloatware...`n" -ForegroundColor Magenta
Start-Sleep -Seconds 2
$BloatSelectionList = @()
foreach ($Bloat in $Script:BloatlistWindowsCapabilities) {
    if ($Script:WindowsCapabilities | Where-Object {$_.Name -like "$($Bloat.Item)*"}) {
        Write-Output "Detected: $($Bloat.Item)"
        $BloatSelectionList += $Bloat
    }
}
if ($BloatSelectionList.Count -gt 0) {
    Write-Header -Text "The following questions will prompt you to select which Windows Capabilities you want to remove.`nReview each one carefully." -Notice
    # Collect user selections for Windows Capabilities and add to removal list
    $NewRemovalItems = Get-BloatRemovalSelection -SelectionList $BloatSelectionList
    if ($NewRemovalItems) {$Script:WindowsCapabilities_RemovalList += $NewRemovalItems}
    # Clear temporary variable
    $NewRemovalItems = $null
} else {
    Write-Host "`nNo bloat items detected for this section. Continuing...`n" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Remove Capability Bloatware
Write-Header -Text "Removing Selected Windows Capability Bloatware" -Large
Start-Sleep -Seconds 3
if ($Script:WindowsCapabilities_RemovalList.Count -gt 0) {
    Remove-BloatWindowsCapability -RemovalList $Script:WindowsCapabilities_RemovalList
} else {
    Write-Host "`nNo Windows Capabilities selected for removal." -ForegroundColor Green
}

# Windows Service Bloatware Removal Selection
Write-Header -Text "Windows Service Bloatware Removal Selection" -Large
# Make selection by checking list of bloat against installed capabilities
Write-Host "`nBuilding list of detected bloatware...`n" -ForegroundColor Magenta
Start-Sleep -Seconds 2
$Script:Services_RemovalList = Get-BloatServicesSelection -SelectionList $Script:BloatlistServices


# Remove Windows Service Bloatware
Write-Header -Text "Removing Selected Windows Service Bloatware" -Large
Start-Sleep -Seconds 3
if ($Script:Services_RemovalList.Count -gt 0) {
    Write-Host "Removing Selected Windows Services..." -ForegroundColor Green
    Remove-BloatServices -RemovalList $Script:Services_RemovalList
} else {
    Write-Host "`nNo Windows Services selected for removal." -ForegroundColor Green
}

#region Bloatware Removal Selections
Write-Header -Text "Bloatware Removal Selections" -Large
Write-Header -Text "The following section will prompt for your choices regarding various options please read and select carefully." -Notice
Start-Sleep -Seconds 3

# Xbox Removal
Bloatware_Xbox

# Microsoft Teams Removal
Bloatware_Teams

# Cortana & Copilot Removal
Bloatware_CortanaCopilot

# CoPilot Recall Removal
Bloatware_CopilotRecall

# Microsoft Edge Removal
Bloatware_MicrosoftEdge
if ($Script:EdgeRemoveResponse -eq "Remove") {
    # Refresh Appx package and capabilities lists after Edge removal
    Write-Host "`nRemoveing Edge as the default PDF handler..." -ForegroundColor Green
    Tweak_BlockEdgePDF -Auto
}

# Start Menu and Taskbar Cleanup
Bloatware_StartMenuTaskbar

# Disable Online Windows Search
Bloatware_BingStartMenuSearch

# Block Start Menu Suggested Apps
Bloatware_StartMenuSuggestedApps

# Block Start Menu Suggested Websites
Bloatware_StartMenuSuggestedSites

# Disable Widgets
Bloatware_Widgets

# Block Bloatware Reinstallation
Bloatware_BlockBloatReinstall

# Block Ads in File Explorer
Bloatware_AdsInExplorer

# Remove OneDrive
Bloatware_OneDrive

# Disable Microsoft Maps
Bloatware_MicrosoftMaps

# Disable Remote Desktop Services
Bloatware_RemoteDesktopServices

# Disable Smart Card Services
Bloatware_SmartCardServices
#endregion

#region Privacy Settings
Write-Header -Text "Privacy Settings" -Large
Write-Header -Text "The following section will prompt for your choices regarding various options please read and select carefully." -Notice
Start-Sleep -Seconds 3

# Block Telemetry and Data Collection
Privacy_BlockTelemetry

# Block Storing User Account Activity
Privacy_BlockUserAccountActivity

# Block Apps accessing user account information
Privacy_BlockAppUserAccountAccess

# Block Apps accessing diagnostic information
Privacy_BlockAppDiagnosticAccess

# Disable Windows Error Reporting
Privacy_DisableErrorReporting

# Disable Text Message Cloud Backup
Privacy_DisableTextMessageCloudBackup

# Disable Cloud Clipboard
Privacy_DisableClipboardCloudSync

# Disable Clipboard History
Privacy_DisableClipboardHistory

# Disable Windows Spotlight
Privacy_DisableWindowsSpotlight

# Disable Camera At Logon
Privacy_DisableCameraAtLogon




#endregion

#region System Tweaks
Write-Header -Text "System Tweaks" -Large
Write-Header -Text "The following section will prompt for your choices regarding various system tweaks please read and select carefully." -Notice

# Disable Fast Startup
Tweak_DisableFastStartup

# Block Automatic Bitlocker Encryption
Tweak_BlockAutomaticBitlocker

# Align Taskbar Icons to Left
Tweak_AlignTaskbarIconsLeft

# Hide Recent Searches in Taskbar on Hover
Tweak_HideTaskbarRecentSearchHover

# Taskbar Search Bar to Icon
Tweak_TaskbarSearchBarToIcon

# ClassicContextMenu
Tweak_ClassicContextMenu

# Disable Clipboard Suggestions
Tweak_DisableClipboardSuggestions

# Start Menu More Pinned Items
Tweak_StartMenuMorePinnedItems

# Enable Long Folder Paths
Tweak_EnableLongPathSupport

# Disable Last Access Time
Tweak_DisableLastAccessTime

# Disable Edge First Run Experience
if ($Script:EdgeRemoveResponse -ne "Remove") {
    Tweak_DisableEdgeFirstRunExperience
}

# Disable Edge as Default PDF Handler
if ($Script:EdgeRemoveResponse -ne "Remove") {
    Tweak_BlockEdgePDF
}

# Enable Verbose BSOD
Tweak_EnableVerboseBSOD

# Enable Verbose Startup and Shutdown
Tweak_EnableVerboseStartupShutdown

# Disable Accessibility Shortcuts
Write-Header -Text "Disable Accessibility Shortcuts"
$DisableAccessibilityShortcutsResponse = Read-PromptUser -Title "Accessibility Shortcuts" -Message "`nDo you want to disable the accessibility shortcuts for Sticky Keys, Toggle Keys, and Filter Keys?`nAnswer Yes to disable all, Choose to choose individually, or No to leave all three intact." -SuggestedAction "Disable, if no one with accessibility needs uses this PC." -DefaultResponse "Skip" -ValidResponses @("Disable", "Choose") -InfoText "Selecting 'Disable' will disable the keyboard shortcuts for all three tools. Selecting 'Choose' will prompt you for each item separately. Selecting 'Skip' will not change any of these settings."
if ($DisableAccessibilityShortcutsResponse -eq "Disable") {
    Write-Host "Removing Accessibility Shortcuts..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    # Disable all three accessibility shortcuts
    Tweak_DisableStickyKeysShortcut -Auto
    Tweak_DisableFilterKeysShortcut -Auto
    Tweak_DisableToggleKeysShortcut -Auto
} elseif ($DisableAccessibilityShortcutsResponse -eq "Choose") {
    # Disable Sticky Keys Shortcut
    Tweak_DisableStickyKeysShortcut
    # Disable Filter Keys Shortcut
    Tweak_DisableFilterKeysShortcut
    #Disable Toggle Keys Shortcut
    Tweak_DisableToggleKeysShortcut
}

# Show or Hide System Tray
Tweak_ShowHideSystemTrayIcons

# Show or Hide File Extensions
Tweak_ShowHideFileExtensions

# Show or Hide Detailed File Operations
Tweak_ShowHideDetailedFileOperations

# Select Default Explorer Location
Tweak_SelectDefaultExplorerLocation


#endregion

#endregion

#endregion

#region Cleanup
Write-Host "`n`n$border" -ForegroundColor Cyan
Write-Host "Cleaning Up and Unmounting Registry Hives" -ForegroundColor Green
Write-Host $border -ForegroundColor Cyan

Dismount-RegistryHives -MountDir $MountDir
#endregion