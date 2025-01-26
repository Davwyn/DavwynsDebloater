[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)][ValidatePattern('^(Online|.:\\)$')][String]$Target,
        [Parameter(Mandatory=$false)][Bool]$Debloat,
        [Parameter(Mandatory=$false)][Bool]$InstallSoftware
    )
$ScriptVersion = 1.1.0
$ScriptVersionDate = "Jan 26, 2025"
Set-ExecutionPolicy Bypass -Scope Process
Write-Host "Script Version: $ScriptVersion"
Write-Host "Script Modified Date: $ScriptVersionDate"

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

Add-Type -AssemblyName PresentationCore, PresentationFramework

$ErrorActionPreference = 'Continue'
$LogFolder = $PSScriptRoot

If (!(Test-Path $LogFolder)) {
    Write-Host "The folder '$LogFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    New-Item -Path "$LogFolder" -ItemType Directory
    Write-Host "The folder $LogFolder was successfully created."
}

Start-Transcript -OutputDirectory $LogFolder

New-Variable -Name MountDir -Scope Script
New-Variable -Name UserHives -Scope Script
New-Variable -Name UserRegs -Scope Script
New-Variable -Name AppxPackages -Scope Script
New-Variable -Name AppxProvisionedPackages -Scope Script
New-Variable -Name Appx_RemovalList -Scope Script
New-Variable -Name System_Packages -Scope Script
New-Variable -Name System_Packages_RemovalList -Scope Script
New-Variable -Name Services_RemovalList -Scope Script
New-Variable -Name Remove_Xbox -Scope Script
New-Variable -Name Remove_Teams -Scope Script
New-Variable -Name Remove_Cortana -Scope Script
New-Variable -Name Disable_EdgePDF -Scope Script

$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(300, 5000)
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"

#Special thanks to testers:
#Skybox, Omega

if (!$Target) {$Target = "Online"}

if ($Target -eq "Online"){
    $MountDir = "$env:SystemDrive\"
} elseif (($Target -ne "Online") -and (Test-Path $Target -PathType Container) -and (Test-Path "$Target`\Windows")) {
    $MountDir = $Target
} else {
    Write-Error "The Path provided $target does not appear to be a valid image path for an offline Windows image."
}

if ($Target -ne "Online") {
    
    $Title = "Windows Version"
    $Info = "Is the image you are changing Windows 10 or 11?"
    $options = [System.Management.Automation.Host.ChoiceDescription[]] @("10", "11")
    $opt = $host.UI.PromptForChoice($Title , $Info , $Options, "")
    switch($opt)
    {
    0 {$WinVer = 10}
    1 {$WinVer = 11}
    }
} elseif ($Target -eq "Online") {
    $WindowsProductName = (Get-CIMInstance -Class Win32_OperatingSystem).Caption
    if ($WindowsProductName -like "*Windows 10*") {
        $WinVer = 10
        Write-Host "Detected OS to be Windows 10"
    } elseif ($WindowsProductName -like "*Windows 11*") {
        $WinVer = 11
        Write-Host "Detected OS to be Windows 11"
    } else {
        Write-Host "Sorry, this Debloat script was designed only for Windows 10 and Windows 11 in mind. It could potentially do damage to other Windows versions."
        Write-Error "Operating system must be Windows 10 or 11" -ErrorAction Stop
        Pause
        Exit 1
    }
}

$Appx_RemovalList = @()
$System_Packages_RemovalList = @()
$Services_RemovalList = @()
$UserHives = @()
$UserRegs = @()



Function Gather_Packages {
    #Get Appx Packages, Appx Provisioned Packages and System Packages
    Write-Host "`nGetting Appx Packages, AppxProvisionedPackages, and System Packages..." -ForegroundColor White -BackgroundColor DarkGreen
    if ($Target -eq "Online") {
        $Script:AppxPackages = Get-AppxPackage -AllUsers
        $Script:AppxProvisionedPackages = Get-AppxProvisionedPackage -Online
        $Script:System_Packages = Get-WindowsCapability -Online | Where-Object {($_.State -notin @('NotPresent', 'Removed'))}
    } else {
        $MountDir = $Target
        New-Item -Path "$MountDir`\Scratch" -ItemType Directory -Force
        $Script:AppxProvisionedPackages = Get-AppxProvisionedPackage -Path $MountDir
        $Script:System_Packages = Get-WindowsCapability -Path $Target | Where-Object {($_.State -notin @('NotPresent', 'Removed'))}
    }
}

Function Bloatware_Appx {
    Write-Host "`n--Appx Packages--" -ForegroundColor White -BackgroundColor DarkCyan

    $title    = "Remove Appx App?"
    $choices  = "&Yes", "&No"

    $Bloatware = @(
        @{Item="MicrosoftWindows.Client.WebExperience";Desc="The widgits found on the left side of the taskbar.`nEven if you hide the widgets in Taskbar settings they stay loaded and load up several browser tabs worth of constent 24/7.`nHighly suggested to remove this for a huge performance boost and for privacy."},
        @{Item="Microsoft.MicrosoftSolitaireCollection";Desc="The Windows Solitare game collection.`nThis is not the classic Solitaire games but rather an online service version.`nYou can reinstall this from the store if you want it later."},
        @{Item="Microsoft.3DBuilder";Desc="Allows users to create and print 3D objects"},
        @{Item="Microsoft.Microsoft3DViewer";Desc="App to view 3D Model files such as OBJ files."},
        @{Item="Microsoft.Print3D";Desc="A modern version of the paint program that supports 3D objects."},
        @{Item="*Microsoft.BingWeather*";Desc="A basic weather app.`nWhile installed it will constantly give Microsoft your location."},
        @{Item="Microsoft.RemoteDesktop";Desc="A simple remote desktop app to connect to other computers."},
        @{Item="Microsoft.GetHelp";Desc="The basic Windows Help app that contains general how to use Windows information.`nIf you don't need it you can remove it."},
        @{Item="Microsoft.WindowsAlarms";Desc="The Clock and Alarm app.`nHas a basic clock, stopwatch, and timer feature."},
        @{Item="Microsoft.WindowsCamera";Desc="A basic webcam camera app to see what your webcam sees and take basic pictures."},
        @{Item="Microsoft.YourPhone";Desc="App to connect to your cell phone if you install the companion app.`nAllows you to view test messages and other things from your phone.`nWhile using this Microsoft might spy on your text messages and content."},
        @{Item="Microsoft.MinecraftUWP";Desc="The Windows 10 edition aka Bedrock edition of Minecraft.`nA Minecraft license is required to use it.`nYou can reinstall this from the windows store if you want it later."},
        @{Item="Microsoft.OutlookForWindows";Desc="A basic version of Microsoft Outlook desktop app."}
    ) | % { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }
    
    Write-Host "`nThe following Appx Apps are sometimes wanted. Only answer Yes if you wish to remove them." -ForegroundColor White -BackgroundColor DarkCyan

    foreach ($Bloat in $Bloatware) {
        if (($Script:AppxPackages | Where-Object Name -like $($Bloat.Item)) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $($Bloat.Item))) {
            $question = "Remove Appx package: $($Bloat.Item)`?`nInfo: $($Bloat.Desc)"
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {$Script:Appx_RemovalList += $($Bloat.Item)}
        }
    }

    #Phase 2 Common unnecessary Windows AppX Apps
    
    $Bloatware = @(
        #Unnecessary Windows AppX Apps
        @{Item="Microsoft.Advertising.Xaml";Desc="Includes advertising components for windows apps."},
        @{Item="Microsoft.Appconnector";Desc="Enables apps to connect and share data across different windows devices."},
        @{Item="Microsoft.BingFinance";Desc="Provides users with financial news, stock market updates, and personal finance tools."},
        @{Item="Microsoft.BingNews";Desc="Provides users with news updates from various sources."},
        @{Item="Microsoft.BingSports";Desc="Provides users with the latest sports news and updates."},
        @{Item="Microsoft.BingTranslator";Desc="Enables users to translate text, speech, and images in multiple languages."},
        @{Item="Microsoft.BingFoodAndDrink";Desc="Provides users with recipes, cooking tips, and food-related news."},
        @{Item="Microsoft.BingHealthAndFitness";Desc="Provides users with health and fitness-related content, including workout plans and nutrition advice."},
        @{Item="Microsoft.BingTravel";Desc="Provides users with travel-related content, including flight and hotel bookings, travel guides, and recommendations."},
        @{Item="Microsoft.WindowsReadingList";Desc="Enables users to save articles, videos, and other content for later reading."},
        @{Item="Microsoft.FreshPaint";Desc="Is a digital painting and drawing app."},
        @{Item="Microsoft.Getstarted";Desc="Provides users with tutorials and guides for using windows features and apps."},
        @{Item="Microsoft.MicrosoftOfficeHub";Desc="Provides access to microsoft office apps and features."},
        @{Item="Microsoft.MicrosoftPowerBIForWindows";Desc="Provides access to data analytics and business intelligence tools."},
        @{Item="Microsoft.NetworkSpeedTest";Desc="Enables users to test the speed of their internet connection."},
        @{Item="Microsoft.News";Desc="Provides users with news updates and articles from various sources."},
        @{Item="Microsoft.Office.Lens";Desc="Is a scanner app that enables users to scan documents and save them as pdfs or images."},
        @{Item="Microsoft.MicrosoftStickyNotes";Desc="Enables users to create and manage sticky notes on their windows desktop."},
        @{Item="Microsoft.Office.OneNote";Desc="Is a note-taking app that enables users to capture and organize notes, drawings, and other content."},
        @{Item="Microsoft.Office.Sway";Desc="Is a presentation app that enables users to create and share interactive web-based presentations."},
        @{Item="Microsoft.OneConnect";Desc="Is a messaging app that enables users to connect with their friends and family across different social networks and messaging apps."},
        @{Item="Microsoft.People";Desc="Is a contact management app that enables users to manage their contacts and connect with them across different services."},
        @{Item="Microsoft.SkypeApp";Desc="Is a messaging and calling app that enables users to connect with others through voice, video, and chat."},
        @{Item="Microsoft.Office.Todo.List";Desc="Is a to-do list and task management app."},
        @{Item="Microsoft.Whiteboard";Desc="Is a digital whiteboard app that enables users to collaborate and draw together in real-time."},
        @{Item="Microsoft.WindowsFeedbackHub";Desc="Enables users to provide feedback and report issues with windows."},
        @{Item="Microsoft.WindowsMaps";Desc="Provides users with maps, directions, and location-based services."},
        @{Item="Microsoft.WindowsPhone";Desc="Enables users to connect and manage their windows phone from their pc."},
        @{Item="Microsoft.WindowsSoundRecorder";Desc="A basic voice recording app."},
        @{Item="Microsoft.ZuneMusic";Desc="Provides access to music and streaming services."},
        @{Item="Microsoft.ZuneVideo";Desc="Provides access to movies and tv shows."},
        @{Item="Microsoft.CommsPhone";Desc="Enables users to make and receive phone calls from their windows pc."},
        @{Item="Microsoft.Wallet";Desc="Is a digital wallet app that enables users to store and manage their payment cards and passes."},
        @{Item="Microsoft.MixedReality.Portal";Desc="Is a mixed reality headset software app for VR."},
        @{Item="MicrosoftCorporationII.MicrosoftFamily";Desc="Provides parental controls and family management features for Microsoft accounts."},
        @{Item="Microsoft.BingSearch";Desc="Description"}
    ) | % { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }


    Write-Host "`nThe following Appx Apps are usually not wanted." -ForegroundColor White -BackgroundColor DarkCyan

    foreach ($Bloat in $Bloatware) {
        if (($Script:AppxPackages | Where-Object Name -like $($Bloat.Item)) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $($Bloat.Item))) {
            $question = "Remove Appx package: $($Bloat.Item)`?`nInfo: $($Bloat.Desc)"
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {$Script:Appx_RemovalList += $($Bloat.Item)}
        }
    }

    $Sponsored = @(
        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
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

    Write-Host "`nThe apps listed below are all sponsored apps Windows pushed onto your PC.`nYou can always reinstall these from the Windows Store if you want." -ForegroundColor White -BackgroundColor DarkCyan

    $SponsoredInstalled = @()
    foreach ($Bloat in $Sponsored) {
        if (($Script:AppxPackages | Where-Object Name -like $Bloat) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $Bloat)) {
            Write-Output $Bloat
            $SponsoredInstalled += $Bloat
        }
    }
    if ($SponsoredInstalled) {
        Write-Host ""
        $title    = "Remove Sponsored Appx Apps?"
        $question = "Remove Appx ALL these sponsored apps?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {$Script:Appx_RemovalList += $SponsoredInstalled}
    } else {
        Write-Host "`nIt seems you have no sponsored apps installed. Yay!" -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Function Remove_Appx {
    Write-Host "`nUninstalling Appx bloatware..." -ForegroundColor White -BackgroundColor DarkGreen

    if ($Target -eq "Online") {
        foreach ($RemoveBloat in $Script:Appx_RemovalList) {
            Write-Host "Trying to remove $RemoveBloat" -ForegroundColor White -BackgroundColor DarkBlue
            try {
                $Script:AppxProvisionedPackages | Where-Object DisplayName -like $RemoveBloat | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction Stop -Verbose
            } Catch {
                Write-Host "Error: Failed to remove Provisioning Package $RemoveBloat Error: $_"
            }
            Write-Host "Trying to remove $RemoveBloat Appx Package"
            Try {
                $Script:AppxPackages | Where-Object Name -like $RemoveBloat | Remove-AppxPackage -AllUsers -ErrorAction Stop -Verbose
            } Catch {
                Write-Host "Error: Failed to remove Appx Package $RemoveBloat Error: $_"
            }
        }
    } else {
        foreach ($RemoveBloat in $Script:Appx_RemovalList) {
            Write-Host "Trying to remove $RemoveBloat" -ForegroundColor White -BackgroundColor DarkBlue
            $Script:AppxProvisionedPackages | Where-Object DisplayName -like $RemoveBloat | Remove-AppxProvisionedPackage -Path $MountDir -ErrorAction Continue -Verbose
        }
   }
   Write-Host "`nAppx Bloatware removed." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Bloatware_SysPackages {
    Write-Host "`n--System Packages--" -ForegroundColor White -BackgroundColor DarkCyan

    $title    = "Remove System Package?"
    $choices  = "&Yes", "&No"

    $BloatPackages = @(
        @{Item="Windows.Kernel.LA57";Desc="Unknown what LA57 does"},
	    @{Item="Browser.InternetExplorer";Desc="Old Internet Explorer. Unless you really need it remove it for security sake!"},
        @{Item="Media.WindowsMediaPlayer";Desc="The old fashioned Windows Media player from Windows XP days. Suggested to remove this and use VideoLan VLC Player instead."},
        @{Item="Microsoft.Wallpapers.Extended";Desc="Windows Wallpaper pack. Doesn't do much but save some disk space if you remove it."}
        @{Item="Hello.Face";Desc="Windows Face Unlock feature. If you don't have a Windows Hello compatible camera or even want to use Windows Hello you can remove this."},
        @{Item="Language.Handwriting";Desc="Touch-based handwriting features. If you don't use tablet features you can remove this."},
        @{Item="Language.OCR";Desc="Optical Character Recognition. Used to scan image of text and turn it into editable text.`nDon't remove this if you use text scanning features like PowerToys screen grabber for text."},
        @{Item="Language.Speech";Desc="Voice to Text functionality such as dictation software. You can remove it if you don't plan on using it."},
        @{Item="Language.TextToSpeech";Desc="TTS or Text-To-Speech. Voices such as Microsoft SAM that reads text out loud to you. Remove it if you have no use for it."},
        #@{Item="MathRecognizer";Desc="Feature to input complex mathimaical symbols into your computer. Keep this if you need to enter in math formulas."},
        @{Item="App.StepsRecorder";Desc="An old troubleshooting tool that takes screenshots with every click of the mouse.`nThis old program only saves in an unsupported Internet Explorer format."}        
    ) | % { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }


    Write-Host "`nThe following are Windows system packages you can optionally remove.`nThis cannot be undone to choose carefully." -ForegroundColor White -BackgroundColor DarkCyan 
    
    foreach ($BloatPackage in $BloatPackages) {
        $PackageArray = $Script:System_Packages | Where-Object {$_.Name -like "$($BloatPackage.Item)*"}
        if ($PackageArray) {
            $question = "Remove system package $($BloatPackage.Item)`?`nInfo: $($BloatPackage.Desc)"
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                foreach ($PackageArrayItem in $PackageArray) {
                    $Script:System_Packages_RemovalList += $PackageArrayItem.Name
                    Write-Output "Package marked to remove: $($PackageArrayItem.Name)"
                }
            }
        }
    }
}

Function Remove_SysPackages {
    Write-Host "`nRemoving Unwanted System Packages..." -ForegroundColor White -BackgroundColor DarkGreen

    foreach ($Package in $Script:System_Packages_RemovalList){
        Write-Host "Removing $Package..." -ForegroundColor White -BackgroundColor DarkBlue
        if ($Target -eq "Online") {
            Remove-WindowsCapability -Online -Name $Package
            #dism /Online /Remove-Package /NoRestart /PackageName:$Package
        } else {
            Remove-WindowsCapability -Path $target -Name $Package
            #dism /Image:$Target /Remove-Package /NoRestart /PackageName:$Package /ScratchDir:"$MountDir`\Scratch"
        }
    }
    Write-Host "`nUnwanted packages removed." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Bloatware_Xbox {
    Write-Host "`n--Xbox App and Components--" -ForegroundColor White -BackgroundColor DarkCyan
    
    $title    = "Remove Xbox?"
    $choices  = "&Yes", "&No"

    #Xbox Appx list
    $XboxAppx = @(
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.GamingServices"
        "Microsoft.GamingApp"
        )


    $XboxAppxInstalled = @()
    foreach ($Bloat in $XboxAppx) {
        if (($Script:AppxPackages | Where-Object Name -like $Bloat) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $Bloat)) {
            $XboxAppxInstalled += $Bloat
        }
    }

    if ($XboxAppxInstalled) {
        Write-Host ""
        $question = "Do you want to completely remove Xbox features from the computer?`nThis cannot be undone."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            $Script:Appx_RemovalList += $XboxAppxInstalled
            $Script:Remove_Xbox = $true
        }
    } else {
        Write-Host "`nIt seems the Xbox features are already removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Function Remove_Xbox {
    Write-Host "Removing Xbox Components..."  -ForegroundColor White -BackgroundColor DarkGreen

    $XboxServices = @(
    "*xbox*" # Xbox Services
    "*Xbl*" # Xbox Services
    "XboxNetApiSvc" # Xbox Services
    )
    foreach ($Service in $XboxServices) {
	    if ($Target -eq "Online") {
            Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -Verbose
                if($Service.Status -match "Run"){
                    Write-Host "Trying to disable $($Service.DisplayName)" -ForegroundColor White -BackgroundColor DarkBlue
                    Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                }
        } else {
            $registryPath = "Reg_HKLM_SYSTEM:\ControlSet001\Services\$Service"
            Write-Output "Trying to disable $Service"
            if (Test-Path $registryPath) {New-ItemProperty $registryPath Start -Value 4 -PropertyType Dword -Force}
        }
    }


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


    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse
    }

    #Disable Game DVR
    Write-Host "Disabling Game DVR" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\GameDVR")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\GameDVR" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0  -PropertyType Dword -Force
	if(!(Test-Path "Reg_HKCU:\System\GameConfigStore")){ New-Item -Path "Reg_HKCU:\System\GameConfigStore" -Force -ErrorAction SilentlyContinue}
	if(!(Test-Path "Reg_HKDefaultUser:\System\GameConfigStore")){ New-Item -Path "Reg_HKDefaultUser:\System\GameConfigStore" -Force -ErrorAction SilentlyContinue}
	New-ItemProperty -Path "Reg_HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWord -Force
	New-ItemProperty -Path "Reg_HKDefaultUser:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWord -Force
    if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord -Force
    if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\GameDVR")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord -Force

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

Function Bloatware_Teams {
    Write-Host "`n--Microsoft Teams Chat--" -ForegroundColor White -BackgroundColor DarkCyan

    $title    = "Remove Teams App?"
    $choices  = "&Yes", "&No"

    #Teams Appx list
    $TeamsAppx = @(
        "Microsoft.Messaging"
        "MicrosoftTeams"
        "MSTeams"
		"microsoft.windowscommunicationsapps"
        )


    $TeamsAppxInstalled = @()
    foreach ($Bloat in $TeamsAppx) {
        if (($Script:AppxPackages | Where-Object Name -like $Bloat) -or ($Script:AppxProvisionedPackages | Where-Object DisplayName -like $Bloat)) {
            $TeamsAppxInstalled += $Bloat
        }
    }
    if ($TeamsAppxInstalled) {
        Write-Host ""
        $question = "Do you want to completely remove Teams and Windows Chat features from the computer?`nNote: This removes Non-M365 version of teams only.`nThis cannot be undone."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            $Script:Appx_RemovalList += $TeamsAppxInstalled
            $Script:Remove_Teams = $true
        }
    } else {
        Write-Host "`nIt seems the Teams Chat features are already removed." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Function Remove_Teams {
    Write-Host "`nRemoving non-M365 Microsoft Teams/Chat..."  -ForegroundColor White -BackgroundColor DarkGreen

    Write-Host "Setting Registry settings to block Teams/Chat from reappearing..." -ForegroundColor White -BackgroundColor DarkBlue
	if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Chat")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Chat" -force -ea SilentlyContinue};
	New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Chat" -Name "ChatIcon" -Value 3 -PropertyType DWord -Force -ea SilentlyContinue;

    if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

    if (Test-path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications") {
        if ($Target -eq "Online") {
            Take-Ownership -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications" -User "BUILTIN\Administrators" -Verbose
        }
        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications")) {  New-Item "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Communications" -Name "ConfigureChatAutoInstall" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    }

    Write-Host "`nTeams/Chat removed." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Bloatware_Cortana {
    Write-Host "`n--Windows Cortana and Online Start Menu Search--" -ForegroundColor White -BackgroundColor DarkCyan
    
    $title    = "Remove Cortana?"
    $choices  = "&Yes", "&No"
    
    Write-Host ""
    $question = "Do you want to remove Cortana search and virtual assistant if it's on your system?`nThis will eliminate a lot of ads and unwanted bing searches."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        $Script:Appx_RemovalList += "*Microsoft.549981C3F5F10*"
        $Script:Remove_Cortana = $true
    }
}

Function Remove_Cortana {
	Write-Host "`nDisabling Cortana and Online Start Menu Search..." -ForegroundColor White -BackgroundColor DarkGreen	

    Write-Host "Disabling Bing Search and Cortana in Start Menu..." -ForegroundColor White -BackgroundColor DarkBlue
    If (!(Test-Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search")) {New-Item -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null}
	New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType Dword -Force
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword -Force

	If (!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search")) {New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType Dword -Force
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword -Force

    If (!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search")) {New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -PropertyType Dword -Force

	#Write-Host "Stopping and disabling Windows Search indexing service..." -ForegroundColor White -BackgroundColor DarkBlue
    #Stop-Service "WSearch" -WarningAction SilentlyContinue
    #Set-Service "WSearch" -StartupType Disabled

    
    If (!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search")) {New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -PropertyType DWord -Force

    New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

    #Remove Cortana Consent
    If (!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search")) {New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword -Force

    If (!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Windows Search")) {New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Windows Search" -Name "CortanaConsent" -Value 0 -PropertyType Dword -Force

    #Disable Extension of Windows Search with Bing
    If (!(Test-Path "Reg_HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {New-Item -Path "Reg_HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -PropertyType Dword -Force

    If (!(Test-Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\Explorer")) {New-Item -Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -PropertyType Dword -Force


    Write-Host "`nCortana disabled." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Bloatware_Services {
    Write-Host "`n--Windows Services--" -ForegroundColor White -BackgroundColor DarkCyan
    
    $title    = "Disable Service?"
    $choices  = "&Yes", "&No"

    $Services = @(
        @{Item="WSearch";Desc="Windows Search. Needed to find files in the Start Menu and File Explorer. Disable only if you have a search alternative."},
        @{Item="icssvc";Desc="Mobile Hotspot"},
        @{Item="MixedRealityOpenXRSvc";Desc="Deprecated Mixed Reality VR system."},
        @{Item="WMPNetworkSvc";Desc="Windows Media Player Sharing"},
        @{Item="wisvc";Desc="Insider Program"},
        @{Item="WerSvc";Desc="Error Reporting"},
        @{Item="WalletService";Desc="Wallet Service"},
        @{Item="SysMain";Desc="SuperFetch - Safe to disable if you only use SSD/M.2 Disks. No HDD drives."},
        @{Item="svsvc";Desc="Spot Verifier"},
        @{Item="SCPolicySvc";Desc="Smart Card Removal Policy"},
        @{Item="ScDeviceEnum";Desc="Smart Card Device Enumeration Service"},
        @{Item="SCardSvr";Desc="Smart Card"},
        @{Item="RetailDemo";Desc="Retail Demo Service"},
        @{Item="UmRdpService";Desc="Remote Desktop Services UserMode Port Redirector"},
        @{Item="TermService";Desc="Remote Desktop Services"},
        @{Item="SessionEnv";Desc="Remote Desktop Configuration"},
        @{Item="RasMan";Desc="Remote Access Connection Manager"},
        @{Item="RasAuto";Desc="Remote Access Auto Connection Manager"},
        #@{Item="TroubleshootingSvc";Desc="Recommended Troubleshooting Service"},
        #@{Item="wercplsupport";Desc="Problem Reports Control Panel Support"},
        #@{Item="PrintNotify";Desc="Printer Extensions and Notifications"},
        @{Item="PhoneSvc";Desc="Phone Service"},
        @{Item="SEMgrSvc";Desc="Payments and NFC/SE Manager"},
        @{Item="WpcMonSvc";Desc="Parental Controls"},
        #@{Item="CscService";Desc="Offline Files"},
        #@{Item="InstallService";Desc="Microsoft Store Install Service"},
        @{Item="SmsRouter";Desc="Microsoft Windows SMS Router Service"},
        #@{Item="smphost";Desc="Microsoft Storage Spaces SMP"},
        #@{Item="NgcCtnrSvc";Desc="Microsoft Passport Container"},
        #@{Item="MsKeyboardFilter";Desc="Microsoft Keyboard Filter"},
        #@{Item="cloudidsvc";Desc="Microsoft Cloud Identity Service"},
        #@{Item="wlidsvc";Desc="Microsoft Account Sign-in Assistant"},
        #@{Item="*diagnosticshub*";Desc="Microsoft (R) Diagnostics Hub Standard Collector Service"},
        @{Item="lfsvc";Desc="Geolocation Service"},
        #@{Item="fhsvc";Desc="File History Service"},
        @{Item="Fax";Desc="Fax"},
        #@{Item="embeddedmode";Desc="Embedded Mode"},
        @{Item="MapsBroker";Desc="Downloaded Maps Manager"},
        #@{Item="TrkWks";Desc="Distributed Link Tracking Client"},
        #@{Item="WdiSystemHost";Desc="Diagnostic System Host"},
        #@{Item="WdiServiceHost";Desc="Diagnostic Service Host"},
        #@{Item="DPS";Desc="Diagnostic Policy Service"},
        #@{Item="diagsvc";Desc="Diagnostic Execution Service"},
        @{Item="DusmSvc";Desc="Keeps track of Data Usage"}
    ) | % { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

    Write-Host "`nPlease select the following Windows Services you want to disable.`nIf in doubt just answer No." -ForegroundColor White -BackgroundColor DarkCyan

    foreach ($Bloat in $Services) {
        if ($Target -eq "Online") {
            $Service = Get-Service -Name $($Bloat.Item) -ErrorAction SilentlyContinue
            if (($Service.StartType -ne "Disabled") -and ($Service.StartType -ne $null)) {
                $question = "Disable Windows Service $($Bloat.Item)`?`nInfo: $($Bloat.Desc)"
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                if ($decision -eq 0) {$Script:Services_RemovalList += $($Bloat.Item)}
            }
        } else {
            $registryPath = "Reg_HKLM_SYSTEM:\ControlSet001\Services\$($Bloat.Item)"
            if (Test-Path -Path $registryPath -ErrorAction SilentlyContinue) {            
                $Service = Get-ItemProperty -Path $registryPath
            } else {
                $Service = $null
            }
            if (($Service.Start -ne 4) -and ($Service.Start -ne $null)) {
                $question = "Disable Windows Service $($Bloat.Item)`?`nInfo: $($Bloat.Desc)"
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                if ($decision -eq 0) {$Script:Services_RemovalList += $($Bloat.Item)}
            }
        }
    }
}

Function Remove_Services {
    Write-Host "`nDisabling unwanted services..." -ForegroundColor White -BackgroundColor DarkGreen

    foreach ($Bloat in $Services_RemovalList) {
        if ($Target -eq "Online") {
            Write-Host "Trying to disable $($Service.DisplayName)" -ForegroundColor White -BackgroundColor DarkBlue
            $Service = Get-Service -Name $Bloat -ErrorAction SilentlyContinue
            if($Service.Status -match "Run") {Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue}
            $Service | Set-Service -StartupType Disabled -Verbose
        } else {
            Write-Host "Trying to disable $($Bloat.DisplayName)" -ForegroundColor White -BackgroundColor DarkBlue
            $registryPath = "Reg_HKLM_SYSTEM:\ControlSet001\Services\$Bloat"
            if (Test-Path $registryPath) {New-ItemProperty $registryPath Start -Value 4 -PropertyType Dword -Force}
        }
    }
    Write-Host "`nUnwanted Services disabled." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Debloat_BlockBloatware {

    $choices  = "&Yes", "&No"
    #Disable Windows Recall
    $title    = "Disable Windows Recall?"
    $question = "Disable Windows Recall? This is a massive potential data leak as malware can easily steal information about everything you do on your computer."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Windows Recall"
        
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\WindowsAI")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\WindowsAI" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -PropertyType Dword -Value 1 -Force

        if(!(Test-Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\WindowsAI")){ New-Item -Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\WindowsAI" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -PropertyType Dword -Value 1 -Force
        
        
    	Get-WindowsOptionalFeature -Online | Where-Object {'State' -notin @('Disabled';'DisabledWithPayloadRemoved') -and ($_.Name -like "Recall")} | Disable-WindowsOptionalFeature -Online -Remove -NoRestart -ErrorAction 'Continue'
    }
    
    #Prevents bloatware applications from returning and removes Start Menu suggestions
    Write-Host "`nAdding Registry key to prevent bloatware apps from returning..." -ForegroundColor White -BackgroundColor DarkGreen

    $registryPath = "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\CloudContent"
    $registryCurrentUser = "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
	$registryDefaultUsers = "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) {
    New-Item $registryPath
   }
    New-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 -PropertyType Dword -Force

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

    If (!(Test-Path $registryCurrentUser)) {
    New-Item $registryCurrentUser
    }
    foreach ($ContentFeature in $ContentFeatures) {
    New-ItemProperty $registryCurrentUser $ContentFeature -Value 0 -PropertyType Dword -Force
    }
    New-ItemProperty $registryCurrentUser  DisableTailoredExperiencesWithDiagnosticData -Value 1 -PropertyType Dword -Force

    If (!(Test-Path $registryDefaultUsers)) {
    New-Item $registryDefaultUsers
    }
    foreach ($ContentFeature in $ContentFeatures) {
    New-ItemProperty $registryDefaultUsers $ContentFeature -Value 0 -PropertyType Dword -Force
    }
    New-ItemProperty $registryDefaultUsers  DisableTailoredExperiencesWithDiagnosticData -Value 1 -PropertyType Dword -Force

    Write-Host "`nBloatware blocked from reinstalling." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Remove_BloatwareReg {

    Write-Host "`nRemoving specific bloatware registry keys..." -ForegroundColor White -BackgroundColor DarkGreen
    #These are the registry keys that it will delete.

    $Keys = @(
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

    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        if (Test-Path $key) {
            Write-Output "Removing from registry $Key"
            Remove-Item $Key -Recurse
        }
    }
    Write-Host "`nLeftover bloatware registry keys removed." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Debloat_BlockAds {

    #Disable ads throughout the system
    Write-Host "`nDisabling several different ads throughout the system..." -ForegroundColor White -BackgroundColor DarkGreen

    if(!(Test-Path -LiteralPath "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
    New-ItemProperty -LiteralPath "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
	
	if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
    New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

    Write-Host "`nAds blocked." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Remove_Telemetry {
    Write-Host "`n--Windows Telemetry and Privacy--" -ForegroundColor White -BackgroundColor DarkCyan

    $choices  = "&Yes", "&No"
    
    Write-Host "`nThis section will Block/Disable Windows Telemetry and Advertising.`nYou will be prompted on a few sections if you want to block them or leave them alone." -ForegroundColor White -BackgroundColor DarkCyan
    Pause

    #Disables Windows Advertising ID
    Write-Host "`nDisabling Advertising ID" -ForegroundColor White -BackgroundColor DarkBlue
	if(!(Test-Path "Reg_HKCU:\SOFTWARE\Microsoft\Input\TIPC")){ New-Item -Path "Reg_HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Force -ErrorAction SilentlyContinue}
	New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Input\TIPC")){ New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Input\TIPC" -Force -ErrorAction SilentlyContinue}
	New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\AdvertisingInfo")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force -ErrorAction SilentlyContinue}
	New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -PropertyType Dword -Force

    #Disable advertisments via Bluetooth
    Write-Host "`nDisabling Advertising via Bluetooth" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Bluetooth")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Bluetooth" -Force -ErrorAction SilentlyContinue}
	New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Value 0 -PropertyType Dword -Force

    #Block Input Data Harvesting
    If (!(Test-Path "Reg_HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {New-Item -Path "Reg_HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -PropertyType DWord -Force
    If (!(Test-Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {New-Item -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -PropertyType DWord -Force
    If (!(Test-Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {New-Item -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -PropertyType DWord -Force

    If (!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Personalization\Settings")) {New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -PropertyType DWord -Force
    If (!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization")) {New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -PropertyType DWord -Force
    If (!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null}
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -PropertyType DWord -Force

    #Block sending typing information to Microsoft
    Write-Host "`nSetting No-Advertizing Info Policy" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AdvertisingInfo")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AdvertisingInfo" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -PropertyType Dword -Force

    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Host "`nStopping the Windows Feedback Experience program" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Siuf\Rules")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Siuf\Rules" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Siuf\Rules" PeriodInNanoSeconds -Value 0 -PropertyType Dword -Force
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Siuf\Rules" NumberOfSIUFInPeriod -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Siuf\Rules")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Siuf\Rules" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Siuf\Rules" PeriodInNanoSeconds  -Value 0 -PropertyType Dword -Force
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Siuf\Rules" NumberOfSIUFInPeriod -Value 0 -PropertyType Dword -Force

    #Preping mixed Reality Portal for removal

    $title    = "Make Mixed Reality Portal removeable?"
    $question = "Do you want to make Widnows Mixed Reality Portal removeable?`nIf you want to uninstall it you can find it in Settings->Apps to uninstall afterwards."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nSetting Mixed Reality Portal value to 0 so that you can uninstall it in Settings" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" FirstRunSucceeded -Value 0 -PropertyType Dword -Force

        if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Holographic")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Holographic" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Holographic" FirstRunSucceeded -Value 0 -PropertyType Dword -Force
    }

    #Disables Wi-fi Sense
    Write-Host "`nDisabling Wi-Fi Sense" -ForegroundColor White -BackgroundColor DarkBlue
    $WifiSense1 = "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "Reg_HKLM_SOFTWARE:\Microsoft\WcmSvc\wifinetworkmanager\config"

    if(!(Test-Path "$WifiSense1")){ New-Item -Path "$WifiSense1" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "$WifiSense1" Value -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "$WifiSense2")){ New-Item -Path "$WifiSense2" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "$WifiSense2" Value -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "$WifiSense3")){ New-Item -Path "$WifiSense3" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "$WifiSense3" AutoConnectAllowedOEM -Value 0 -PropertyType Dword -Force


    #Disables live tiles
    Write-Host "`nDisabling live tiles" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")){ New-Item -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" NoTileApplicationNotification -Value 1 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")){ New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" NoTileApplicationNotification -Value 1 -PropertyType Dword -Force

    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Host "`nTurning off Data Collection" -ForegroundColor White -BackgroundColor DarkBlue

    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\DataCollection")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\DataCollection" AllowTelemetry -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DataCollection")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DataCollection" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DataCollection" AllowTelemetry -Value 0 -PropertyType Dword -Force
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" AllowTelemetry -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat" AITEnable -Value 0 -PropertyType Dword -Force
	

    #Disables People icon on Taskbar
    Write-Host "`nDisabling People icon on Taskbar" -ForegroundColor White -BackgroundColor DarkBlue

    if(!(Test-Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")){ New-Item -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" PeopleBand -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")){ New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" PeopleBand -Value 0 -PropertyType Dword -Force

   #Restrict Windows Update P2P only to local network
    Write-Host "`nRestricting Windows Update P2P only to local network..." -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DeliveryOptimization")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DeliveryOptimization" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -PropertyType Dword -Force

    #Disable Online Windows Search
    $title    = "Disable Bing search in Start Menu?"
    $question = "Disable Web Search aka Bing in the Start Menu?`nDisabling Web Search will significantly speed up the Start Menu and stop countless unwanted web searches when trying to open programs."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisable Online Windows Search" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -force -ea SilentlyContinue}
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaInAAD" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchHighlights" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "DoNotUseWebResults" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    }

    #Disable Hand Writing Error Reports
    Write-Host "`nDisabling Handwriting Error Reports" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\HandwritingErrorReports")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\HandwritingErrorReports" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -PropertyType Dword -Value 1 -Force

    #Disable sharing of Handwriting Data
    Write-Host "`nDisabling Sharing of Handwriting Data" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\TabletPC")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\TabletPC" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -PropertyType Dword -Value 1 -Force
	
    #Disable Auto Map Downloading/Updating
    $title    = "Disable Microsoft Maps Autodownload?"
    $question = "Disable Windows Maps from automatically downloading maps? Unless you use this feature it's best to answer yes."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Auto Map Downloading/UpDating" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Maps")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Maps" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -PropertyType Dword -Value 0 -Force
    }

    #Disable Customer Experience Improvement Program
    if ($Target -eq "Online") {
        Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    } else {
        if (Test-Path "$Target`\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ea SilentlyContinue) {
            [xml]$Task = Get-Content "$Target`\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
            $Task.Task.Settings.Enabled = "false"
        }
    }
        
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\SQMClient\Windows")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\SQMClient\Windows" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -PropertyType DWord -Force

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

    #Disable nag to finish setting up the device
    if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -PropertyType Dword -Force

    #Disable System Telemetry Services
    if ((Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet") -and ($Target -eq "Online")) {
      #Disabled for testing if(Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Services\DiagTrack"){New-ItemProperty -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 4 -PropertyType DWord -Force}
        #if(Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Services\dmwappushservice"){New-ItemProperty -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Value 4 -PropertyType DWord -Force}
        #Disabled for testing if(Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"){New-ItemProperty -Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 4 -PropertyType DWord -Force}
    } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
        #Disabled for testing if(Test-Path "Reg_HKLM_SYSTEM:\ControlSet001\Services\DiagTrack"){New-ItemProperty -Path "Reg_HKLM_SYSTEM:\ControlSet001\Services\DiagTrack" -Name "Start" -Value 4 -PropertyType DWord -Force}
        #if(Test-Path "Reg_HKLM_SYSTEM:\ControlSet001\Services\dmwappushservice"){New-ItemProperty -Path "Reg_HKLM_SYSTEM:\ControlSet001\Services\dmwappushservice" -Name "Start" -Value 4 -PropertyType DWord -Force}
        #Disabled for testing if(Test-Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"){New-ItemProperty -Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 4 -PropertyType DWord -Force}
    }

    #Disable Windows tracking app starts/usage
    if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType Dword -Force

    if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType Dword -Force

    #Disable Apps accessing user account information
    $title    = "Disable Apps Access to User Account Information?"
    $question = "Would you like to disable apps from having access to your user account information?`nApps have access to your account name, picture, and other account info. If you answer yes this will disable access for all apps.`nYou can find this setting in the Settings App under Privacy and look under Account Info."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Auto Map Downloading/Updating" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -PropertyType String -Value "Deny" -Force

        if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -PropertyType String -Value "Deny" -Force

        #Block for whole system
        #if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force -ErrorAction SilentlyContinue}
        #New-ItemProperty -Path "Reg_HKLM_SOFTWARE:Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -PropertyType String -Value "Deny" -Force
    }

    #Disable app access to Diagnostic Information
    $title    = "Disable Apps Access to Diagnostic Information?"
    $question = "Would you like to disable apps from having access to Diagnostic Information?`nApps have access to diagnostic information which can sometimes be an invasion of privacy. If you answer yes this will disable access for all apps.`nYou can find this setting in the Settings App under Privacy and look under App diagnostics."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Apps having access to Diagnostic Information" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -PropertyType String -Value "Deny" -Force

        if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -PropertyType String -Value "Deny" -Force

        #Block for whole system
        #if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Force -ErrorAction SilentlyContinue}
        #New-ItemProperty -Path "Reg_HKLM_SOFTWARE:Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -PropertyType String -Value "Deny" -Force
    }

    #Disable use of diagnostic data for tailor-made user experience
    Write-Host "`nDisabling use of diagnostic data for tailor-made user experience (aka ads and suggestions)" -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType Dword -Value 0 -Force

    if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Privacy")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType Dword -Value 0 -Force

    #Disable backup of text messages to the cloud
    $title    = "Disable Text Message Cloud Backup?"
    $question = "Windows has a feature to back up all text messages to the cloud which can be an invasion to privacy.`nDo you want to block text message cloud backup?"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Text Message Backup" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Messaging")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Messaging" -Force -ErrorAction SilentlyContinue}
	    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -PropertyType Dword -Force
    }
    
    #Disable Windows Error Reporting
    $title    = "Disable Windows Error Reporting?"
    $question = "Windows Error Reporting sends application error information to Windows to help diagnose issues.`nThis is a legitimate feature that is helpful for making computers run smoothly, but can give Microsoft details about applications you are using and what you are doing in them.`nDo you want to disable Error Reporting?`nSuggested: No"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Windows Error Reporting" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\Windows Error Reporting")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\Windows Error Reporting" -Force -ErrorAction SilentlyContinue}
	    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -PropertyType Dword -Force
    }
    Write-Host "`nTelemetry blocked." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Remove_Edge {
    Write-Host "--Microsoft Edge--" -ForegroundColor White -BackgroundColor DarkCyan

    $title    = "Disable Microsoft Edge App?"
    $choices  = "&Yes", "&No"
    Write-Host ""
    $question = "Would you like to Disable Microsoft Edge Browser from the computer?`nMake sure you have at least one other web browser installed.`nFirefox or Brave are reccomended as they are privacy-focused free browers.`nThis will rename $MountDir`Program Files (x86)\Microsoft\Edge and EdgeUpdate to with a _Disabled suffix`nIf you choose no, you will be given an option to disable Edge from stealing defaults of PDF files."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        if ($Target -eq "Online") {
            Get-Process -Name "*Edge*" | Stop-Process -Force
            taskkill /f /im msedge.exe | Out-Null
        }
        if (Test-Path "$MountDir`Program Files (x86)\Microsoft\Edge"){
            takeown /f "$MountDir`Program Files (x86)\Microsoft\Edge"
            icacls "$MountDir`Program Files (x86)\Microsoft\Edge" /grant Administrators:F /T /C | Out-Null
            Rename-Item -Path "$MountDir`Program Files (x86)\Microsoft\Edge" -NewName "Edge_Disabled"
        }
        if (Test-Path "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate"){
            takeown /f "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate"
            icacls "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate" /grant Administrators:F /T /C | Out-Null
            Rename-Item -Path "$MountDir`Program Files (x86)\Microsoft\EdgeUpdate" -NewName "EdgeUpdate_Disabled"
        }
        if((Test-Path -LiteralPath "Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge") -ne $true) {  New-Item "Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge\Main") -ne $true) {  New-Item "Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge\Main" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge\TabPreloader") -ne $true) {  New-Item "Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge\TabPreloader" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath 'Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge\Main' -Name 'AllowPrelaunch' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'Reg_HKLM_SOFTWARE\Policies\Microsoft\Microsoft Edge\TabPreloader' -Name 'AllowTabPreloading' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        
        $Script:Disable_EdgePDF = $true
        Write-Host "`nMicrosoft Edge Browser disabled." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Function Stop_EdgePDF {
    #Stops edge from taking over as the default .PDF viewer
    Write-Host "`n--Microsoft Edge PDF Handler--" -ForegroundColor White -BackgroundColor DarkCyan

    if ($Script:Disable_EdgePDF -ne $true) {
        $title    = "Disable Edge handling PDFs?"
        $choices  = "&Yes", "&No"
        $question = "Would you like to stop Edge from trying to open PDF files by default? This will stop Edge from repeatedly taking control of PDF files from Firefox, Adobe Reader, Foxit, etc."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    }

    if (($decision -eq 0) -or ($Script:Disable_EdgePDF -eq $true)) {
        Write-Host "`nStopping Edge from taking over as the default .PDF viewer..." -ForegroundColor White -BackgroundColor DarkGreen
        $NoPDF = "Reg_HKCR:\.pdf"
        $NoProgids = "Reg_HKCR:\.pdf\OpenWithProgids"
        $NoWithList = "Reg_HKCR:\.pdf\OpenWithList"
        If (!(Test-Path "$NoPDF")) {New-Item -Path "$NoPDF" -Force | Out-Null}
        If (!(Get-ItemProperty $NoPDF NoOpenWith -ErrorAction SilentlyContinue)) {New-ItemProperty $NoPDF NoOpenWith}
        If (!(Get-ItemProperty $NoPDF NoStaticDefaultVerb -ErrorAction SilentlyContinue)) {New-ItemProperty $NoPDF NoStaticDefaultVerb}
        If (!(Test-Path "$NoProgids")) {New-Item -Path "$NoProgids" -Force | Out-Null}
        If (!(Get-ItemProperty $NoProgids NoOpenWith -ErrorAction SilentlyContinue)) {New-ItemProperty $NoProgids NoOpenWith}
        If (!(Get-ItemProperty $NoProgids NoStaticDefaultVerb -ErrorAction SilentlyContinue)) {New-ItemProperty $NoProgids NoStaticDefaultVerb}
        If (!(Test-Path "$NoWithList")) {New-Item -Path "$NoWithList" -Force | Out-Null}
        If (!(Get-ItemProperty $NoWithList NoOpenWith -ErrorAction SilentlyContinue)) {New-ItemProperty $NoWithList NoOpenWith}
        If (!(Get-ItemProperty $NoWithList NoStaticDefaultVerb -ErrorAction SilentlyContinue)) {New-ItemProperty $NoWithList NoStaticDefaultVerb}

        #Appends an underscore '_' to the Registry key for Edge
        $Edge = "Reg_HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
        If (Test-Path $Edge) {Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_}
        $EdgePDF = "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge"
        If (!(Test-Path $EdgePDF)) {New-Item $EdgePDF}
        New-ItemProperty -Path $EdgePDF -Name AlwaysOpenPdfExternally -Value 1 -PropertyType Dword -Force

        Write-Host "`nEdge blocked from taking over .PDF files." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Function Restore_EdgePDF {
    #Stops edge from taking over as the default .PDF viewer
    Write-Host "`n--Microsoft Edge PDF Handler--"
    if ($Script:Disable_EdgePDF -ne $true) {
        $title    = "Restore Edge for handling PDFs? (To undo previous blocking PDFs)"
        $choices  = "&Yes", "&No"
        $question = "Would you like to once again allow Edge to open PDF files by default?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    }

    if (($decision -eq 0) -and ($Script:Disable_EdgePDF -eq $false)) {
        Write-Host "`nRestoring Edge as a .PDF viewer..."
        $NoPDF = "Reg_HKCR:\.pdf"
        $NoProgids = "Reg_HKCR:\.pdf\OpenWithProgids"
        $NoWithList = "Reg_HKCR:\.pdf\OpenWithList"
        If ((Get-ItemProperty $NoPDF NoOpenWith -ErrorAction SilentlyContinue)) {Remove-ItemProperty $NoPDF NoOpenWith}
        If ((Get-ItemProperty $NoPDF NoStaticDefaultVerb -ErrorAction SilentlyContinue)) {Remove-ItemProperty $NoPDF NoStaticDefaultVerb}
        If ((Get-ItemProperty $NoProgids NoOpenWith -ErrorAction SilentlyContinue)) {Remove-ItemProperty $NoProgids NoOpenWith}
        If ((Get-ItemProperty $NoProgids NoStaticDefaultVerb -ErrorAction SilentlyContinue)) {Remove-ItemProperty $NoProgids NoStaticDefaultVerb}
        If ((Get-ItemProperty $NoWithList NoOpenWith -ErrorAction SilentlyContinue)) {Remove-ItemProperty $NoWithList NoOpenWith}
        If ((Get-ItemProperty $NoWithList NoStaticDefaultVerb -ErrorAction SilentlyContinue)) {Remove-ItemProperty $NoWithList NoStaticDefaultVerb}

        #Appends an underscore '_' to the Registry key for Edge
        #$Edge = "Reg_HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
        #If (Test-Path $Edge) {Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_}
        $EdgePDF = "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge"
        If ((Get-ItemProperty $EdgePDF AlwaysOpenPdfExternally -ErrorAction SilentlyContinue)) {Remove-ItemProperty -Path $EdgePDF -Name AlwaysOpenPdfExternally}

        Write-Host "`nEdge restored to open .PDF files."
    }
}

Function Remove_OneDrive {

    Write-Host "`n--Microsoft OneDrive--" -ForegroundColor White -BackgroundColor DarkCyan

    $title    = "Remove Microsoft OneDrive?"
    $choices  = "&Yes", "&No"
    Write-Host ""
    $question = "Would you like to remove OneDrive?"
    $decision = 1 #$Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nAttempting to uninstall OneDrive..."
        if ($Target -eq "Online"){
            Get-Process -Name "*OneDrive*" | Stop-Process -Force
            taskkill /f /im OneDrive.exe | Out-Null
        }
        if (Test-Path "$MountDir`Windows\System32\OneDriveSetup.exe") {
            if ($Target -eq "Online"){
                Start-Process "$env:SystemDrive\Windows\System32\OneDriveSetup.exe" -ArgumentList "/Uninstall" -Wait
                Sleep 2
                }
            takeown /f $MountDir`Windows\System32\OneDriveSetup.exe
            icacls $MountDir`Windows\System32\OneDriveSetup.exe /grant Administrators:F /C
            Rename-Item -Path "$MountDir`Windows\System32\OneDriveSetup.exe" -NewName "OneDriveSetup_Disabled.exe"
        }
        if (Test-Path "$MountDir`Windows\SysWOW64\OneDriveSetup.exe") {
            if ($Target -eq "Online"){
                Start-Process "$env:SystemDrive\Windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/Uninstall" -Wait
                Sleep 2
            }
            takeown /f $MountDir`Windows\SysWOW64\OneDriveSetup.exe
            icacls $MountDir`Windows\SysWOW64\OneDriveSetup.exe /grant Administrators:F /C
            Rename-Item -Path "$MountDir`Windows\SysWOW64\OneDriveSetup.exe" -NewName "OneDriveSetup_Disabled.exe"
        }
        Write-Host "`nMicrosoft OneDrive Removed."
    }
}

Function Clean_StartMenu {
    Write-Host "`n--Start Menu--" -ForegroundColor White -BackgroundColor DarkCyan

    $title    = "Clean the Start Menu?"
    $choices  = "&Yes", "&No"
    Write-Host ""
    $question = "Would you like to clean the Start Menu?`nThis will only affect new users logging into the computer or if you were to clear your local profile or Start Menu data."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nCleaning Start Menu for new users..." -ForegroundColor White -BackgroundColor DarkGreen
	    
        if ($WinVer -eq 10) {
            $startlayout=@"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout">
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
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Windows.Explorer" />
        <taskbar:UWA AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
	        $startlayout | Out-File $ENV:TEMP\StartLayout.xml
            try {
                Import-StartLayout -LayoutPath $ENV:TEMP\StartLayout.xml -MountPath $MountDir -Verbose -ErrorAction Stop
            } catch {
                Write-Host "Failed to Import a clean Start Menu Layout. Error: $_"
                Write-Error "Failed to Import a clean Start Menu Layout. Error: $_"
            }
	        Start-Sleep 1
	        Remove-Item $ENV:TEMP\StartLayout.xml -Force -ErrorAction Continue
        }
	
	    if ($WinVer -eq 11) {
            $W11StartLayout= '{"pinnedList":[{"packagedAppId":"windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"},{"desktopAppLink":"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\File Explorer.lnk"},{"desktopAppLink":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Microsoft Edge.lnk"},{"desktopAppLink":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Word.lnk"},{"desktopAppLink":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Excel.lnk"},{"desktopAppLink":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\PowerPoint.lnk"}]}'

	        #$W11StartLayout | Out-File "$MountDir`Users\Default\Appdata\Local\Microsoft\Windows\Shell\LayoutModification.json" -Force
	        #if ((Test-Path -Path "$MountDir`Users\Default\Appdata\Local\Microsoft\Windows\Shell\LayoutModification.xml") -eq $true) {Remove-Item "$MountDir`Users\Default\Appdata\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force}
            #if((Test-Path -Path "$MountDir`Users\Default\Appdata\Local\Microsoft\Windows\Shell\DefaultLayouts.xml") -eq $true) {Remove-Item "$MountDir`Users\Default\Appdata\Local\Microsoft\Windows\Shell\DefaultLayouts.xml" -Force};

            if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start")) {  New-Item "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start" -force -ea SilentlyContinue }
            New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start" -Name "ConfigureStartPins" -Value $W11StartLayout -PropertyType String -Force
            #New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\PolicyManager\current\device\Start" -Name "ConfigureStartPins_ProviderSet" -Value 1 -PropertyType DWord -Force
        }
        Write-Host "`nStart menu cleaned for new users." -ForegroundColor White -BackgroundColor DarkCyan
    }
}

Function System_Tweaks {
    Write-Host "`n--Windows Tweaks--" -ForegroundColor White -BackgroundColor DarkCyan

    Write-Host "`nIn this section you will be offered a lot of Windows tweak options.`nSome options may do the opposite of previous options.`nThese are preferences more than debloat features." -ForegroundColor White -BackgroundColor DarkCyan
    Pause

    $choices  = "&Yes", "&No"
    
    #Harden C:\ to stop non-administrators modifying the root C: Drive
    $title    = "Harden C: Drive Root Security?"
    $question = "Answering yes makes the root of C:\ modifiable only by administrators."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nHardening C: Drive Root"
        icacls.exe C:\ /remove:g "*S-1-5-11"
    }
    
    #Block Edge First Run Experience
    $title    = "Disable Edge First Run Experience?"
    $question = "Answering yes stops Edge from asking you about setting up your Edge preferences on first launch."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling the storing of user activity history"
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge" -Force -ErrorAction SilentlyContinue}
	    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -PropertyType Dword -Force
    }

    #W11 Align taskbar
    if ($WinVer -eq 11) {
        $title    = "Align Taskbar to the left?"
        $question = "Change Windows 11 Start Menu to be on the left instead of center?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Start Menu set to the left side (If Windows 11)"
            if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

            if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

    #W11 Show More Pins
    if ($WinVer -eq 11) {
        $title    = "Change Pins?"
        $question = "Change Windows 11 Start Menu to Show More Pins instead of recommendations?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Start Menu set to show more pins (If Windows 11)" -ForegroundColor White -BackgroundColor DarkBlue
            if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

            if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

    #W11 Hide Widgets on Taskbar
    if ($WinVer -eq 11) {
        $title    = "Hide Widgets?"
        $question = "Hide the Widgets button from the Task Bar?`nThis is redundant if you removed Widgets earlier step but does no harm."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Removing Widgits from the Taskbar" -ForegroundColor White -BackgroundColor DarkBlue
            if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

            if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

    #W11 Classic Context Menu
    if ($WinVer -eq 11) {
        $title    = "Revert to Classic Context Menus?"
        $question = "Would you like back the classic right-click context menu that shows all options by default?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Removing Widgits from the Taskbar" -ForegroundColor White -BackgroundColor DarkBlue
            if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32")) {  New-Item "Reg_HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name '(Default)' -Value $null -PropertyType String -Force -ea SilentlyContinue;

            if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32")) {  New-Item "Reg_HKDefaultUser:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name '(Default)' -Value $null -PropertyType String -Force -ea SilentlyContinue;
        }
    }

    #W11 Hide Recent Searches when hovering over search icon
    if ($WinVer -eq 11) {
        $title    = "Hide Recent Searches?"
        $question = "Hide Recent Searches when you mouse-over the search icon in the taskbar?`nThis is often annoying when your mouse pointer passes over the taskbar."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Hiding Recent Searches from the taskbar search icon" -ForegroundColor White -BackgroundColor DarkBlue
            if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSh" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

            if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue };
            New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSh" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

    #Disable storing of user's activity history
    #https://www.tenforums.com/tutorials/100341-enable-disable-collect-activity-history-windows-10-a.html
    $title    = "Disable Storing User Activity History?"
    $question = "Windows stores User Activity History as part of the Pickup Where You Left Off feature from Cortana.`nThis sends your activities including what applications you've been using recently among other factors.`nIf you have already disabled Cortana you may as well disable this as well."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling the storing of user activity history" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System" -Force -ErrorAction SilentlyContinue}
	    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -PropertyType Dword -Force
	    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -PropertyType Dword -Force
    }
    
    #Search Bar to Icon
    $title    = "Search Bar to Icon"
    $question = "Change the Windows Search Bar on the Taskbar to an icon? (If applicable)"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
	    Write-Host "Setting Search Bar to Icon" -ForegroundColor White -BackgroundColor DarkBlue
	    if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")) {New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -force -ea SilentlyContinue};
	    New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
        
        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search")) {New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -force -ea SilentlyContinue};
	    New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    }

	#Disable News and Interests
    if ($WinVer -eq 10) {
        $title    = "Hide News and Interests?"
        $question = "Hide the annoying News and Interests icon from the Taskbar that shows weather, stock market, news, etc.?`nThis is not only annoying but uses up a lot of memory and does constant Bing searches without asking."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Disabling Windows News and Interests" -ForegroundColor White -BackgroundColor DarkBlue
	        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Feeds")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Feeds" -force -ea SilentlyContinue};
	        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

	#Disable News and Interests aka Widgets Win 11
    if ($WinVer -eq 11) {
        $title    = "Hide Windows 11 Widgets?"
        $question = "Hide the annoying Windows 11 Widgets that show ads, weather, and other annoyances that also slow down workstations."
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Disabling Windows News and Interests aka Widgets"
	        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Dsh")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Dsh" -force -ea SilentlyContinue};
	        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

	#Disable Recommended Section in Start Menu
    if ($WinVer -eq 11) {
        $title    = "Disable Recommended Section in Start Menu?"
        $question = "Remove the Reccomended section from the Start Menu that shows common files and apps"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Disabling Recommended Apps in Start Menu"
	        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -force -ea SilentlyContinue};
	        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

	#Disable Personalized Sites in Start Menu
    if ($WinVer -eq 11) {
        $title    = "Recommended Websites in Start Menu?"
        $question = "Remove Recommended Websites from the Start Menu that shows recent and frequent websites?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Disabling Recommended Sites in Start Menu"
	        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -force -ea SilentlyContinue};
	        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedPersonalizedSites" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
        }
    }

    #Disable Inventory Collector **ONLY for home computers!**
    $title    = "Disable Inventory Collector function?"
    $question = "Note: If this is a work computer or used in a managed envrionment do NOT disable this service!`nInventory Collector is a service for Windows to allow management software to get an inventory of installed applications, devices, and system information.`nIf this is a home PC used for only personal purposes you can disable this service."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Inventory Collector" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat" -force -ea SilentlyContinue};
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    }

    #Disable camera in logon screen
    $title    = "Disable camera in logon?"
    $question = "Would you like to block your webcam from being used in the logon screen? This may cause face unlock to no longer work.`nIf you don't want to use Face unlock and have no reason to use the webcam at the logon screen you can disable this."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling camera access at logon screen" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Personalization")) {New-Item "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Personalization" -force -ea SilentlyContinue};
        New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    }

	#Show BSOD Details
    $title    = "Verbose BSOD"
    $question = "Would you like to make the BSOD (Blue Screen Of Death) give you a proper explaination of what is wrong instead of the useless sad face?"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Showing BSOD Details instead of sad face" -ForegroundColor White -BackgroundColor DarkBlue
	    if ((Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet") -and ($Target -eq "Online")) {
		    if(Test-Path -LiteralPath "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\CrashControl") {New-ItemProperty -LiteralPath "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;}
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
		    if(Test-Path -LiteralPath "Reg_HKLM_SYSTEM:\ControlSet001\Control\CrashControl") {New-ItemProperty -LiteralPath "Reg_HKLM_SYSTEM:\ControlSet001\Control\CrashControl" -Name "DisplayParameters" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;}
        }
    }

	#Verbose Startup/Shutdown
    $title    = "Verbose Startup and Shutdown"
    $question = "Would you like to enable Verbose Startup and Shutdown?`nThis will tell you what Windows is doing during Startup and Shutdown instead of the generic Starting and Shutting Down message."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Verbose Startup and Shutdown Messages" -ForegroundColor White -BackgroundColor DarkBlue
	    if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System")) {New-Item "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System" -force -ea SilentlyContinue};
	    New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    }

	#Disable Meet Now
    $title    = "Disable Meet Now"
    $question = "Would you like to disable the annoying Meet Now icon on the Taskbar or System Tray?`nThis is another Teams-like Windows product where clicking the icon takes you to the service."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Meet Now" -ForegroundColor White -BackgroundColor DarkBlue
	    if(!(Test-Path -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {New-Item "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\Explorer" -force -ea SilentlyContinue};
	    New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    }

    #Disable Clipboard Suggestions Windows 11
    $title    = "Disable Clipboard Suggested Actions (Windows 11)"
    $question = "Would you like to disable the popup every time you use the clipboard where Windows suggests actions for the clipboard content?"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Clipboard Suggestions"
	    if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Name "Disabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard")) {  New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Name "Disabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    }

	#Disable Sticky keys prompt
    $title    = "Disable Sticky Keys Shortcut?"
    $question = "Sticky Keys is an Accessibility feature that will hold down modifier keys such as Ctrl, Alt, or Shift.`nWhile useful for those that need it, it's very easy to accidentically activate it as it turns on by pressing shift 5 times in a row.`nAnswering yes will disable the shortcut.`nYou can find these options in Ease of Access if you need to change it later."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
	    Write-Host "Disabling Sticky keys shortcut" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Control Panel\Accessibility\StickyKeys")) {New-Item "Reg_HKCU:\Control Panel\Accessibility\StickyKeys" -force -ea SilentlyContinue};
	    New-ItemProperty -Path "Reg_HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "506" -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Control Panel\Accessibility\StickyKeys")) {New-Item "Reg_HKDefaultUser:\Control Panel\Accessibility\StickyKeys" -force -ea SilentlyContinue};
	    New-ItemProperty -Path "Reg_HKDefaultUser:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "506" -Force
    }

    #Disable Filter keys prompt
    $title    = "Disable Filter Keys Shortcut?"
    $question = "Filter Keys is an Accessibility feature that will ignore keys if you press them more than once in rapid succession.`nWhile useful for those that need it, it's very easy to accidentically activate it as it turns on by holding the right-shift key for 8 seconds.`nAnswering yes will disable the shortcut.`nYou can find these options in Ease of Access if you need to change it later."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Filter keys shortcut" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Control Panel\Accessibility\Keyboard Response")) {New-Item "Reg_HKCU:\Control Panel\Accessibility\Keyboard Response" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -PropertyType String -Value "122" -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Control Panel\Accessibility\Keyboard Response")) {New-Item "Reg_HKDefaultUser:\Control Panel\Accessibility\Keyboard Response" -force -ea SilentlyContinue};
	    New-ItemProperty -Path "Reg_HKDefaultUser:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -PropertyType String -Value "122" -Force
    }

    #Disable Toggle keys prompt
    $title    = "Disable Toggle Keys Shortcut?"
    $question = "Toggle Keys is an Accessibility feature that will play a sound every time Caps Lock, Num Lock, or Scroll Lock are pressed.`nWhile useful for those that need it, it's very easy to accidentically activate it as it turns on by holding the Num lock key for 5 seconds.`nAnswering yes will disable the shortcut.`nYou can find these options in Ease of Access if you need to change it later."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Toggle keys shortcut" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Control Panel\Accessibility\ToggleKeys")) {New-Item "Reg_HKCU:\Control Panel\Accessibility\ToggleKeys" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -PropertyType String -Value "58" -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Control Panel\Accessibility\ToggleKeys")) {New-Item "Reg_HKDefaultUser:\Control Panel\Accessibility\ToggleKeys" -force -ea SilentlyContinue};
	    New-ItemProperty -Path "Reg_HKDefaultUser:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -PropertyType String -Value "58" -Force
    }

	#Show all tray icons
    if ($WinVer -eq 10) {
        $title    = "Show all System Tray Icons?"
        $question = "Would you like all system tray icons to be visible at all times instead of pressing the little ^ icon to reveal them?"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Showing all system tray icons..." -ForegroundColor White -BackgroundColor DarkBlue
            if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer")) {New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -force -ea SilentlyContinue};
            New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWord -Value 0 -Force

            if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer")) {New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer" -force -ea SilentlyContinue};
            New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWord -Value 0 -Force
        }
    }

	#Hide tray icons as needed
    if ($WinVer -eq 10) {
        $title    = "Hide System Tray Icons?"
        $question = "Would you like system tray icons to automatically hide until pressing the little ^ icon to reveal them? (Opposite of previous option)"
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Write-Host "Hiding system try icons automatically" -ForegroundColor White -BackgroundColor DarkBlue
            Remove-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -ErrorAction SilentlyContinue
        }
    }

	#Show known file extensions
    $title    = "Show file extensions?"
    $question = "Windows by default hides known file extensions eg. plain text files ending in .txt or programs ending in .exe in their names.`nWould you like to make them visible again?`nThis helps in identifying what a file is without opening it."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
	    Write-Host "Showing known file extensions..." -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
	    New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 0 -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
	    New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 0 -Force
    }

	# Hide known file extensions
    $title    = "Hide file extensions?"
    $question = "Would you like to restore the default Windows setting to hide file extensions?`n(Opposite of the previous option)"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Hiding known file extensions" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 1 -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 1 -Force
    }
	
	#Show file operations details
    $title    = "Show detailed file operations?"
    $question = "Windows by default shows only the basic file operations window for copying, moving or modifying files.`nWould you like it to show the full details by default for you and new users?"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Defaulting to show file operation details" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {New-Item "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1 -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {New-Item "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1 -Force
    }
	
	#Set Default Explorer View to "This PC"
    $title    = "Show This PC by Default"
    $question = "When opening an Explorer Window, would you like it go to to This PC by default instead of Quick Access?"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Defaulting to This PC view in Explorer" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value 1 -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {New-Item "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value 1 -Force
    }
    #Disable Fast Startup Windows 10/11
    $title    = "Disable Fast Boot"
    $question = "Windows has a feature called Fast Boot where when you select Shut Down from the start menu, the computer is actually going into a partial hibernation.`nThis usually only saves you a few seconds during startup but introduces a lot of problems where corrupted memory makes the computer act strangely.`nTurning off Fast Boot often resolves many problems.`nDisable Fast Boot?"
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Fast Startup" -ForegroundColor White -BackgroundColor DarkBlue
        if ((Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet") -and ($Target -eq "Online")) {
		    if(Test-Path "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\Session Manager\Power"){New-ItemProperty -LiteralPath "Reg_HKLM_SYSTEM:\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue}
        } elseif ((Test-Path "Reg_HKLM_SYSTEM:\ControlSet001") -and ($Target -ne "Online")) {
		    if(Test-Path "Reg_HKLM_SYSTEM:\ControlSet001\Control\Session Manager\Power"){New-ItemProperty -LiteralPath "Reg_HKLM_SYSTEM:\ControlSet001\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue}
        }
    }

    #Disable Clipboard Sync
    $title    = "Disable Clipboard Cloud Sync"
    $question = "Windows Clipboard has a feature to sync your clipboard between devices. This means any content in your clipboard is being sent to the Microsoft cloud.`nUnless you are using this feature, it's suggested you disable this for security and privacy reasons."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Clipboard Cloud Sync" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System" -Force -ErrorAction SilentlyContinue}
	    New-ItemProperty -LiteralPath "Reg_HKLM_SOFTWARE:\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    }

    #Disable Clipboard History
    $title    = "Disable Clipboard History"
    $question = "Do you want to disable Clipboard History?`nThis means as soon as you copy an item into the clipboard the last time is forgotten. If left enabled Windows Key + V opens Clipboard History`nOften useful, disable only if you really don't want this."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "Disabling Clipboard History" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path -LiteralPath "Reg_HKCU:\Software\Microsoft\Clipboard")) {New-Item "Reg_HKCU:\Software\Microsoft\Clipboard" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 0 -Force

        if(!(Test-Path -LiteralPath "Reg_HKDefaultUser:\Software\Microsoft\Clipboard")) {New-Item "Reg_HKDefaultUser:\Software\Microsoft\Clipboard" -force -ea SilentlyContinue};
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 0 -Force
    }

    #Disable Windows Spotlight on Lockscreen
    $title    = "Disable Windows Spotlight?"
    $question = "Would you like to disable Windows Spotlight on the logon screen?`nWindows Spotlight selects random images from around the world and displays random tips and search suggestions on the lock screen.`nThis means your lock screen is making Bing searches and downloading lockscreen wallpapers in the background."
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if ($decision -eq 0) {
        Write-Host "`nDisabling Windows Spotlight" -ForegroundColor White -BackgroundColor DarkBlue
        if(!(Test-Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")){ New-Item -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -PropertyType Dword -Value 0 -Force
        New-ItemProperty -Path "Reg_HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -PropertyType Dword -Value 0 -Force
        if(!(Test-Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")){ New-Item -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType Dword -Value 1 -Force
        New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType Dword -Value 1 -Force
        New-ItemProperty -Path "Reg_HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -PropertyType Dword -Value 1 -Force

        if(!(Test-Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")){ New-Item -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -PropertyType Dword -Value 0 -Force
        New-ItemProperty -Path "Reg_HKDefaultUser:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -PropertyType Dword -Value 0 -Force
        if(!(Test-Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")){ New-Item -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force -ErrorAction SilentlyContinue}
        New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType Dword -Value 1 -Force
        New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType Dword -Value 1 -Force
        New-ItemProperty -Path "Reg_HKDefaultUser:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -PropertyType Dword -Value 1 -Force
    }
    
    #Bypass NRO in OOBE aka prompts to create Microsoft Accounts
    Write-Host "Bypassing NRO prompts in OOBE`nThis allows skipping the nag to set up a Microsoft Account." -ForegroundColor White -BackgroundColor DarkBlue
    if(!(Test-Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\OOBE")){ New-Item -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\OOBE" -Force -ErrorAction SilentlyContinue}
    New-ItemProperty -Path "Reg_HKLM_SOFTWARE:\Microsoft\Windows\CurrentVersion\OOBE" -Name "BypassNRO" -PropertyType DWord -Value 1 -Force

    Write-Host "`nSystem Tweaks completed." -ForegroundColor White -BackgroundColor DarkCyan
}

Function CheckDMWService {
    Write-Host "`nRe-enabling DMWAppushservice if it was disabled" -ForegroundColor White -BackgroundColor DarkGreen

    If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
        Set-Service -Name dmwappushservice -StartupType Automatic
    }

    If (Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
        Start-Service -Name dmwappushservice
    }
}

Function Cleanup_Image {

    #Cleans up the Windows Component Store to reduce image size
    Write-Host "`nCleaning up Windows Image, please wait..." -ForegroundColor White -BackgroundColor DarkGreen
    dism /Image:$Target /Cleanup-Image /StartComponentCleanup /ResetBase /ScratchDir:"$MountDir`\Scratch"
    Write-Host "Image cleanup complete." -ForegroundColor White -BackgroundColor DarkCyan
}

Function Mount_Registry {
    Write-Host "`nMounting the registry..." -ForegroundColor Yellow
    if ($Target -eq "Online") {
        #Mount Registry Roots
        #if (!(Get-PSDrive -Name Reg_HKLM_COMPONENTS)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\COMPONENTS -Name Reg_HKLM_COMPONENTS -Scope Global -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKLM_SOFTWARE -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\SOFTWARE -Name Reg_HKLM_SOFTWARE -Scope Global -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKLM_SYSTEM -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\SYSTEM -Name Reg_HKLM_SYSTEM -Scope Global -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKDefaultUser -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$env:SystemDrive\Users\Default\NTUSER.DAT" -Key "HKLM\TEMP_HKDefaultUser" -Name Reg_HKDefaultUser -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKCU -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_CURRENT_USER -Name Reg_HKCU -Scope Global -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKCR -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name Reg_HKCR -Scope Global -ErrorAction Stop}

    } elseif ((Test-Path $Target -PathType Container) -and (Test-Path "$Target`\Windows")) {
        $MountDir = $Target
        #if (!(Get-PSDrive -Name Reg_HKLM_COMPONENTS -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Windows\System32\config\COMPONENTS" -Key "HKLM\TEMP_HKLM_COMPONENTS" -Name Reg_HKLM_COMPONENTS -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKLM_SOFTWARE -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Windows\System32\config\SOFTWARE" -Key "HKLM\TEMP_HKLM_SOFTWARE" -Name Reg_HKLM_SOFTWARE -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKLM_SYSTEM -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Windows\System32\config\SYSTEM" -Key "HKLM\TEMP_HKLM_SYSTEM" -Name Reg_HKLM_SYSTEM -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKDefaultUser -ErrorAction SilentlyContinue)) {Import-RegistryHive -File "$Target`\Users\Default\NTUSER.DAT" -Key "HKLM\TEMP_HKDefaultUser" -Name Reg_HKDefaultUser -ErrorAction Stop}
        if (!(Get-PSDrive -Name Reg_HKCU -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\TEMP_HKDefaultUser -Name Reg_HKCU -Scope Global -ErrorAction Stop} #Although redundant, this prevents errors for any tasks that try to write to HKEY_Current_USER
        if (!(Get-PSDrive -Name Reg_HKCR -ErrorAction SilentlyContinue)) {New-PSDrive -PSProvider Registry -Root HKEY_LOCAL_MACHINE\TEMP_HKLM_SOFTWARE\Classes -Name Reg_HKCR -Scope Global -ErrorAction Stop}
    }
}

Function UnMount_Registry {
    Write-Host "`nUnmounting the registry..." -ForegroundColor Yellow

    $RegDrives = @("Reg_HKCR","Reg_HKCU","Reg_HKLM_SOFTWARE","Reg_HKLM_SYSTEM","Reg_HKDefaultUser")
    $UnmountAttempts = 1
    While (Compare-Object -ReferenceObject $(Get-PSDrive | ForEach-Object -MemberName Name) -DifferenceObject $RegDrives -IncludeEqual -ExcludeDifferent) {
        Write-Host "Attempt: $UnmountAttempts" -ForegroundColor Gray
        if ($UnmountAttempts -ge 5) {
            Write-Host "-----------------------------" -ForegroundColor Red
            Write-Error "Error: Failed to unmount registry objects: $(Get-PSDrive -Name "Reg_*"). You may need to open Regedit.exe and look for keys labeled Reg_ under HKEY_Local_Machine and manually unload them."
            Write-Host "-----------------------------" -ForegroundColor Red

            Break
        }
        $UnmountAttempts++
        Sleep 2
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
    if ($TestDrive -ne $null)
    {
        throw [Management.Automation.SessionStateException] "A drive with the name '$Name' already exists."
    }

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait

    if ($Process.ExitCode)
    {
        throw [Management.Automation.PSInvalidOperationException] "The registry hive '$File' failed to load. Verify the source path or target registry key."
    }

    try
    {
        # validate patten on $Name in the Params and the drive name check at the start make it very unlikely New-PSDrive will fail
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
    }
    catch
    {
        throw [Management.Automation.PSInvalidOperationException] "A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually."
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
        Write-Error "The registry key '$Key' could not be unloaded, the key may still be in use."
        #throw [Management.Automation.PSInvalidOperationException] "The registry key '$Key' could not be unloaded, the key may still be in use."
    }
}

#Tasks before mounting registry
#Build task list
Gather_Packages
Bloatware_Appx
Bloatware_SysPackages
Bloatware_Xbox
Bloatware_Teams
Bloatware_Cortana

#Debloat using DISM functions
Remove_Appx
Remove_SysPackages

Mount_Registry
#After mounting registry
Debloat_BlockBloatware
Remove_BloatwareReg
Bloatware_Services
Remove_Services
Debloat_BlockAds
if ($Script:Remove_Xbox) {Remove_Xbox}
if ($Script:Remove_Teams) {Remove_Teams}
if ($Script:Remove_Cortana) {Remove_Cortana}
Remove_Telemetry
Remove_Edge
Stop_EdgePDF
Restore_EdgePDF
Remove_OneDrive
Clean_StartMenu
System_Tweaks

UnMount_Registry

if ($Target -eq "Online") {
    CheckDMWService
} else {
    #Cleanup_Image #Cleans up the Component Store, however it appears newest versions of Windows might have issues using the "Reset PC" feature if this is done.
}

Write-Host "`nDebloat, Privacy, and cleanup complete!" -ForegroundColor White -BackgroundColor DarkCyan 