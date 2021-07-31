trap {"An error trapped..."}

# ::***********************************************************************************************
# :: Definition-1: Check bitness of OS, process, package, guid of old version
# ::***********************************************************************************************
$OS_BITNESS=32
if([Environment]::Is64BitOperatingSystem -eq $True) {
$OS_BITNESS=64
}

$PS_BITNESS=32
if([Environment]::Is64BitProcess -eq $True) {
$PS_BITNESS=64
}

$PK_BITNESS=32
if(($PSScriptRoot.ToLower().Contains("x64".ToLower())) -eq $True) {
$PK_BITNESS=64
}

$arch="x86"
if ($OS_BITNESS -eq 64) {
$arch="x64"
}

$PRODCODE64="{CBEDEC16-C4F5-4255-99E4-5884EFEDD1BC}"
$PRODCODE32="{01DBFF2E-73FD-4CC3-98CE-B39260D80D8C}"
$PRODCODE64_OLD="{B8D3ED8D-A295-44C2-8AE1-56823D44AD1F}"
$PRODCODE32_OLD="{840DE7EE-4816-4402-BEE4-80517B3233A3}"


# ::***********************************************************************************************
# :: Definition-2: common variables and functions
# ::***********************************************************************************************
$PackageName = "LenovoBatteryGaugePackage"
$PathPackageDirDest = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage"
$PathPackageDirSource = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_"

# ::***********************************************************************************************
# :: Definition: Write-Log
$LogFileName = ("$PackageName" + ".Install." + (Get-Date -Format "-yyyy_MM_dd-HH-mm-ss") + ".txt")
$PathLogFile = "$env:ProgramData\Lenovo\Modern\Logs\$LogFileName"

[bool]$EnableLogging = $false
try { $EnableLogging = ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Lenovo\Modern\Logs" -Name "ImController.Service") -eq 0 ) } catch{}

if($EnableLogging -and ( -not(Test-Path $PathLogFile))) {
	New-Item -Path (Split-Path $PathLogFile) -Name (Split-Path $PathLogFile -leaf) -ItemType File -force
}

$PSDefaultParameterValues["Write-Log:pathToLogFile"]=$PathLogFile
$PSDefaultParameterValues["Write-Log:enableLogging"]=$EnableLogging

Function Write-Log
{
    [CmdletBinding()]
    param(
		[Parameter(
			Mandatory=$false,
			Position=1,
			ValueFromPipeline=$true
		)]
		[PSObject[]]$inputObject,
        [string]$pathToLogFile=".\" + [System.IO.Path]::GetFileName($MyInvocation.ScriptName) + ".log",
		[bool]$enableLogging=$true
    )

    $obj=$null
    if($input -ne $null)
    {
        $obj=$input
    }
    else
    {
        $obj=$inputObject
    }

    Out-Host -InputObject $obj
    if($enableLogging)
    {
		$timeStamp = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss  ')
		$objTS = $timeStamp + $obj

	  	Out-File -InputObject $objTS -FilePath $pathToLogFile -Encoding unicode -Append -Width 200
    }
}

Function PrintDestPackageDetails
{
	if($EnableLogging)
	{
		if(Test-Path "$PathPackageDirDest\$arch")
		{
			Get-ChildItem -Path "$PathPackageDirDest\$arch" | Select-Object Name, LastWriteTime, Length | Out-File  $PathLogFile -Encoding unicode -Append
		}
		else
		{
			Write-Log "The dest package dir does not exist($PathPackageDirDest\$arch)"
		}
	}
}


Function UninstallMsi($prodCode)
{
	$uninstallString = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$prodCode" -Name "UninstallString" -ErrorAction SilentlyContinue).UninstallString
	if (($UninstallString -ne $null) -and ($uninstallString.Length -ne 0)) {
		Write-Log "start uninstall msi package for PRODCODE $prodCode"
		$MSIEXECPATH = "$env:SystemRoot\System32\MsiExec.exe"
		Write-Log "Start-Process -NoNewWindow -Wait -FilePath $MSIEXECPATH `"/X$prodCode /quiet /noreboot`""
		Start-Process -NoNewWindow -Wait -FilePath $MSIEXECPATH "/X$prodCode /quiet /noreboot" *>&1 | Write-Log
	}
	else
	{
		Write-Log "cannot find uninstall entry for program PRODCODE $prodCode"
	}
}

Function GetCurrentActiveUserSID
{
	$activeUser = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername -EA stop | Select UserName -Unique|%{"{0}" -f $_.UserName.ToString().Split('\')[1]}
	$objUser = New-Object System.Security.Principal.NTAccount("$activeUser")
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	$strSID.Value
}

Function CheckCVLibrarySignature($moduleFullPathName)
{
	$ASValid = $False
	$ASCheck  =Get-AuthenticodeSignature $moduleFullPathName
	if($ASCheck -ne $null)
	{
		if ( ($ASCheck.Status.ToString()).ToLower() -eq "valid" )
		{
			$ASValid = $True
		}
	}

	if($ASValid -eq $False)
	{
		Exit
	}
}


# ::***********************************************************************************************
# :: Definition: BatteryGaugeIconControl
$applicationName = "$env:SystemRoot\system32\rundll32.exe"
$ShowBg = "ShowBatteryGauge"
$HideBg = "HideBatteryGauge"
$UnloadBg = "UnloadBatteryGaugeFromExplorer"
$InstallFileName = "Install.ps1"
$UninstallFileName = "Uninstall.ps1"

# Check file signature validation

CheckCVLibrarySignature("$PSScriptRoot\Lenovo.CertificateValidation.dll")

Import-Module "$PSScriptRoot\Lenovo.CertificateValidation.dll"

Function IsTrustedAssemblyFile($fullFileName)
{
	 $validRet = [Lenovo.CertificateValidation.FileValidator]::GetTrustStatus($fullFileName)
	 if( ($validRet -eq 0) -or ($validRet -eq "FileTrusted") -or ($validRet -eq [Lenovo.CertificateValidation.TrustStatus]::FileTrusted))
	 {
	 	 return 1
	 }
	 return 0
}


# Notice: ImpersonnateLoggedOnUser in exe
Function BatteryGaugeCtrlByApp($commandName)
{
	# Execute from dest dir
	$pathAppFile = "$PathPackageDirDest\$arch\BGHelper.exe"
	$pathDllFile = "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if((-not(Test-Path -Path "$pathDllFile" -PathType Leaf)) -or (-not(Test-Path -Path "$pathAppFile" -PathType Leaf)))
	{
		# Execute from source dir
		$pathAppFile = "$PathPackageDirSource\$arch\BGHelper.exe"
		$pathDllFile = "$PathPackageDirSource\$arch\LenovoBatteryGaugePackage.dll"
	}

	if((Test-Path -Path "$pathDllFile" -PathType Leaf) -and (Test-Path -Path "$pathAppFile" -PathType Leaf))
	{
		if(IsTrustedAssemblyFile($pathAppFile) -eq 1)
		{
			powershell $pathAppFile $commandName
			if ($? -eq $true)
			{
				Write-Log "BatteryGaugeCtrlByApp OK: ReturnCode=$LastExitCode, CmdName=$commandName"
				return 1
			}
		}
	}

	Write-Log "BatteryGaugeCtrlByApp($commandName) failed! ReturnCode=$LastExitCode"
	return 0
}

# Notice: ImpersonnateLoggedOnUser in dll
Function BatteryGaugeCtrlByRundll32($commandName)
{
	#Param(
	#	[string]$commandName,
	#	[bool]$impersonnateLoggedOnUser = $True
	#)

	# Execute from dest dir
	$pathCmdFile = "$PathPackageDirDest\$arch\$commandName.lnk"
	$pathDllFile = "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if((-not(Test-Path -Path "$pathDllFile" -PathType Leaf)) -or (-not(Test-Path -Path "$pathCmdFile" -PathType Leaf)))
	{
		# Execute from source dir
		$pathCmdFile = "$PathPackageDirSource\$arch\$commandName.lnk"
		$pathDllFile = "$PathPackageDirSource\$arch\LenovoBatteryGaugePackage.dll"
	}

	if((Test-Path -Path "$pathDllFile" -PathType Leaf) -and (Test-Path -Path "$pathCmdFile" -PathType Leaf))
	{
		if(IsTrustedAssemblyFile($pathDllFile) -eq 1)
		{
			# IMPORT: the 'blank space' MUST reserve!!!
			$commandParam = " $pathDllFile, " + $commandName
			powershell $applicationName $commandParam
			if ($? -eq $true)
			{
				Write-Log "BatteryGaugeIconControlEx OK: ReturnCode=$LastExitCode, CmdName=$commandName"
				return 1
			}
		}
	}

	Write-Log "BatteryGaugeIconControlEx($commandName) failed! ReturnCode=$LastExitCode"
	return 0
}

Function BatteryGaugeIconControlEx($commandName)
{
	$BGCtrlRet = BatteryGaugeCtrlByRundll32($commandName)
	if ($BGCtrlRet -eq 0)
	{
		$BGCtrlRet = BatteryGaugeCtrlByApp($commandName)	
	}

	return $BGCtrlRet
}

# ::***********************************************************************************************
# :: Definition: expand shortcut file
$PathShortCutDir = "$PSScriptRoot\.."
if( -not(Test-Path $PathShortCutDir) ) {
	$PathShortCutDir = $PathPackageDirDest
	if($true -eq ((($PSCommandPath).ToUpper()).Contains("LENOVOBATTERYGAUGEPACKAGE_"))){
		$PathShortCutDir = $PathPackageDirSource
	}
}

Function Expand-EnvironmentVariablesForLnkFile
{
    param([string]$modulePlatform, [string]$moduleFunction)

	if( -not(Test-Path "$PathShortCutDir\$modulePlatform") ) {
		return
	}

    $shortCutFile = "$PathShortCutDir\$modulePlatform\$moduleFunction" + ".lnk"
	$argumentsList = "$PathPackageDirDest\$modulePlatform\LenovoBatteryGaugePackage.dll," + $moduleFunction
	$workingDir = "$PathPackageDirDest\$modulePlatform\"

    $wScriptShell = New-Object -ComObject WScript.Shell 
    $shortCut = $wScriptShell.CreateShortcut($shortCutFile) 
    $shortCut.TargetPath = [Environment]::ExpandEnvironmentVariables($applicationName)
    $shortCut.Arguments = [Environment]::ExpandEnvironmentVariables($argumentsList)
    $shortCut.WorkingDirectory = [Environment]::ExpandEnvironmentVariables($workingDir)
    $shortCut.Save() 
}

Function Expand-EnvironmentVariablesForLnkFileEx
{
	param([string]$moduleFunction)

	Expand-EnvironmentVariablesForLnkFile "x86" $moduleFunction
	Expand-EnvironmentVariablesForLnkFile "x64" $moduleFunction
}


# Kill BG processes directly. Only call when necessary.
Function StopBGProcessDirectly
{
	Write-Log "Kill BG related processes, which run from: `"$PathPackageDirDest`" "
	
	(Get-Process | Select-Object Path,Id,Name | Where-Object {$_.Path -Ilike "$PathPackageDirDest*"}) | Stop-Process -Force
}

Function StopProcessByTaskkill
{
	Write-Log "Kill BG special processes if running"
	$TaskkillPath = "$env:SystemRoot\System32\taskkill.exe"

	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM HeartbeatMetrics.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM IdeaIntelligentCoolingMetrics.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM QuickSetting.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM QuickSettingEx.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM QSHelper.exe"
}


# BG should be excluded when device satisfies: {China + Lenovo/Idea brand + PCManager installed}
Function BatteryGaugeShouldBeExclude
{
    $IsExclude = $False

    $miVantagePath = "$env:LOCALAPPDATA\Packages\E046963F.LenovoCompanion_k1h2ywk1493x8"
	$miVantageMVPPath = "$env:LOCALAPPDATA\Packages\E046963F.LenovoCompanionBeta_k1h2ywk1493x8"
    $miLEPath = "$env:LOCALAPPDATA\Packages\E046963F.LenovoSettingsforEnterprise_k1h2ywk1493x8"
    $IsInstallVantageLE = ((Test-Path $miVantagePath) -or (Test-Path $miVantageMVPPath) -or (Test-Path $miLEPath))
    if(-not($IsInstallVantageLE))
    {
        $miXmlFilePath = "$env:ProgramData\Lenovo\ImController\shared\MachineInformation.xml"

        $miXmlData = [xml](Get-Content $miXmlFilePath)
        $miCountry = ($miXmlData.MachineInformation.Country).ToLower()
        if($miCountry.Contains("cn"))
        {
            $miBrand = ($miXmlData.MachineInformation.Brand).ToLower()            
            $IsExclude = (($miBrand.Contains("idea")) -or ($miBrand.Contains("lenovo")))
        }

    }
    
    if($IsExclude)
    {
        #Is PCManager installed?
		$PcManagerRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lenovo\PcManager'
		$IsExclude = (Test-Path "Registry::$PcManagerRegPath")
    }

    return $IsExclude
}

# BG is installed?
Function BatteryGaugeIsInstalled
{
    $IsInstalled = $False
	$BGRegistryPath = 'HKEY_CLASSES_ROOT\CLSID\{E303DE81-073F-438A-B0D3-11C27526F607}'
	if(Test-Path "Registry::$BGRegistryPath")
	{
		$IsInstalled = $True
	}

    return $IsInstalled
}

# BG is pinned in taskbar?
Function IsBatteryGaugePinInTaskbar
{
	$IsBGPinned = 0

	$BgTaskList = tasklist /M "LenovoBatteryGaugePackage.dll"
	$ExplorerLike = $BgTaskList -like "explorer*"
	if($ExplorerLike -eq $true)
	{  
		$IsBGPinned = 1  
	}
	elseif($ExplorerLike -ne $false)
	{
		$BgInExplorer = (($ExplorerLike).ToLower()).Contains("explorer")
		if($BgInExplorer -eq $true)
		{  
			$IsBGPinned = 1  
		}
	}

	return $IsBGPinned
}



$RegSvr32Path = "$env:SystemRoot\System32\regsvr32.exe"
$RegAsmPath = "$PathPackageDirDest\$arch\RegAsm.exe"

# ::***********************************************************************************************
# :: Register new Lenovo Battery Gauge: PluginsContract.dll, LenovoBatteryGaugePackage.dll
# ::***********************************************************************************************
Function RegisterNewBatteryGauge
{
	# check directory first!!!!
	#Start-Process -NoNewWindow -Wait -FilePath $RegAsmPath -ArgumentList "/silent $PathPackageDirDest\$arch\PluginsContract.dll"
	powershell $RegAsmPath "/silent $PathPackageDirDest\$arch\PluginsContract.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegAsmPath `"/silent $PathPackageDirDest\$arch\PluginsContract.dll`""
	}

	#Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList "/s $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	powershell $RegSvr32Path "/s $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegSvr32Path `"/s $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll`""
	}
}


# ::***********************************************************************************************
# Unregister new Lenovo Battery Gauge: LenovoBatteryGaugePackage.dll, PluginsContract.dll
# ::***********************************************************************************************
Function UnregisterNewBatteryGauge
{
	# check directory first!!!!
	#Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList "/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	powershell $RegSvr32Path "/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegSvr32Path `"/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll`""
	}

	#Start-Process -NoNewWindow -Wait -FilePath $RegAsmPath -ArgumentList "/silent /u $PathPackageDirDest\$arch\PluginsContract.dll"
	powershell $RegAsmPath "/silent /u $PathPackageDirDest\$arch\PluginsContract.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegAsmPath `"/silent /u $PathPackageDirDest\$arch\PluginsContract.dll`""
	}
}


# ::***********************************************************************************************
# Uninstall old Lenovo Battery Gauge(which install by MSI). 
# Notice: It does not exist in most Win10 devices now. So handle it with low priority.
# ::***********************************************************************************************
Function UninstallMsiOldBatteryGauge
{
	if (Get-Variable ProdCode64 -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode64)
	}
	if (Get-Variable ProdCode32 -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode32)
	}
	if (Get-Variable ProdCode64_OLD -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode64_OLD)
	}
	if (Get-Variable ProdCode32_OLD -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode32_OLD)
	}
}


# ::***********************************************************************************************
# Register exe MaintenanceTask 
# ::***********************************************************************************************
Function RegisterMaintenanceTask
{
	# Delete ps1 MaintenanceTask if exist. 
	$SchTasksPath = "$env:SystemRoot\System32\schtasks.exe"
	#if( Test-Path -Path "$PathPackageDirDest\data\Maintenance.ps1" -PathType Leaf )
	#{
		powershell $SchTasksPath /Delete /TN "\Lenovo\BatteryGauge\BatteryGaugeMaintenance" /F
		if($? -eq $true)
		{
			if( Test-Path -Path "$PathPackageDirDest\data\Maintenance.ps1" -PathType Leaf )
			{
				Remove-Item -Path "$PathPackageDirDest\data\Maintenance.ps1"
			}
		}
	#}

	# Register exe MaintenanceTask. check directory first!!!!
	$PathMaintenanceTask = $PathPackageDirDest
	if ($PSScriptRoot -ne "$PathPackageDirDest\$arch")
	{$PathMaintenanceTask = $PathPackageDirSource}

	powershell $SchTasksPath /Create /XML "$PathMaintenanceTask\data\MaintenanceTask.xml" /TN "\Lenovo\BatteryGauge\BatteryGaugeMaintenance"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, $SchTasksPath /Create /XML `"$PathMaintenanceTask\data\MaintenanceTask.xml`" /TN `"\Lenovo\BatteryGauge\BatteryGaugeMaintenance`""
	}
}


# ::***********************************************************************************************
# :: Rename to ensure file update successful
# ::***********************************************************************************************
Function RenameFileForUpdate
{
	param([string]$fileName)

	$fileNameBK = $fileName + "_bk"
	if( Test-Path -Path "$PathPackageDirDest\x86\$fileNameBK" -PathType Leaf)
	{
		Remove-Item -Path "$PathPackageDirDest\x86\$fileNameBK" -Force
	}
	Rename-Item -Path "$PathPackageDirDest\x86\$fileName" -NewName "$fileNameBK"

	if( Test-Path -Path "$PathPackageDirDest\x64\$fileNameBK" -PathType Leaf)
	{
		Remove-Item -Path "$PathPackageDirDest\x64\$fileNameBK" -Force
	}	
	Rename-Item -Path "$PathPackageDirDest\x64\$fileName" -NewName "$fileNameBK"
}

Function RenameFileBack
{
	param([string]$fileNameSrc)

	$fileNameSrcBK = $fileNameSrc + "_bk"
	if( -not(Test-Path -Path "$PathPackageDirDest\x86\$fileNameSrc" -PathType Leaf) )
	{
		Rename-Item -Path "$PathPackageDirDest\x86\$fileNameSrcBK" -NewName "$fileNameSrc"
	}

	if( -not(Test-Path -Path "$PathPackageDirDest\x64\$fileNameSrc" -PathType Leaf) )
	{
		Rename-Item -Path "$PathPackageDirDest\x64\$fileNameSrcBK" -NewName "$fileNameSrc"
	}
}

# ::***********************************************************************************************
# :: use "Trap" to handle terminating error( to force script running )
# ::***********************************************************************************************
trap 
{
	"An error trapped"
	$TrapError = $_.Exception
	$TrapErrorMsg = $TrapError.Message 
	$TrapLine = $_.InvocationInfo.ScriptLineNumber	
	Write-Log "Caught exception( trapped error ) at line[$TrapLine]: Msg= $TrapErrorMsg"
}

# ::***********************************************************************************************
# :: Begin installation
# ::
# :: 
# ::***********************************************************************************************

Write-Log "Below logs come from: $PSCommandPath"

Write-Log "Register MaintenanceTask if necessary"
RegisterMaintenanceTask


# BG should be excluded from this device?
$BgInstalled = BatteryGaugeIsInstalled
if(BatteryGaugeShouldBeExclude)
{
	Write-Log "Exit... BatteryGauge should be excluded from device whom brand is Lenovo or Idea and PCManager has been installed(Geo = China(PRC))"

	# Delete BG if it has been installed
	if($BgInstalled -eq $True)
	{
		if (Test-Path "$PathPackageDirDest\$arch\$UninstallFileName")
		{
			Write-Log "Begin to uninstall BatteryGauge in the device which has installed PCManager...."
			$PSPATH="$env:SystemRoot\System32\WindowsPowerShell\v1.0\PowerShell.exe"
			Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PSPATH -ArgumentList `"$PathPackageDirDest\$arch\$UninstallFileName`""
			Start-Process -NoNewWindow -Wait -FilePath $PSPATH -ArgumentList "$PathPackageDirDest\$arch\$UninstallFileName" *>&1 | Write-Log
		}
	}
		
	Exit
}

# Does package match OS bitness???
Write-Log "OperatingSystem=[$OS_BITNESS bit], Process=[$PS_BITNESS bit], Package=[$PK_BITNESS bit]"
if ($PS_BITNESS -eq 32)
{
	if ($PK_BITNESS -eq 64)
	{
		if ($OS_BITNESS -eq 32)
		{
			Write-Log "cannot install a 64 bit package in an 32 bit os."
		}
		else
		{
			Write-Log "Package bitness is 64 but process is 32.  Relaunching as 64"
			$PS64BITPATH="$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\PowerShell.exe"
			Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PS64BITPATH -ArgumentList `"$PSCommandPath`""
			Start-Process -NoNewWindow -Wait -FilePath $PS64BITPATH -ArgumentList "$PSCommandPath" *>&1 | Write-Log
			Write-Log "Completed re-running as 64 bit"
			Exit
		}
	}
}
elseif ($PS_BITNESS -eq 64)
{
	if ($PK_BITNESS -eq 32)
	{
		Write-Log "Package bitness is 32 but process is 64.  Relaunching as 32"
		$PS32BITPATH="$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\PowerShell.exe"
		Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PS32BITPATH -ArgumentList `"$PSCommandPath`""
		Start-Process -NoNewWindow -Wait -FilePath $PS32BITPATH -ArgumentList "$PSCommandPath" *>&1 | Write-Log
		Write-Log "Completed re-running as 32 bit"
		Exit
	}
}
else
{
	Write-Log "Package bitness unknown, will exit."
}


# ::***********************************************************************************************
# Expand shortcut with absolute path for BG control
# ::***********************************************************************************************
Expand-EnvironmentVariablesForLnkFileEx "ShowBatteryGauge"
Expand-EnvironmentVariablesForLnkFileEx "HideBatteryGauge"
Expand-EnvironmentVariablesForLnkFileEx "UnpinFromTaskbar"
Expand-EnvironmentVariablesForLnkFileEx "UnloadBatteryGaugeFromExplorer"
Expand-EnvironmentVariablesForLnkFileEx "SetMenuItemNameofBatteryGauge"
Expand-EnvironmentVariablesForLnkFileEx "UpdateBatteryGaugeToastInfo"
Expand-EnvironmentVariablesForLnkFileEx "LaunchPinVantageToolbarToast"

# ::***********************************************************************************************
# :: [Kill active BG processes]:
# ::  QuickSetting.exe,QuickSettingEx.exe,HeartbeatMetrics.exe,SetThinkTouchPad.exe....]
# ::***********************************************************************************************
#StopBGProcessDirectly


# ::***********************************************************************************************
# :: [Uninstall old Lenovo Battery Gauge ]
# ::***********************************************************************************************
Write-Log "Uninstall old Lenovo Battery Gauge(which install by MSI). It might not exist"
UninstallMsiOldBatteryGauge


#::***********************************************************************************************
#:: [Check whether pinned battery gauge to taskbar previously]
#::***********************************************************************************************
$Pinned = 0
$SID = GetCurrentActiveUserSID	
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$BgPinReg = (Get-ItemProperty -Path HKU:$SID\SOFTWARE\Lenovo\BatteryGauge -Name "ShowInTaskbar" -ErrorAction SilentlyContinue).ShowInTaskbar
	
## Is BG pinned ? Check it in taskbar
$BgPinTaskbar = IsBatteryGaugePinInTaskbar	
if(($BgPinReg -eq 1) -or ($BgPinTaskbar -eq 1))
{
	$Pinned = 1
}

Write-Log "The BatteryGauge current display status: BgPinReg = $BgPinReg, BgPinTaskbar=$BgPinTaskbar"
#Remove-PSDrive -Name HKU


# ::**************************************************************************************************
# :: This section run only when current scripts running in package folder
# ::    1. Call uninstall.ps1 in the package folder if it has been install in this PC, and then delete package folder
# ::    2. Create package folder and copy content to it
# ::    3. Call install.ps1 in the package folder
# :: 
# ::**************************************************************************************************
if ($PSScriptRoot -ne "$PathPackageDirDest\$arch")
{
	trap {"An error trapped 2..."}

	Write-Log "Details of dest package info(old version)-------------------------"
	PrintDestPackageDetails
	
	#::***********************************************************************************************
	#:: [Uninstall the old version]
	#::***********************************************************************************************
	if (Test-Path "$PathPackageDirDest\$arch\$UninstallFileName")
	{
		trap {"An error trapped 3..."}

		Write-Log "Uninstall old version directly"
		Write-Log "Push-Location `"$PathPackageDirDest\$arch\`""
		Push-Location "$PathPackageDirDest\$arch\"
		
		Write-Log "Unload BatteryGauge from explorer"
		BatteryGaugeIconControlEx($UnloadBg)
		
		if ($Pinned -eq 1)
		{
			Write-Log "Keep BG status in registry if necessary, PinStatus=$Pinned"
			#$SID = GetCurrentActiveUserSID
			
			#New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
			New-ItemProperty -Path HKU:$SID\SOFTWARE\Lenovo\BatteryGauge -Name "ShowInTaskbar" -Value $Pinned -PropertyType DWORD -Force		
			#Remove-PSDrive -Name HKU
		}

		Write-Log "Unregister BatteryGauge related components"
		UnregisterNewBatteryGauge

		Write-Log "Pop-Location"
		Pop-location
		
		Write-Log "Uninstall completely! Kill related BG processes"
		StopBGProcessDirectly

		# try again
		StopProcessByTaskkill
		# don't remove old version files!!!
		#Write-Log "Remove-Item -Recurse -Force `"$PathPackageDirDest`""
		#Remove-Item -Recurse -Force "$PathPackageDirDest"
	}

	## ::************************************************************************************************
	## :: [Rename the LenovoBatteryGaugePackage.dll file if this file haven't been removed. There was   ]
	## :: [issue which will lead this dll cannot unload from explorer due to in-use, then cannot replace]
	## :: [Can remove this operation from next version, since already fixed the in-use issue in the dll ]
	## ::************************************************************************************************
	if(Test-Path -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll" -PathType Leaf)
	{
		$BgPinTaskbar = IsBatteryGaugePinInTaskbar	
		Write-Log "Some files might still exist, such as BG main dll. Rename it to avoid copy files failure"
		RenameFileForUpdate "LenovoBatteryGaugePackage.dll"
		RenameFileForUpdate "Lenovo.AssemblyValidation.Native.dll"
		RenameFileForUpdate "Lenovo.CertificateValidation.dll"
		RenameFileForUpdate "QuickSetting.exe"
		RenameFileForUpdate "QuickSettingEx.exe"
		RenameFileForUpdate "QSHelper.exe"
		RenameFileForUpdate "HeartbeatMetrics.exe"
		RenameFileForUpdate "IdeaIntelligentCoolingMetrics.exe"
		RenameFileForUpdate "Lenovo.ImController.EventLogging.dll"
		RenameFileForUpdate "Lenovo.Modern.CoreTypes.dll"
		RenameFileForUpdate "Lenovo.Modern.ImController.ImClient.dll"
		RenameFileForUpdate "Lenovo.Modern.Utilities.dll"
		RenameFileForUpdate "Newtonsoft.Json.dll"


		if($BgPinTaskbar -eq 1)
		{
			Start-Sleep -Milliseconds 1200
		}
	}
	

	#::***********************************************************************************************
	#:: [Copy new version to dest directory]
	#::***********************************************************************************************
	Write-Log "Make package folder for new version"
	Write-Log "New-Item `"$PathPackageDirDest\`" -type directory"
	New-Item "$PathPackageDirDest\" -type directory

	# Copy source files to destination directory
	Write-Log "Copy new version package contents to package folder, and give neccessary privileage"
	Write-Log "Copy-Item `"$PSScriptRoot\..\*`" `"$PathPackageDirDest\`" -force -recurse"
	Copy-Item "$PSScriptRoot\..\*" "$PathPackageDirDest\" -force -recurse
	if($? -ne $true)
	{
		Write-Log "Copy-Item error... error code is: $LastExitCode"
	}

	# Preserve old version again, if copy failed or the new source files was deleted unexpectedly
	Write-Log "Preserve old version again, if copy failed"
	RenameFileBack "LenovoBatteryGaugePackage.dll"
	RenameFileBack "Lenovo.AssemblyValidation.Native.dll"
	RenameFileBack "Lenovo.CertificateValidation.dll"
	RenameFileBack "QuickSetting.exe"
	RenameFileBack "QuickSettingEx.exe"
	RenameFileBack "QSHelper.exe"
	RenameFileBack "HeartbeatMetrics.exe"
	RenameFileBack "IdeaIntelligentCoolingMetrics.exe"
	RenameFileBack "Lenovo.ImController.EventLogging.dll"
	RenameFileBack "Lenovo.Modern.CoreTypes.dll"
	RenameFileBack "Lenovo.Modern.ImController.ImClient.dll"
	RenameFileBack "Lenovo.Modern.Utilities.dll"
	RenameFileBack "Newtonsoft.Json.dll"


	Write-Log "Install new version directly"
	Write-Log "Push-Location `"$PathPackageDirDest\$arch\`""
	Push-Location "$PathPackageDirDest\$arch\"
	
	Write-Log "Register BatteryGauge related components"
	RegisterNewBatteryGauge

	Write-Log "Show BatteryGauge if neccessary: PinStatus = $Pinned"
	if ($Pinned -eq 1)
	{
		BatteryGaugeIconControlEx($ShowBg)
	}

	Write-Log "Pop-location"
	Pop-location
	
	Write-Log "Install completely! Remove the temporary install package folder"
	Write-Log "Remove-Item -Recurse -Force `"$PSScriptRoot\..`""
	Remove-Item -Recurse -Force "$PSScriptRoot\.."
	
	#Write-Log "Uninstall old Lenovo Battery Gauge(which install by MSI). It might not exist"
	#UninstallMsiOldBatteryGauge

	Write-Log "Details of dest package info(new version)-------------------------"
	PrintDestPackageDetails
	
	Remove-PSDrive -Name HKU

	Write-Log "Update-Install sucessful!"
	Exit
}


# ::***********************************************************************************************
# :: [Register PluginsContract.dll,Register LenovoBatteryGaugePackage.dll ]
# ::***********************************************************************************************
Write-Log "Register BatteryGauge related components"
RegisterNewBatteryGauge


# ::***********************************************************************************************
# :: [ Pin to task bar if needed]
# ::***********************************************************************************************
Write-Log "installing param is: $Pinned"
if ($Pinned -eq 1)
{
	$retCtrl = BatteryGaugeIconControlEx($ShowBg)
	if($retCtrl -eq 0)
	{
		Write-Log "Try to show BatteryyGauge again..., ReturnCode=$LastExitCode"
		Start-Sleep -Milliseconds 400	
		$retCtrl = BatteryGaugeIconControlEx($ShowBg)
	}
	Write-Log "Show BatteryGauge on taskbar, show = $retCtrl, ReturnCode=$LastExitCode"
}


Remove-PSDrive -Name HKU

Write-Log "Install sucessful!"
Exit

# SIG # Begin signature block
# MIIeBgYJKoZIhvcNAQcCoIId9zCCHfMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCf3acKRZzs3G45
# tWsGUMLzi6npH3Wlq2SzDzszn8OhGaCCGNwwggSZMIIDgaADAgECAhBNFlUhGoem
# rvEW+464AME4MA0GCSqGSIb3DQEBCwUAMIGEMQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0
# IE5ldHdvcmsxNTAzBgNVBAMTLFN5bWFudGVjIENsYXNzIDMgU0hBMjU2IENvZGUg
# U2lnbmluZyBDQSAtIEcyMB4XDTIwMTEwNjAwMDAwMFoXDTIxMTEwNzIzNTk1OVow
# bDELMAkGA1UEBhMCVVMxFzAVBgNVBAgMDk5vcnRoIENhcm9saW5hMRQwEgYDVQQH
# DAtNb3JyaXN2aWxsZTEPMA0GA1UECgwGTGVub3ZvMQwwCgYDVQQLDANHMDgxDzAN
# BgNVBAMMBkxlbm92bzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKYO
# U8/glGZ9w+49XZs0S9EYwBinZ8dn3WTBd4uMlwQYFmt7BwgqflvhbXXO1KEoa9aZ
# ZP+bgBnRRTgnOK0P7ffH+eh88sSpBGxLrkhXAB953fdvLlfnat6d4254N7CySRNr
# MU4CFX+nohd2K0xgTsGmS0Kd18ipzzwTc7asiogbE4M9IC5tnlhLXntnYuzSRBZ+
# Ifq5ePpH78/nNPcSARsf04z67+yKqwA3QxNqWlTugfMX5dmzVwmRY7WeFw5R8abE
# hlLt9z2QD0AE1c2r5pNfPmAQCQhl4CqaOgXoGHzDFUZ/oSsJU2tKgad4+01x0HGH
# +71qtiiHKbu3YFmQth0CAwEAAaOCARwwggEYMAkGA1UdEwQCMAAwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMD8GA1UdIAQ4MDYwNAYGZ4EMAQQB
# MCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHwYD
# VR0jBBgwFoAU1MAGIknrOUvdk+JcobhHdglyA1gwKwYDVR0fBCQwIjAgoB6gHIYa
# aHR0cDovL3JiLnN5bWNiLmNvbS9yYi5jcmwwVwYIKwYBBQUHAQEESzBJMB8GCCsG
# AQUFBzABhhNodHRwOi8vcmIuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8v
# cmIuc3ltY2IuY29tL3JiLmNydDANBgkqhkiG9w0BAQsFAAOCAQEAR4EfcLqvuGkh
# gdAXOEEnyx67Ojc9+30/qq78x9+cA6ezFAC3bjUVdKnuR8q/8FK+8sVRDGgCH47k
# 6Z26Vi/svWTvk6F+tZPhzfbcLTWCwBaAgUs9DhbsrzVCqCrJy7CCy11Wv7FKp8Pa
# ciank1I4MBD7/cWhSleFHE/+0ctTt9LUm7fixNKB4idBgTSxUmG7aJSz0w7CKg66
# pyj7H7cohNEuMCHUVtBZUEYIKmcqUC8JdHS+4RtLWgpR/99ak4qy27MmCjDuApce
# JSnKvdOxP1fvIEKIW10WoGW0CSR9XEtcaRRn0AF4CHLYgkfoZjfNYamgyvLkIoVa
# 9nZBXsIh2DCCBLkwggOhoAMCAQICEEAaxGQhsxMhAw675BIaxR0wDQYJKoZIhvcN
# AQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEf
# MB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIw
# MDggVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE4MDYG
# A1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkwHhcNMDgwNDAyMDAwMDAwWhcNMzcxMjAxMjM1OTU5WjCBvTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2ln
# biBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5j
# LiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBV
# bml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAMdhN16xATTbYtcVm/9YWowjI9ZgjpHXkJiD
# euZYGTiMxfblZIW0onH77b252s1NALTILXOlx2lxlR85PLJEB5zoDvpNSsQh3ylh
# jzIiYYLFhx9ujHxfFiBRRNFwT1fq4xzjzHnuWNgOwrNFk8As55oXK3sAN3pBM3jh
# M+LzEBp/hyy+9vX3QuLlv4diiV8AS9/F3eR1RDJBOh5xbmnLC3VGCNHK0iuV0M/7
# uUBrZIxXTfwTEXmE7V5U9jSfCAHzECUGF0ra8R16ZmuYYGak2e/SLoLx8O8J6kTJ
# FWriA24z06yfVQDH9ghqlLlf3OAz8YRg+VsnEbT8FvK7VmqAJY0CAwEAAaOBsjCB
# rzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARh
# MF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvD
# z4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdp
# ZjAdBgNVHQ4EFgQUtnf6aUhHn1MS1cLqBzJ2B9GXBxkwDQYJKoZIhvcNAQELBQAD
# ggEBAEr4+LAD5ixne+SUd2PMbkz5fQ4N3Mi5NblwT2P6JPpsg4xHnTtj85r5djKV
# kbF3vKyavrHkMSHGgZVWWg6xwtSxplms8WPLuEwdWZBK75AWKB9arhD7gVA4DGzM
# 8T3D9WPjs+MhySQ56f0VZkb0GxHQTXOjfUb5Pe2oX2LU8T/44HRXKxidgbTEKNqU
# l6Vw66wdvgcR8NXb3eWM8NUysIPmV+KPv76hqr89HbXUOOrXsFw6T2o/j8BmbGOq
# 6dmkFvSB0ZUUDn3NlTTZ0o9wc4F7nH69mGHYRYeYkMXrhjDGNb/w/8NViINL7wWS
# BnHyuJiTt+zNgmHxOOZPl5gqWo0wggT+MIID5qADAgECAhANQkrgvjqI/2BAIc4U
# APDdMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwHhcNMjEwMTAx
# MDAwMDAwWhcNMzEwMTA2MDAwMDAwWjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIx
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuZhhGfFivUNCKRFymNr
# Udc6EUK9CnV1TZS0DFC1JhD+HchvkWsMlucaXEjvROW/m2HNFZFiWrj/ZwucY/02
# aoH6KfjdK3CF3gIY83htvH35x20JPb5qdofpir34hF0edsnkxnZ2OlPR0dNaNo/G
# o+EvGzq3YdZz7E5tM4p8XUUtS7FQ5kE6N1aG3JMjjfdQJehk5t3Tjy9XtYcg6w6O
# LNUj2vRNeEbjA4MxKUpcDDGKSoyIxfcwWvkUrxVfbENJCf0mI1P2jWPoGqtbsR0w
# wptpgrTb/FZUvB+hh6u+elsKIC9LCcmVp42y+tZji06lchzun3oBc/gZ1v4NSYS9
# AQIDAQABo4IBuDCCAbQwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwQQYDVR0gBDowODA2BglghkgBhv1sBwEwKTAn
# BggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB8GA1UdIwQY
# MBaAFPS24SAd/imu0uRhpbKiJbLIFzVuMB0GA1UdDgQWBBQ2RIaOpLqwZr68KC0d
# RDbd42p6vDBxBgNVHR8EajBoMDKgMKAuhixodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vc2hhMi1hc3N1cmVkLXRzLmNybDAyoDCgLoYsaHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwgYUGCCsGAQUFBwEBBHkwdzAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME8GCCsGAQUFBzAChkNo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElE
# VGltZXN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQBIHNy16ZojvOca
# 5yAOjmdG/UJyUXQKI0ejq5LSJcRwWb4UoOUngaVNFBUZB3nw0QTDhtk7vf5EAmZN
# 7WmkD/a4cM9i6PVRSnh5Nnont/PnUp+Tp+1DnnvntN1BIon7h6JGA0789P63ZHdj
# XyNSaYOC+hpT7ZDMjaEXcw3082U5cEvznNZ6e9oMvD0y0BvL9WH8dQgAdryBDvjA
# 4VzPxBFy5xtkSdgimnUVQvUtMjiB2vRgorq0Uvtc4GEkJU+y38kpqHNDUdq9Y9Yf
# W5v3LhtPEx33Sg1xfpe39D+E68Hjo0mh+s6nv1bPull2YYlffqe0jmd4+TaY4cso
# 2luHpoovMIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# VGltZXN0YW1waW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# vdAy7kvNj3/dqbqCmcU5VChXtiNKxA4HRTNREH3Q+X1NaH7ntqD0jbOI5Je/YyGQ
# mL8TvFfTw+F+CNZqFAA49y4eO+7MpvYyWf5fZT/gm+vjRkcGGlV+Cyd+wKL1oODe
# Ij8O/36V+/OjuiI+GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr4M8iEA91z3FyTgqt
# 30A6XLdR4aF5FMZNJCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZuVmEnKYmEUeaC50ZQ
# /ZQqLKfkdT66mA+Ef58xFNat1fJky3seBdCEGXIX8RcG7z3N1k3vBkL9olMqT4Ud
# xB08r8/arBD13ays6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0OBBYEFPS24SAd/imu
# 0uRhpbKiJbLIFzVuMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqg
# OKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRBc3N1cmVkSURSb290Q0EuY3JsMFAGA1UdIARJMEcwOAYKYIZIAYb9bAACBDAq
# MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAsGCWCG
# SAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN793afKpjerN4zwY3
# QITvS4S/ys8DAv3Fp8MOIEIsr3fzKx8MIVoqtwU0HWqumfgnoma/Capg33akOpMP
# +LLR2HwZYuhegiUexLoceywh4tZbLBQ1QwRostt1AuByx5jWPGTlH0gQGF+JOGFN
# YkYkh2OMkVIsrymJ5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tTYYmo9WuWwPRYaQ18
# yAGxuSh1t5ljhSKMYcp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhgm7oMLSttosR+u8Ql
# K0cCCHxJrhO24XxCQijGGFbPQTS2Zl22dHv1VjMiLyI2skuiSpXY9aaOUjCCBUcw
# ggQvoAMCAQICEHwbNTVK59t050FfEWnKa6gwDQYJKoZIhvcNAQELBQAwgb0xCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVy
# aVNpZ24gVHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24s
# IEluYy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNp
# Z24gVW5pdmVyc2FsIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQw
# NzIyMDAwMDAwWhcNMjQwNzIxMjM1OTU5WjCBhDELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
# dCBOZXR3b3JrMTUwMwYDVQQDEyxTeW1hbnRlYyBDbGFzcyAzIFNIQTI1NiBDb2Rl
# IFNpZ25pbmcgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# ANeVQ9Tc32euOftSpLYmMQRw6beOWyq6N2k1lY+7wDDnhthzu9/r0XY/ilaO6y1L
# 8FcYTrGNpTPTC3Uj1Wp5J92j0/cOh2W13q0c8fU1tCJRryKhwV1LkH/AWU6rnXmp
# AtceSbE7TYf+wnirv+9SrpyvCNk55ZpRPmlfMBBOcWNsWOHwIDMbD3S+W8sS4duM
# xICUcrv2RZqewSUL+6McntimCXBx7MBHTI99w94Zzj7uBHKOF9P/8LIFMhlM07Ac
# n/6leCBCcEGwJoxvAMg6ABFBekGwp4qRBKCZePR3tPNgKuZsUAS3FGD/DVH0qIuE
# /iHaXF599Sl5T7BEdG9tcv8CAwEAAaOCAXgwggF0MC4GCCsGAQUFBwEBBCIwIDAe
# BggrBgEFBQcwAYYSaHR0cDovL3Muc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRw
# czovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3lt
# Y2IuY29tL3JwYTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vcy5zeW1jYi5jb20v
# dW5pdmVyc2FsLXJvb3QuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB
# /wQEAwIBBjApBgNVHREEIjAgpB4wHDEaMBgGA1UEAxMRU3ltYW50ZWNQS0ktMS03
# MjQwHQYDVR0OBBYEFNTABiJJ6zlL3ZPiXKG4R3YJcgNYMB8GA1UdIwQYMBaAFLZ3
# +mlIR59TEtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUAA4IBAQB/68qn6ot2Qus+
# jiBUMOO3udz6SD4Wxw9FlRDNJ4ajZvMC7XH4qsJVl5Fwg/lSflJpPMnx4JRGgBi7
# odSkVqbzHQCR1YbzSIfgy8Q0aCBetMv5Be2cr3BTJ7noPn5RoGlxi9xR7YA6JTKf
# RK9uQyjTIXW7l9iLi4z+qQRGBIX3FZxLEY3ELBf+1W5/muJWkvGWs60t+fTf2omZ
# zrI4RMD3R3vKJbn6Kmgzm1By3qif1M0sCzS9izB4QOCNjicbkG8avggVgV3rL+JR
# 51EeyXgp5x5lvzjvAUoBCSQOFsQUecFBNzTQPZFSlJ3haO8I8OJpnGdukAsak3HU
# JgLDwFojMYIEgDCCBHwCAQEwgZkwgYQxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRT
# eW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0
# d29yazE1MDMGA1UEAxMsU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWdu
# aW5nIENBIC0gRzICEE0WVSEah6au8Rb7jrgAwTgwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgFC9ETB5Hh+sGuqvQccgUf6eLjUPFgIHh7zq4AMbuv1kwDQYJKoZIhvcNAQEB
# BQAEggEAovnmDIxecy2V8SLwNJzuM9kubaM0gzIG9IAxaYBFLls1vkclGApq+3Ry
# 4eYdqPZt3GdeQnd8HVyWXkGSJ21Id0MLqbvj4KJLXR9r6bbXMbdPpJ8oShWGKcxP
# itwZFQb4JNbCNUBDbaNQ784YzSeTiHuYg3DR1yV22HW0Gzkyp3M0XUlb1oomgjM9
# nmfhTi4uap7MIzVzikz+hohebxa0Xo0JUarT+thGu5UEkpKTIDMnRGkqODHJBn+N
# 9PNAhWxrgw54EnUefcHUWRP9MoQuji0LuwClPiHhUBxDfZ46CJfYRtoD3nwQ5GCP
# s88YE/TEVtVzGGaeE8FA1CLp9Ud/KqGCAjAwggIsBgkqhkiG9w0BCQYxggIdMIIC
# GQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEy
# IEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhANQkrgvjqI/2BAIc4UAPDdMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjEwNTE5MTI1MTAzWjAvBgkqhkiG9w0BCQQxIgQgC3E3Xd9UhDUv
# RGSF+8pHxZUQicbuf6VGd5CDnNuwIjEwDQYJKoZIhvcNAQEBBQAEggEAJlda36NI
# 94FtZ44WMa4pz6SCFEqDKAucTgld0nT4dvPGzOt7E/lztAvxVu3DvfkmMXy+BYBt
# bUqpXDp+1GpWkB/M++28vYK6oP+858rJ5mpNJZcj7a8I+0z2DKeEBuAvxP28OhQJ
# 7NEsVbuSJHV3g+e+oS4BoXpSLnH72eW2meay+ELwyRcWZsRyFAfCH0ugR3qIVwEb
# SJ55B93EmW66T5p2PiifcJSsgDNL2LCYMRLisSF98w/6gdV3tgob7Xml4uOoFFYH
# V5N/OOuM2nTFAt6SFQY7NMo7VfM+N74m1uppHF1FCKKyf6Ssxt4igJl2YqIvg0yb
# JRAeCQhntTIWdQ==
# SIG # End signature block
