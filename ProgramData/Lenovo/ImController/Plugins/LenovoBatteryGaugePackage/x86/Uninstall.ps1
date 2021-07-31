trap {"An error trapped..."}


$PackageName = "LenovoBatteryGaugePackage"
$PathToPluginDir = "$env:ProgramData\Lenovo\ImController\Plugins"
$PathToPackageDir = "$PathToPluginDir\$PackageName"
$LogFileName = ("$PackageName" + ".Uninstall." + (Get-Date -Format "-yyyy_MM_dd-HH-mm-ss") + ".txt")
$PathToLogsDir = "$env:ProgramData\Lenovo\Modern\Logs"
$PathToLogFile = "$PathToLogsDir\$LogFileName"
$UninstallFileName = $MyInvocation.MyCommand.Name
$InstallFileName = "Install.ps1"
[bool]$EnableLogging = $false
try { $EnableLogging = ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Lenovo\Modern\Logs" -Name "ImController.Service") -eq 0 ) } catch{}

$PSDefaultParameterValues["Write-Log:pathToLogFile"]=$PathToLogFile
$PSDefaultParameterValues["Write-Log:enableLogging"]=$EnableLogging

Function Check-Is64BitProcess()
{
	return [Environment]::Is64BitProcess
}

Function Check-Is64BitOS()
{
	return [Environment]::Is64BitOperatingSystem
}

Function Check-IsWow64()
{
	return !(Check-Is64BitProcess) -and (Check-Is64BitOS)
}

Function Check-Is64BitPackage()
{
	return $PSScriptRoot.ToLower().Contains("x64".ToLower())
}

function Write-Log
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

		if( -not(Test-Path $pathToLogFile)) { New-Item -Path (Split-Path $pathToLogFile) -Name (Split-Path $pathToLogFile -leaf) -ItemType File -force | Out-Null }
	  	Out-File -InputObject $objTS -FilePath $pathToLogFile -Encoding unicode -Append -Width 200
    }
}

function Get-CurrentActiveUser
{
	$activeUser = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername -EA stop | Select UserName -Unique|%{"{0}" -f $_.UserName.ToString().Split('\')[1]}
	$objUser = New-Object System.Security.Principal.NTAccount("$activeUser")
	$objUser.Value
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


if(Check-Is64BitOS)
{
	$OS_BITNESS=64
}
else
{
	$OS_BITNESS=32
}
	
if(Check-Is64BitProcess)
{
	$PS_BITNESS=64
}
else
{
	$PS_BITNESS=32
}

if(Check-Is64BitPackage)
{
	$PK_BITNESS=64
}
else
{
	$PK_BITNESS=32
}

if ($OS_BITNESS -eq 64)
{
	$arch="x64"
}
else
{
	$arch="x86"
}

# ::***********************************************************************************************
# :: Definition: BatteryGaugeIconControl
$applicationName = "$env:SystemRoot\system32\rundll32.exe"
$PathPackageDirDest = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage"
$commandline = " $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll, "
$cmdLineDll = "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
$HideBg="HideBatteryGauge"
$UnloadBg="UnloadBatteryGaugeFromExplorer"

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

# Check if dll file is still used by explorer
Function IsFileUsedByExplorer
{
	param([string]$dllFileName)

	$IsInUsed = $false
	$TaskListRet = tasklist /M "$dllFileName"
	$IsExplorerLike = $TaskListRet -like "explorer*"
	if($IsExplorerLike -ne $false)
	{  
		$IsInUsed = (($IsExplorerLike).ToLower()).Contains("explorer")
	}

	return $IsInUsed
}


trap 
{
	"An error trapped"
	$TrapError = $_.Exception
	$TrapErrorMsg = $TrapError.Message 
	$TrapLine = $_.InvocationInfo.ScriptLineNumber	
	Write-Log "Caught exception( trapped error ) at line[$TrapLine]: Msg= $TrapErrorMsg"
}

Write-Log "Below logs come from $PSCommandPath"
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
# :: [Remove LenovoBatteryGaugePackage.dll from taskbar]
# ::***********************************************************************************************
Write-Log "Remove LenovoBatteryGaugePackage.dll from taskbar"

$RetryCount = 0
$completed = $false
while(($completed -eq $false) -and ($RetryCount -le 2))
{
	if(BatteryGaugeIconControlEx($UnloadBg) -ne 0 )
	{
		# Wait BGdll to unload from explorer. 1.2 seconds might be enough
		Start-Sleep -Milliseconds 1200
		$completed = $true
		Write-Log "Unload battery gauge from explorer tray sucessful"
	}
	else
	{
		Start-Sleep -Milliseconds 400
		Write-Log "Unload battery gauge from explorer tray failure"
	}
		
	if ($RetryCount -ge 2)
    {
		Write-Log "Error : failed to unload BatteryGauge icon from explorer.."
		#Exit
	}
	$RetryCount++
}


# ::***********************************************************************************************
# :: [Kill active BG processes]:
# ::  QuickSetting.exe,QuickSettingEx.exe,HeartbeatMetrics.exe,SetThinkTouchPad.exe....]
# ::***********************************************************************************************
StopBGProcessDirectly
StopProcessByTaskkill

# ::***********************************************************************************************
# :: [Unregister LenovoBatteryGaugePackage.dll ]
# ::***********************************************************************************************
$RegSvr32Path = "$env:SystemRoot\System32\regsvr32.exe"
Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList `"/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll`""
Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList "/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll" *>&1 | Write-Log
if($? -ne $true)
{
	Write-Log "Unregistry battery gauge from system return code $LastExitCode"
}

# ::***********************************************************************************************
# :: [Unregister PluginsContract.dll ]
# ::***********************************************************************************************
Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PathPackageDirDest\$arch\RegAsm.exe -ArgumentList `"/silent /u $PathPackageDirDest\$arch\PluginsContract.dll`""
Start-Process -NoNewWindow -Wait -FilePath $PathPackageDirDest\$arch\RegAsm.exe -ArgumentList "/silent /u $PathPackageDirDest\$arch\PluginsContract.dll" *>&1 | Write-Log
if($? -ne $true)
{
	Write-Log "Unregistry PluginsContract.dll from system return code $LastExitCode"
}

# ::***********************************************************************************************
# :: [Check if LenovoBatteryGaugePackage.dll still running. If running, force to restart explorer]
# ::***********************************************************************************************
Write-Log "Check if BG has been removed from taskbar"

$RetryCount = 0
$completed = $false
while(($completed -eq $false) -and ($RetryCount -le 1))
{
	$BGInUse = IsFileUsedByExplorer "LenovoBatteryGaugePackage.dll"
	$AVInUse = IsFileUsedByExplorer "Lenovo.AssemblyValidation.Native.dll"
	$CVInUse = IsFileUsedByExplorer "Lenovo.CertificateValidation.dll"

	if( ($BGInUse -eq $true) -or ($AVInUse -eq $true) -or ($CVInUse -eq $true) )
	{
		# Force to unload: rename dll, then restart explorer
		Remove-Item -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll" -NewName "LenovoBatteryGaugePackage_bk.dll"  *>&1 | Write-Log

		Remove-Item -Path "$PathPackageDirDest\$arch\Lenovo.AssemblyValidation.Native_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.AssemblyValidation.Native.dll" -NewName "Lenovo.AssemblyValidation.Native_bk.dll"  *>&1 | Write-Log

		Remove-Item -Path "$PathPackageDirDest\$arch\Lenovo.CertificateValidation_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.CertificateValidation.dll" -NewName "Lenovo.CertificateValidation_bk.dll"  *>&1 | Write-Log

		Remove-Item -Path "$PathPackageDirDest\$arch\Newtonsoft.Json_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Newtonsoft.Json.dll" -NewName "Newtonsoft.Json_bk.dll"  *>&1 | Write-Log

		# BG can't load anymore after restart explorer, because file can't be found.
		Stop-Process -ProcessName "explorer"
		Start-Sleep -Milliseconds 400		

		# Rename dll back
		Rename-Item -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage_bk.dll" -NewName "LenovoBatteryGaugePackage.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.AssemblyValidation.Native_bk.dll" -NewName "Lenovo.AssemblyValidation.Native.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.CertificateValidation_bk.dll" -NewName "Lenovo.CertificateValidation.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Newtonsoft.Json_bk.dll" -NewName "Newtonsoft.Json.dll"  *>&1 | Write-Log
	}
    else
    {
		$completed = $true
    }
		
	if ($RetryCount -ge 1)
    {
		Write-Log "Error : LenovoBatteryGaugePackage.dll is still in use but failed to restart explorer....."
		#Exit
	}
	$RetryCount++
}

Function GetCurrentActiveUserSID
{
	$activeUser = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername -EA stop | Select UserName -Unique|%{"{0}" -f $_.UserName.ToString().Split('\')[1]}
	$objUser = New-Object System.Security.Principal.NTAccount("$activeUser")
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	$strSID.Value
}

# try to remove temporary files, folders?
if($($args[0]) -eq "ForUpdate")
{
	Write-Log "No need to removing Lenovo Battery Gauge temporary folders and user data for upgradation"
}
else
{
	# ::***********************************************************************************************
	# :: Delete BG MaintenanceTask
	# ::***********************************************************************************************
	$SchTasksPath = "$env:SystemRoot\System32\schtasks.exe"
	Write-Log "$SchTasksPath /Delete /TN `"\Lenovo\BatteryGauge\BatteryGaugeMaintenance`" /F"
	powershell $SchTasksPath /Delete /TN "\Lenovo\BatteryGauge\BatteryGaugeMaintenance" /F  *>&1 | Write-Log

	# Rename QSHelper
	Rename-Item -Path "$PathPackageDirDest\$arch\QSHelper.exe" -NewName "QSHelper_bk.exe"  *>&1 | Write-Log

	# ::***********************************************************************************************
	# :: [Remove Lenovo Battery Gauge Registry Entries ]
	# ::***********************************************************************************************
	$RegPath = "$env:SystemRoot\System32\reg.exe"
	Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList `"delete HKLM\Software\Lenovo\QuickSetting /v Location /f`""
	Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList "delete HKLM\Software\Lenovo\QuickSetting /v Location /f" *>&1 | Write-Log
	if($? -ne $true)
	{
		Write-Log "Unregistry battery gauge from system return code $LastExitCode"
	}

	Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList `"delete HKLM\Software\Lenovo\QuickSetting /v Path /f`""
	Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList "delete HKLM\Software\Lenovo\QuickSetting /v Path /f" *>&1 | Write-Log
	if($? -ne $true)
	{
		Write-Log "Delete registry value `"Path`" from `"HKLM\Software\Lenovo\QuickSetting`" return code $LastExitCode"
	}

	Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList `"delete HKLM\Software\Lenovo\QuickSetting /f`""
	Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList "delete HKLM\Software\Lenovo\QuickSetting /f" *>&1 | Write-Log
	if($? -ne $true)
	{
		Write-Log "Delete registry key `"HKLM\Software\Lenovo\QuickSetting`" return code $LastExitCode"
	}


	# ::***********************************************************************************************
	# :: [Remove Lenovo Battery Gauge temporary folders ]
	# ::***********************************************************************************************
    $pathReg = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
    Get-ItemProperty -Path $pathReg | ForEach-Object { $SidStr = $_ | Select-Object -Property PSChildName -Unique|%{"{0}" -f $_.PSChildName.ToString()} 
    REG DELETE HKU\$SidStr\Software\Lenovo\BatteryGauge  /f}

	Write-Log "Remove Lenovo Battery Gauge temporary folders"
	$ACTIVEUSER=Get-CurrentActiveUser
	Write-Log "Remove-Item -Recurse -Force `"$env:ProgramData\Lenovo\BatteryGauge`""
	Remove-Item -Recurse -Force "$env:ProgramData\Lenovo\BatteryGauge" *>&1 | Write-Log

	Write-Log "Remove-Item -Recurse -Force `"$env:HomeDrive\Users\$ACTIVEUSER\AppData\Local\Lenovo\BatteryGauge`""
	Remove-Item -Recurse -Force "$env:HomeDrive\Users\$ACTIVEUSER\AppData\Local\Lenovo\BatteryGauge" *>&1 | Write-Log

	Write-Log "Remove-Item -Recurse -Force `"$env:HomeDrive\Users\$ACTIVEUSER\AppData\LocalLow\Lenovo\batterygauge`""
	Remove-Item -Recurse -Force "$env:HomeDrive\Users\$ACTIVEUSER\AppData\LocalLow\Lenovo\batterygauge" *>&1 | Write-Log

    Write-Log "Remove-Item -Recurse -Force `"$env:ProgramData\Lenovo\settings_batterygaugeplugin`""
	Remove-Item -Recurse -Force "$env:ProgramData\Lenovo\settings_batterygaugeplugin" *>&1 | Write-Log
	
	$au = GetCurrentActiveUserSID
	Write-Log "Remove-ItemProperty -Path HKCU:\SOFTWARE\Lenovo\BatteryGaugeToast\ResetEyeCareMode"
	Write-Log "user = $au"
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS *>&1 | Write-Log
	Remove-ItemProperty -Path "HKU:$au\SOFTWARE\Lenovo\BatteryGaugeToast" -Name "ResetEyeCareMode" -ErrorAction SilentlyContinue *>&1 | Write-Log
	Remove-ItemProperty -Path "HKU:$au\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LenovoVantageToolbar" -ErrorAction SilentlyContinue *>&1 | Write-Log
	Remove-PSDrive -Name HKU *>&1 | Write-Log
}

Write-Log "Uninstall success"
Exit
# SIG # Begin signature block
# MIIeBgYJKoZIhvcNAQcCoIId9zCCHfMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDKkVptQ/kxNPq8
# HsZScRy4y1ITbFRCmwgxu/Fk58mo7qCCGNwwggSZMIIDgaADAgECAhBNFlUhGoem
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
# IgQgqemA7AJCNHXDP1P0OLctqVUhZkcUiqL6KGAe0H1qrncwDQYJKoZIhvcNAQEB
# BQAEggEAIkETCKx2cW+fR/7cGz0r8CXh1Xj2gP8HmNTmC71COyAc464NK9impBVp
# o65GtgyxnVEG0t1dSVgAC8/9ThemVh+07JwZm6PPBzwVLEkyLUU2C8jYUmzpFwlz
# r0weJeb5Nal3oU4ffjljD1V8fMZ9CDkRinHcWZwWPgoWSA8Fp0qy6Lc2BlpFeL/9
# hqa7q+aWmxvBEGYSo7owaJriJ2VTWvqhFDl5rS7Wf6v+zTnzohJ+fRsYy+vGpkZF
# djG7K+UjyPDNONGAMnb9b1gHD6pHtq1K2v6h9Hu2F1DEB5vXJ1NINfzXcF/KpnaW
# 8/frat0EnitdJyQz0T0l1C9WekXcFaGCAjAwggIsBgkqhkiG9w0BCQYxggIdMIIC
# GQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEy
# IEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhANQkrgvjqI/2BAIc4UAPDdMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjEwNTE5MTI1MTA5WjAvBgkqhkiG9w0BCQQxIgQgMpH4Z8S0Zqlm
# PKaGtFRtsuMnzRZ+oSvTTMpl24HzMV8wDQYJKoZIhvcNAQEBBQAEggEAjf5gvoEP
# 10ddlX0yNeNCUZ7gCjxCKCTC4o93BA09GWqBVhj+sTXR/I5A4mHEC6TS/C2+jFMX
# +8Erxo0Y6NAjfdn/73ifZh+eNPelDh5F+yWeSbE8u4ogaqpqWtq9RKzVIT+yFoA6
# jFnN69XED5wh7NO9OB33KmL+53K2+Ig6SBR6N0yiHbzY/6sw3H5wdiLY99hjxNNK
# ZPwZlUjD3afNTNE4JwbT6ncCJSJNgBSyv7CB1muU1u+8bxdcxVWmw4j/1aI9aOMW
# PuwhjFXco+8uEiJmNJmKz3x4jXtH9/odZXJz4oRJX05m6t+hLgW54VnibO2EgMxW
# J09CxFAExUObcA==
# SIG # End signature block
