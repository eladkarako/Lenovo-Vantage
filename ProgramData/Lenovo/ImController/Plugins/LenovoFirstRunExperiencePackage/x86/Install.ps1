$PackageName = "LenovoFirstRunExperiencePackage"
$LogFileName = ($PackageName + (Get-Date -Format "-yyyy_MM_dd-HH-mm-ss") + "-install.txt")
[bool]$EnableLogging = $true
try { $EnableLogging = ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Lenovo\Modern\Logs" -Name "ImController.Service" -ErrorAction Stop) -eq 0 ) } catch { Write-Host "LOGGING DISABLED - Lenovo modern logs registry key not found" }
$Is64BitOs = [Environment]::Is64BitOperatingSystem
if($Is64BitOs) { $OsBitness = 64 } else { $OsBitness = 86 }
$DomainUser = $(Get-WMIObject -class Win32_ComputerSystem | select username).username 
$username = $DomainUser -Split "\\" | Select-Object -Index 1

#### Shared Functions ####
function Write-Log($text)
{
    $pathToLogsDir = "$env:ProgramData\lenovo\Modern\Logs"
    Write-Host $text
    if($EnableLogging)
    {
        $pathToFile = "$pathToLogsDir\$LogFileName"
        if( -not(Test-Path $pathToFile)) { New-Item -Path $pathToLogsDir -Name $LogFileName -ItemType File | Out-Null }
        Add-Content -Path ($pathToFile) -Value $text
    }
}

function Invoke-LnkFile($pathToLnk)
{
    if(Test-Path $pathToLnk)
    {
        Write-Log "Invoking LNK $pathToLnk"
        Invoke-Item -Path $pathToLnk -OutVariable outVar -Verbose
        if($outVar -ne ""){ Write-Log "Error: $outVar" }
    }else{
        Write-Log "Error: Hide LNK $pathToLnk does not exist"
    }
}


function Invoke-Cmd($cmd){
    $errorVar = ""
    $outVar = ""
    Write-Log "Info: Invoking $cmd"   
    Invoke-Expression -Command $cmd -ErrorVariable errorVar -OutVariable outVar

    if($outVar -ne ""){ Write-Log "Info: $outVar" }
    if($errorVar -ne ""){ Write-Log "Error: $errorVar" }
}

function Invoke-RegSvr($pathToDll, $arg){
    if(Test-Path $pathToDll)
    {
        $cmd = "& $env:windir\System32\regsvr32.exe $arg '$pathToDll'"
        Invoke-Cmd -cmd $cmd
        #Start-Process -FilePath "$env:windir\System32\regsvr32.exe" -ArgumentList "$arg $pathToDll"  -Wait -PassThru

    }else{
        Write-Error "Warning: DLL $pathToDll does not exist"
    }
}

function Stop-Process($processName)
{
    # Stop the OLD quick optimizer
    $cmd = "& $env:windir\System32\taskkill.exe /t /f /im $processName"
    Write-Log "Stopping process named $processName"
    Invoke-Cmd $cmd
}

function Move-TempPackageToFinalDir($packageName)
{
    $pathToPluginsDir = "$env:ProgramData\Lenovo\ImController\Plugins"
    $finalpath = "$pathToPluginsDir\$packageName"
    $tempPath = "$pathToPluginsDir\$packageName" + "_"

    if(-not(Test-Path $tempPath -PathType Container))
    {
        Write-Log "Error: Expected package temp path $tempPath does not exist"
        return
    }
    $errorVar = ""
    #$perms = Get-Acl -Path $pathToPluginsDir
    if(Test-Path $finalpath -PathType Container)
    {
        Write-Log "Info: Found existing package ($finalpath).  Removing all contents"
        #Remove-Item $finalpath\* -Recurse -Force -ErrorAction Continue -Verbose -ErrorVariable errorVar
        #if($errorVar -ne ""){ Write-Log "Error: remove items $finalpath $errorVar" }
        Remove-Item $finalpath -Recurse -Force -ErrorAction Continue -Verbose -ErrorVariable errorVar
        if($errorVar -ne ""){ Write-Log "Error: remove items $finalpath $errorVar" }
    }
    else
    {
        New-Item -Path $pathToPluginsDir -Name $packageName -ItemType Directory
        #Set-Acl -Path $finalpath -AclObject $perms
        
    }

    Write-Log "Info: Copying from '$tempPath' to '$finalpath'"
    $errorVar = ""
    if (test-path $finalpath)
    {
        Copy-Item -Path "$tempPath\*" -Destination $finalpath -Force -Recurse -ErrorVariable errorVar -Verbose
    }
    else
    {
        Copy-Item -Path "$tempPath" -Destination $finalpath -Force -Recurse -ErrorVariable errorVar -Verbose
    }
    if($errorVar -ne ""){ Write-Log "Error: copy item, $errorVar" }
    # Set the permissions on each child
    $errorVar = ""
    #Get-ChildItem -Path $finalpath -Recurse -Force | ForEach-Object { Set-Acl -Path $_.FullName -AclObject $perms -Verbose }
    
    if(-not(Test-Path $finalpath -PathType Container))
    {
        Write-Log "Error: after moving, final path does not exist ($finalpath)"
    }
}

#### /Shared Functions ####


#### LEGACY ITEMS ####

# Stop the current process if needed
function Stop-LegacyProcess($processName)
{ 
    Stop-Process -processName $processName
}

#### /LEGACY ITEMS ####


#### Lenovo Welcome Functions ####
$companyName = 'Lenovo'
$taskName    = 'LenovoWelcomeTask'
$taskDesc    = 'Lenovo Welcome application'
$welcomeTaskEXE  = 'LenovoWelcomeTask.exe'
$welcomeEXE      = 'LenovoWelcome.exe'
$machineInfoXml = 'MachineInformation.xml'
$shortcutName = 'Lenovo Welcome'


$taskXML = '<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>' + "$companyName" + '</Author>
    <Description>' + "$taskDesc" + '</Description>
    <URI>\' + "$companyName" + '\' + "$taskName" + '</URI>
  </RegistrationInfo>
  <Triggers>
   <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name="Microsoft-Windows-Power-Troubleshooter"] and EventID=1]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
	  <Delay>PT3M</Delay>
	</EventTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT3M</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>' + "$welcomeTaskEXE" + '</Command>
    </Exec>
  </Actions>
</Task>'

function Delete-ScheduledTask()
{
    ## Delete the old scheduled task if it exist
    if (Get-ScheduledTask -TaskPath "\$companyName\" -TaskName "$taskName" -ErrorAction SilentlyContinue)
    {
        Write-Log 'Remove existing scheduled task...'
        Unregister-ScheduledTask -TaskPath "\$companyName\" -TaskName "$taskName" -Confirm:$false
        Start-Sleep -Seconds 2
        if (Get-ScheduledTask -TaskPath "\$companyName\" -TaskName "$taskName" -ErrorAction SilentlyContinue)
        {
			Write-Log 'Scheduled task has NOT been removed...'
            return $false
        }
    }
    return $true
}

function Create-ScheduledTask()
{
    if (Delete-ScheduledTask)
    {
        Write-Log 'Create new scheduled task'
        Register-ScheduledTask -Xml "$taskXML" -TaskName "$taskName" -TaskPath "\$companyName\"
        return
    }
    else
    {
        Write-Log 'ERROR creating new scheduled task, old task still exist'

        return $false
    }
}

function Update-ScheduledTask()
{
    if (Create-ScheduledTask)
    {
        Write-Log 'Update action'
        $workingDir = Join-Path -path "$Env:ProgramData" -childPath "$companyName" | Join-Path -childPath 'ImController' | Join-Path -childPath 'Plugins' | Join-Path -childPath "$PackageName" | Join-Path -childPath 'x86'
        $execute    = Join-Path -path "$workingDir" -childPath "$welcomeTaskEXE"
        
        $action = New-ScheduledTaskAction -Execute "`"$execute`"" -Argument '/task' -WorkingDirectory "$workingDir"


        ### Users GROUP = S-1-5-32-545
        #$principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited


        Write-Log 'Update triggers'
        $taskTriggers = (Get-ScheduledTask -TaskPath "\$companyName\" -TaskName "$taskName").Triggers

        ## Can only use RandomDelay with New-ScheduledTaskTrigger
        #$triggerLogOn = New-ScheduledTaskTrigger -AtLogOn -RandomDelay (New-TimeSpan -Minutes 5)
        $triggerDate  = New-ScheduledTaskTrigger -Once -At ((Get-Date) + (New-TimeSpan -Minutes 5))
        $taskTriggers += $triggerDate


        #$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        #Register-ScheduledTask -TaskName "$companyName\$taskName" -Description "$taskDesc" -Principal $principal -Trigger $triggerLogOn,$triggerDate -Action $action -Settings $settings
        Write-Log 'Update scheduled task with correct Triggers and Action paths'
        Set-ScheduledTask -TaskPath "\$companyName\" -TaskName "$taskName" -Trigger $taskTriggers -Action $action
        return
    }
    else
    {
        Write-Log 'ERROR updating new scheduled task'

        return $false
    }
}

function Get-FirstRunDate()
{
	try 
	{
		$defaultProfileDir = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' Default).Default
		if ([environment]::Is64BitOperatingSystem)
		{
			$pathToStateIniFile = $defaultProfileDir + "\Documents"
		}
		else
		{
			$pathToStateIniFile = $defaultProfileDir
		}

		if (Test-Path $pathToStateIniFile)
		{
			$createdDate = Get-Item $pathToStateIniFile | Foreach {$_.LastWriteTime}
			return $createdDate.ToString('yyyy-MM-dd')
		}
		else
		{
			Write-Log "Directory $pathToStateIniFile does not exist"
		}
	}
	catch
	{
		Write-Log "Exception while getting FirstRunDate, $_.Exception.Message"
	}
}

#Use simpler method, get Country string for China System only.
#more reliable method is in GenericCorePlugin code.
function Get-Country()
{
	## Get country from HKCU\Control Panel\International\Geo, need do mapping because of system account
	$ntAccount = New-Object -TypeName System.Security.Principal.NTAccount($DomainUser)
	$sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
	$RegKey = "HKU:\" + $sid + "\Control Panel\International\Geo"
	New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	$keyValue = Get-ItemProperty -Path $RegKey -Name Nation
	$geoId = $keyValue.Nation
	Write-Log "Get-Country: GeoId = $geoId"
	if ($geoId -eq 45)
	{
		$country = "CN"
	}

	if ($country -eq "CN")
	{
		return "CN"
	}
	else
	{
		return "non-CN"
	}
}


#Use simpler method, get Brand for Think if Manufacturer contain 'Lenovo' AND SystemSKU contain 'BU_Think'.
#more reliable method is in GenericCorePlugin code.
function Get-Brand()
{
	$objWmi = get-wmiobject -namespace root\WMI -computername localhost -Query "Select * from MS_SystemInformation"
	$manufacturer = $objWmi.SystemManufacturer
	#This is an example of SKU string: LENOVO_MT_20G1_BU_Think_FM_ThinkPad S3
	$sku = $objWmi.SystemSKU
	if ($manufacturer -match "lenovo" -and $sku -match "bu_think")
	{
		return "think"
	}
	else
	{
		return "non-think"
	}
}

function Check-OutsideOfOOBEweek($oobeDateString)
{
	try
	{
		$oobeDate = [datetime]::ParseExact($oobeDateString, "yyyy-MM-dd", $null)
	}
	catch
	{
		$oobeDate = [datetime]::ParseExact($oobeDateString, "yyyy-MM-ddTHH:mm:ss", $null)
	}
	$oobeDate = $oobeDate.ToString('yyyy-MM-dd')
	$currentDate = Get-Date -Format "yyyy-MM-dd"
	$timeSpan = New-TimeSpan -Start $oobeDate -End $currentDate
	$daysSinceOOBE = $timeSpan.Days + 1
	Write-Log "Check-OutsideOfOOBEweek: oobeDate = $oobeDate, currentDate = $currentDate, daysSinceOOBE = $daysSinceOOBE"
	if ($daysSinceOOBE -gt 7)
	{
		New-Object psobject -Property @{
            Result  = $true
        }
	}
	else
	{
		New-Object psobject -Property @{
            Result  = $false
        }
	}
}

function Check-CanInstall()
{
	##Parse MachineInformation.xml to check the following conditions:
		#Check for OOBE+7 in the install script. Don't install if outside of OOBE+7.
		#Check for Think system in the install script.  Don't install on Think system.
		#Check for China system in the install script.  Don't install on China system.
	$machineInfoPath = "$env:programdata\Lenovo\ImController\shared\$machineInfoXml"
	Write-Log "Determine whether or not to install app"
	if (Test-Path  $machineInfoPath)
	{
		$xml = [xml](get-content $machineInfoPath)
		$brand = $xml.MachineInformation.Brand
		#This is an example data in the xml: <FirstRunDate>2017-05-13</FirstRunDate>
		$firstRunDate = $xml.MachineInformation.FirstRunDate
		$country = $xml.MachineInformation.Country
	}
	else
	{
		Write-Log "Unable to find $machineInfoPath, try to check conditions by ourselves"
		$brand = Get-Brand
		$firstRunDate = Get-FirstRunDate
		$country = Get-Country
	}

	$outsideOfOOBEweek = (Check-OutsideOfOOBEweek $firstRunDate).Result
	Write-Log "brand=$brand, country=$country, outsideOfOOBEweek=$outsideOfOOBEweek"
	if ($brand -eq "think" -or $country -eq "cn" -or $outsideOfOOBEweek)
	{
		Write-Log "Don't install app"
		return $false
	}
	else
	{
		Write-Log "Install app"
		return $true
	}
}

function Delete-StartMenu()
{
	$sysDrive = "$env:systemdrive"

	$shortcutFilePath = $sysDrive + "\Users\" + $userName + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\" + $shortcutName + ".lnk"
	if (Test-Path  $shortcutFilePath)
	{
		Write-Log "Removing start menu item $shortcutFilePath"
		Remove-Item $shortcutFilePath
	}
	else
	{
		Write-Log "Unable to find shortcut $shortcutFilePath"
	}
}

function Delete-TempFolder()
{
	Write-Log "Delete the temp folder..."
	$path = "$env:localappdata\Lenovo\ImController\PluginData\LenovoFirstRunExperiencePackage"
	Remove-Item -Path $path -Force -Recurse
}

function Delete-Registry()
{
	## Delete the app registry key from HKCU, need do mapping because of system account
	Write-Log "Delete the registry..."
	#$explorers = Get-WmiObject -Namespace root\cimv2 -Class Win32_Process -Filter "Name='explorer.exe'"
    #$explorers | ForEach-Object {
    #    $owner = $_.GetOwner()
    #    if($owner.ReturnValue -eq 0) {
    #        $user = '{0}\{1}' -f $owner.Domain, $owner.User
    #        $ntAccount = New-Object -TypeName System.Security.Principal.NTAccount($user)
    #        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    #        $RegKey = "HKU:\" + $sid + "\Software\Lenovo\LenovoFirstRunExperience"
    #        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    #        Remove-Item -Path $RegKey
    #        Write-Log "Deleted the registry... $RegKey"
    #    }
    #}

	$ntAccount = New-Object -TypeName System.Security.Principal.NTAccount($DomainUser)
    $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $RegKey = "HKU:\" + $sid + "\Software\Lenovo\LenovoFirstRunExperience"
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    Remove-Item -Path $RegKey
    Write-Log "Deleted the registry... $RegKey"
}

#### /Lenovo Welcome Functions ####


Write-Log "INSTALL START - $PackageName"

# Stop the legacy process (if running)
Stop-LegacyProcess($welcomeEXE)
Stop-LegacyProcess($welcomeTaskEXE)

# Copy from temp dir to final dir
Move-TempPackageToFinalDir -packageName $PackageName

if (Check-CanInstall)
{
	# Clean up in case upgrade
	try
	{
		Delete-TempFolder
		Delete-StartMenu
		Delete-Registry
	}
	catch
	{
		Write-Log "Exception happen..."
		Write-Log $_.Exception.Message
	}

	Update-ScheduledTask
}

Write-Log "INSTALL COMPLETE - $PackageName"

# SIG # Begin signature block
# MIIcZQYJKoZIhvcNAQcCoIIcVjCCHFICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDYjW5FemBREjmu
# sB4LoNJV9AGj1R4iQFXTevbwpTjQH6CCF2AwggPuMIIDV6ADAgECAhB+k+v7fMZO
# WepLmnfUBvw7MA0GCSqGSIb3DQEBBQUAMIGLMQswCQYDVQQGEwJaQTEVMBMGA1UE
# CBMMV2VzdGVybiBDYXBlMRQwEgYDVQQHEwtEdXJiYW52aWxsZTEPMA0GA1UEChMG
# VGhhd3RlMR0wGwYDVQQLExRUaGF3dGUgQ2VydGlmaWNhdGlvbjEfMB0GA1UEAxMW
# VGhhd3RlIFRpbWVzdGFtcGluZyBDQTAeFw0xMjEyMjEwMDAwMDBaFw0yMDEyMzAy
# MzU5NTlaMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwS
# CtgleZEiVypv3LgmxENza8K/LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3
# Te2/tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwF
# eEWlL4nO55nn/oziVz89xpLcSvh7M+R5CvvwdYhBnP/FA1GZqtdsn5Nph2Upg4XC
# YBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+nw54trorqpuaqJxZ9YfeYcRG8
# 4lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+VMET
# fMV58cnBcQIDAQABo4H6MIH3MB0GA1UdDgQWBBRfmvVuXMzMdJrU3X3vP9vsTIAu
# 3TAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0
# ZS5jb20wEgYDVR0TAQH/BAgwBgEB/wIBADA/BgNVHR8EODA2MDSgMqAwhi5odHRw
# Oi8vY3JsLnRoYXd0ZS5jb20vVGhhd3RlVGltZXN0YW1waW5nQ0EuY3JsMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIBBjAoBgNVHREEITAfpB0wGzEZ
# MBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMTANBgkqhkiG9w0BAQUFAAOBgQADCZuP
# ee9/WTCq72i1+uMJHbtPggZdN1+mUp8WjeockglEbvVt61h8MOj5aY0jcwsSb0ep
# rjkR+Cqxm7Aaw47rWZYArc4MTbLQMaYIXCp6/OJ6HVdMqGUY6XlAYiWWbsfHN2qD
# IQiOQerd2Vc/HXdJhyoWBl6mOGoiEqNRGYN+tjCCBKMwggOLoAMCAQICEA7P9DjI
# /r81bgTYapgbGlAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzIwHhcNMTIxMDE4MDAwMDAwWhcNMjAx
# MjI5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgU2lnbmVyIC0gRzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCi
# Yws5RLi7I6dESbsO/6HwYQpTk7CY260sD0rFbv+GPFNVDxXOBD8r/amWltm+YXkL
# W8lMhnbl4ENLIpXuwitDwZ/YaLSOQE/uhTi5EcUj8mRY8BUyb05Xoa6IpALXKh7N
# S+HdY9UXiTJbsF6ZWqidKFAOF+6W22E7RVEdzxJWC5JH/Kuu9mY9R6xwcueS51/N
# ELnEg2SUGb0lgOHo0iKl0LoCeqF3k1tlw+4XdLxBhircCEyMkoyRLZ53RB9o1qh0
# d9sOWzKLVoszvdljyEmdOsXF6jML0vGjG/SLvtmzV4s73gSneiKyJK4ux3DFvk6D
# Jgj7C72pT5kI4RAocqrNAgMBAAGjggFXMIIBUzAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBzBggrBgEFBQcBAQRn
# MGUwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA3
# BggrBgEFBQcwAoYraHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vdHNzLWNh
# LWcyLmNlcjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vdHMtY3JsLndzLnN5bWFu
# dGVjLmNvbS90c3MtY2EtZzIuY3JsMCgGA1UdEQQhMB+kHTAbMRkwFwYDVQQDExBU
# aW1lU3RhbXAtMjA0OC0yMB0GA1UdDgQWBBRGxmmjDkoUHtVM2lJjFz9eNrwN5jAf
# BgNVHSMEGDAWgBRfmvVuXMzMdJrU3X3vP9vsTIAu3TANBgkqhkiG9w0BAQUFAAOC
# AQEAeDu0kSoATPCPYjA3eKOEJwdvGLLeJdyg1JQDqoZOJZ+aQAMc3c7jecshaAba
# tjK0bb/0LCZjM+RJZG0N5sNnDvcFpDVsfIkWxumy37Lp3SDGcQ/NlXTctlzevTcf
# Q3jmeLXNKAQgo6rxS8SIKZEOgNER/N1cdm5PXg5FRkFuDbDqOJqxOtoJcRD8HHm0
# gHusafT9nLYMFivxf1sJPZtb4hbKE4FtAC44DagpjyzhsvRaqQGvFZwsL0kb2yK7
# w/54lFHDhrGCiF3wPbRRoXkzKy57udwgCRNx62oZW8/opTBXLIlJP7nPf8m/PiJo
# Y1OavWl0rMUdPH+S4MO8HNgEdTCCBLkwggOhoAMCAQICEEAaxGQhsxMhAw675BIa
# xR0wDQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJp
# U2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazE6MDgG
# A1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9yaXplZCB1
# c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJvb3QgQ2VydGlm
# aWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwNDAyMDAwMDAwWhcNMzcxMjAxMjM1OTU5
# WjCBvTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYD
# VQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBW
# ZXJpU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQD
# Ey9WZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
# eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMdhN16xATTbYtcVm/9Y
# WowjI9ZgjpHXkJiDeuZYGTiMxfblZIW0onH77b252s1NALTILXOlx2lxlR85PLJE
# B5zoDvpNSsQh3ylhjzIiYYLFhx9ujHxfFiBRRNFwT1fq4xzjzHnuWNgOwrNFk8As
# 55oXK3sAN3pBM3jhM+LzEBp/hyy+9vX3QuLlv4diiV8AS9/F3eR1RDJBOh5xbmnL
# C3VGCNHK0iuV0M/7uUBrZIxXTfwTEXmE7V5U9jSfCAHzECUGF0ra8R16ZmuYYGak
# 2e/SLoLx8O8J6kTJFWriA24z06yfVQDH9ghqlLlf3OAz8YRg+VsnEbT8FvK7VmqA
# JY0CAwEAAaOBsjCBrzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBt
# BggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcGBSsOAwIa
# BBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJpc2lnbi5j
# b20vdnNsb2dvLmdpZjAdBgNVHQ4EFgQUtnf6aUhHn1MS1cLqBzJ2B9GXBxkwDQYJ
# KoZIhvcNAQELBQADggEBAEr4+LAD5ixne+SUd2PMbkz5fQ4N3Mi5NblwT2P6JPps
# g4xHnTtj85r5djKVkbF3vKyavrHkMSHGgZVWWg6xwtSxplms8WPLuEwdWZBK75AW
# KB9arhD7gVA4DGzM8T3D9WPjs+MhySQ56f0VZkb0GxHQTXOjfUb5Pe2oX2LU8T/4
# 4HRXKxidgbTEKNqUl6Vw66wdvgcR8NXb3eWM8NUysIPmV+KPv76hqr89HbXUOOrX
# sFw6T2o/j8BmbGOq6dmkFvSB0ZUUDn3NlTTZ0o9wc4F7nH69mGHYRYeYkMXrhjDG
# Nb/w/8NViINL7wWSBnHyuJiTt+zNgmHxOOZPl5gqWo0wggS7MIIDo6ADAgECAhBH
# dlXIifGiaUK19l+IGeN3MA0GCSqGSIb3DQEBCwUAMIGEMQswCQYDVQQGEwJVUzEd
# MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
# IFRydXN0IE5ldHdvcmsxNTAzBgNVBAMTLFN5bWFudGVjIENsYXNzIDMgU0hBMjU2
# IENvZGUgU2lnbmluZyBDQSAtIEcyMB4XDTE5MDkyNzAwMDAwMFoXDTIwMTEyNzIz
# NTk1OVowbDELMAkGA1UEBhMCVVMxFzAVBgNVBAgMDk5vcnRoIENhcm9saW5hMRQw
# EgYDVQQHDAtNb3JyaXN2aWxsZTEPMA0GA1UECgwGTGVub3ZvMQwwCgYDVQQLDANH
# MDgxDzANBgNVBAMMBkxlbm92bzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAMdSFmbc/pBLa6XvDzzY6HrU3OoCYE1qZgpHObXCrBSG1YEQqZUI9AkgjB1J
# 6JOh8zNlsujpnunz8krxEig6S9o6/UQq7hSXoW54E9LiDebzCFpYVcGGDzdTo0Ya
# +qcH1T7nR30rEydI+i9ITA+zZ1G6EqIbwOKAZW49S002ZrOXxBpRanKiPIcQRNF9
# nC3nc+C7aMwJ8hCwz5jzzTOgQH5pbz6wlgdmAGUhTCiSnp9Yz1g5CghA9BOjvu4j
# f5Ems5qfjW6T8ONiSfmftQrJATw/7Q2WbHZPpR0n/ECTSvTfpY1qti9adAacDnH+
# NAG0b8+tJp+5HIRYx8L+RkalaXkCAwEAAaOCAT4wggE6MAkGA1UdEwQCMAAwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMGEGA1UdIARaMFgwVgYG
# Z4EMAQQBMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUG
# CCsGAQUFBwICMBkMF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMB8GA1UdIwQYMBaA
# FNTABiJJ6zlL3ZPiXKG4R3YJcgNYMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9y
# Yi5zeW1jYi5jb20vcmIuY3JsMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYT
# aHR0cDovL3JiLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3JiLnN5bWNi
# LmNvbS9yYi5jcnQwDQYJKoZIhvcNAQELBQADggEBAErfOUAjaiVnd4daZRZFHOMP
# /onsqnRWIV/kr7aph/ErtvteOi2Asv8dLmu9p0IorAQWxK7Mp29LEjn9VeYKEvWC
# BAoTEZ5KfewNEMGK+uQCEdBuVnyZjD0wjUmqvl75+dTjSyXJ3ZEZE5tJV0+Pu7Q3
# wR7vHe6OgkanL5BIJ3+lKup66yhxr3mwfb1g2/3KKuxpkdm7uExueRTtFfCLJUAv
# Lp4eX829Jrqzo8yr3TV9PZ0m9Htnccd+Al7v7Hpi8zWKSW3xY/N0F930ZPSLJ577
# BFuNrq7pRPS6i9ZAFOZo3+dE/DXkPHmFxS55g0ydY0VrdYUq489kUSVa+bKRX/Ew
# ggVHMIIEL6ADAgECAhB8GzU1SufbdOdBXxFpymuoMA0GCSqGSIb3DQEBCwUAMIG9
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsT
# FlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlT
# aWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1Zl
# cmlTaWduIFVuaXZlcnNhbCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4X
# DTE0MDcyMjAwMDAwMFoXDTI0MDcyMTIzNTk1OVowgYQxCzAJBgNVBAYTAlVTMR0w
# GwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMg
# VHJ1c3QgTmV0d29yazE1MDMGA1UEAxMsU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYg
# Q29kZSBTaWduaW5nIENBIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQDXlUPU3N9nrjn7UqS2JjEEcOm3jlsqujdpNZWPu8Aw54bYc7vf69F2P4pW
# justS/BXGE6xjaUz0wt1I9VqeSfdo9P3Dodltd6tHPH1NbQiUa8iocFdS5B/wFlO
# q515qQLXHkmxO02H/sJ4q7/vUq6crwjZOeWaUT5pXzAQTnFjbFjh8CAzGw90vlvL
# EuHbjMSAlHK79kWansElC/ujHJ7YpglwcezAR0yPfcPeGc4+7gRyjhfT//CyBTIZ
# TNOwHJ/+pXggQnBBsCaMbwDIOgARQXpBsKeKkQSgmXj0d7TzYCrmbFAEtxRg/w1R
# 9KiLhP4h2lxeffUpeU+wRHRvbXL/AgMBAAGjggF4MIIBdDAuBggrBgEFBQcBAQQi
# MCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNkLmNvbTASBgNVHRMBAf8ECDAG
# AQH/AgEAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYX
# aHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9k
# LnN5bWNiLmNvbS9ycGEwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3Muc3ltY2Iu
# Y29tL3VuaXZlcnNhbC1yb290LmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNV
# HQ8BAf8EBAMCAQYwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJ
# LTEtNzI0MB0GA1UdDgQWBBTUwAYiSes5S92T4lyhuEd2CXIDWDAfBgNVHSMEGDAW
# gBS2d/ppSEefUxLVwuoHMnYH0ZcHGTANBgkqhkiG9w0BAQsFAAOCAQEAf+vKp+qL
# dkLrPo4gVDDjt7nc+kg+FscPRZUQzSeGo2bzAu1x+KrCVZeRcIP5Un5SaTzJ8eCU
# RoAYu6HUpFam8x0AkdWG80iH4MvENGggXrTL+QXtnK9wUye56D5+UaBpcYvcUe2A
# OiUyn0SvbkMo0yF1u5fYi4uM/qkERgSF9xWcSxGNxCwX/tVuf5riVpLxlrOtLfn0
# 39qJmc6yOETA90d7yiW5+ipoM5tQct6on9TNLAs0vYsweEDgjY4nG5BvGr4IFYFd
# 6y/iUedRHsl4KeceZb847wFKAQkkDhbEFHnBQTc00D2RUpSd4WjvCPDiaZxnbpAL
# GpNx1CYCw8BaIzGCBFswggRXAgEBMIGZMIGEMQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0
# IE5ldHdvcmsxNTAzBgNVBAMTLFN5bWFudGVjIENsYXNzIDMgU0hBMjU2IENvZGUg
# U2lnbmluZyBDQSAtIEcyAhBHdlXIifGiaUK19l+IGeN3MA0GCWCGSAFlAwQCAQUA
# oIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIIoM55LCxNKZLAJx+Cz3CDtcZxHxA9mgTdRcB74RWR/GMA0GCSqGSIb3
# DQEBAQUABIIBAImuv6fNZZlHFIWVP36V9FoELN/VWXguE1yEne73DhxL7oALATCj
# eXkdRTfkwJqA8YU8XjAZj3fEdqroTy89RU/Ccthl8C2996VALgfsQ4yLOAAK05fP
# bjQDwxujTM/ZjkAaDzKF0UION1DZ9Ikfz05rod0L4b2ZAVqOXjp3w4Nhxp3I5UGm
# bYBFAdXiq3RcEKYBavydpUzX2fDAsMgmfwA9N8ofPLxZvyODVE3rH2nKNrqYou4h
# EU2VpYVCWVr4NIy7kSnAtVvWpBYRnmFy46R1+7/a8dETT5vylmnQtLJAVKfAw/lV
# 4vqaUD8beMXdixondzhQuJbyHGAjXGeDWc6hggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwMzE3MTEyMDA3
# WjAjBgkqhkiG9w0BCQQxFgQUwi7y2Aku3hmc2WorSB7FK2Tl36gwDQYJKoZIhvcN
# AQEBBQAEggEAgmsBSlZaPzfVoGNlqVEgI3lZLYMLM5E+KXbFKBSeYgKkUuy++gTo
# p2znTe8EU5PKnPO1o+bb6dx5Vc0iHFhWiZP/u0/vovncwfCgy7ecK5T7UgIIYZ6r
# r0abhmMLVHYs2wVCLo/AIfvONDN3oIt015brd7R479yO2KJfjYyReaO1eG2DhyGD
# tMQvZiszYAdXsEkyhORhjlriMZKHVyasttGvwPy3TmxYjN63u3c0THTjLeCa/zj6
# wAhfn7VfjNWwHBesLqKa8Uun+BdaBSL7bqIC/QGXyhPG4axchc8/NQak576y+T26
# czo3ldvxwhRPM3szzkJb3VKFpSALJWQpvg==
# SIG # End signature block
