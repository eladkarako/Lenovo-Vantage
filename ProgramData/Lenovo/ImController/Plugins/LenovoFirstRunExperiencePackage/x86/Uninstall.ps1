$PackageName = "LenovoFirstRunExperiencePackage"
$LogFileName = ($PackageName + (Get-Date -Format "-yyyy_MM_dd-HH-mm-ss") + "-uninstall.txt")
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
        Invoke-Item -Path $pathToLnk
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

#### /Shared Functions ####


#### LEGACY ITEMS ####

# Stop the current process if needed
function Stop-LegacyProcess($processName)
{ 
    Stop-Process -processName $processName
}

#### / LEGACY ITEMS ####


#### Lenovo Welcome Functions ####
$companyName = 'Lenovo'
$taskName    = 'LenovoWelcomeTask'
$welcomeTaskEXE  = 'LenovoWelcomeTask.exe'
$welcomeEXE      = 'LenovoWelcome.exe'
$shortcutName = 'Lenovo Welcome'

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
	#$path = "$env:localappdata\Lenovo\ImController\PluginData\LenovoFirstRunExperiencePackage"
	$userPublicPath = $env:public
	$userPath = Split-Path -Path $userPublicPath
	$userProfilePath = Join-Path -Path $userPath -ChildPath $DomainUser.Split('\')[1]
	$pathToFreTempFolder = Join-Path -Path $userProfilePath -ChildPath 'AppData\Local\Lenovo\ImController\PluginData\LenovoFirstRunExperiencePackage'
	if(Test-Path $pathToFreTempFolder)
    {
		Remove-Item -Path $pathToFreTempFolder -Force -Recurse
	}
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


Write-Log "UNINSTALL START - $PackageName"

# Stop the legacy process (if running)
Stop-LegacyProcess($welcomeEXE)
Stop-LegacyProcess($welcomeTaskEXE)

try
{
	Delete-TempFolder
	Delete-StartMenu
	Delete-ScheduledTask
	Delete-Registry
}
catch
{
	Write-Log "Exception happen..."
	Write-Log $_.Exception.Message
}

Write-Log "UNINSTALL COMPLETE - $PackageName"

# SIG # Begin signature block
# MIIcZQYJKoZIhvcNAQcCoIIcVjCCHFICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDFftl/WscVG4Hd
# I9g8HyhMupa557k703N9m/d8yGMDYKCCF2AwggPuMIIDV6ADAgECAhB+k+v7fMZO
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
# AQkEMSIEIDsJCxOiDGVqtp9pCmWXvMZ8/UUKzj+ov3A0gry2GsorMA0GCSqGSIb3
# DQEBAQUABIIBAJJ2/LdEulOokLGkNyoiGwejQySWj6NSZCdCOEFoG4xm5cH22V6Q
# GOwDLDnfXd2GJm9KaJS+T2y1sM3qVulc1hRyJ/+hv3gNvUutPGJK03asTUZUFs79
# Yjzk0meXVYjH4IdSayPTozjELJ/gQLLbtWYDS5a2jENWXt9aXQRJD8qyxtfJEVHA
# zqo7dmClTqeatHLJEL0mjfOfiXwVYHejsNKanDNSWsRk3PwG0HUaNpoYO4Gax5w2
# VTXYxuKAfB3WtGufSd6QlCeYMeYZsE7LutUxey5SEYPJdFF8wlQiABoqLI98D/8H
# DEoaGi7rjzBkuHLC6dau/mORTC82/lTjW3qhggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwMzE3MTEyMDA5
# WjAjBgkqhkiG9w0BCQQxFgQUClH4P5Hgqx/rvW9eol6d4IBjcMcwDQYJKoZIhvcN
# AQEBBQAEggEAeQArs8mfmpUEJKQSRcNLI/mjHdHl567iiBDfA5n73qx3tosJsR1g
# pOqLzU7xG9TxKW8jzHtAZbWKtM513Z8/8mJPIgAFB3p6TdZ3AYCw9nXi4N5xc9Ae
# 40ewpol7LAI0dYu7wuFvXSYJQ94sD5K2VfWQbIzfaBd5rJy8YrRHWSDLUK3w94P5
# lyxjknK2ebsx94lpG/KjqxFbaP/RBkBQZbrc+kjgEGdvnmeRrpkK2Vn+CbegKrQc
# QcnPcSlGXBJwdiUZnHnZhHmBjaUayrLxWSeyp+RG0OGYu3ukkIgY46tB9vCXNtql
# 4nUudLZ9690/bNP1daItZfIZE090VCQDsA==
# SIG # End signature block
