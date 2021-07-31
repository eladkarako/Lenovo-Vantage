########################################################################### 
#    Version 1.0 - 07/16/2018
#    Version 1.1 - 07/20/2018
#
#    ti_update_status.ps1: 
#
#    This script is designed to parse the most recent ThinInstaller log 
#    file and populate the Lenovo_Updates WMI class with status of updates
#    processed by ThinInstaller.  This class can then be inventoried by 
#    SCCM. 
#
#    Copyright Lenovo. All Rights Reserved.
########################################################################### 

###########################################################################
#    Functions
###########################################################################

#####################################
# Function to create class.
#####################################
function createclass {
    #make sure the Lenovo namespace exists
    $ns = [wmiclass]'root:__namespace'
    $sc = $ns.CreateInstance()
    $sc.Name = 'Lenovo'
    $sc.Put()

    #create Lenovo_Updates class insance in the Lenovo namespace 
    $myclass = New-Object System.Management.ManagementClass ("root\Lenovo", [string]::Empty, $null)
    $myclass["__CLASS"] = "Lenovo_Updates"
    $myclass.Qualifiers.Add("SMS_Report", $true)
    $myclass.Qualifiers.Add("SMS_Group_Name", "Lenovo_Updates")
    $myclass.Qualifiers.Add("SMS_Class_Id", "Lenovo_Updates")

    $myclass.Properties.Add("PackageID", [System.Management.CimType]::String, $false)
    $myclass.Properties.Add("Title", [System.Management.CimType]::String, $false)
    $myclass.Properties.Add("Status", [System.Management.CimType]::String, $false)
    $myclass.Properties.Add("AdditionalInfo", [System.Management.CimType]::String, $false)
	$myclass.Properties.Add("Version", [System.Management.CimType]::String, $false)
    $myclass.Properties.Add("Severity", [System.Management.CimType]::String, $false)
    
    $myclass.Properties["PackageID"].Qualifiers.Add("Key", $true)
    $myclass.Properties["PackageID"].Qualifiers.Add("SMS_Report", $true)
    $myclass.Properties["Title"].Qualifiers.Add("SMS_Report", $true)
    $myclass.Properties["Status"].Qualifiers.Add("SMS_Report", $true)
    $myclass.Properties["AdditionalInfo"].Qualifiers.Add("SMS_Report", $true)
	$myclass.Properties["Version"].Qualifiers.Add("SMS_Report", $true)
	$myclass.Properties["Severity"].Qualifiers.Add("SMS_Report", $true)

    $myclass.Put()
}

#####################################
# Function to add all update statuses 
# from log file to the WMI class
#####################################
function addstatus {
    # get current log file and parse

    # following path will need to be modified before implementing in production
    $updateHistory = "update_history.txt"

    Get-Content $updateHistory | ForEach-Object {
        $oneRecord = $_ -split " %-% "
        $packageid = $oneRecord[0]
        $title = $oneRecord[1]
        $status = $oneRecord[2]
        $additionalInfo = $oneRecord[3]
        $version = $oneRecord[4]
        $Severity = $oneRecord[5]
        try {
            $update = Get-WmiObject -Namespace root\Lenovo -Class Lenovo_Updates -Filter "PackageID = '$packageid'"
            if ($update.PackageID -eq $packageid) {
                if ($update.Status -ne $status -or $update.Title -ne $title -or $update.AdditionalInfo -ne $additionalInfo -or $update.Version -ne $version -or $update.Severity -ne $Severity) {
                    $update.Status = $status
                    $update.Title = $title
                    $update.AdditionalInfo = $additionalInfo
                    $update.Version = $version
                    $update.Severity = $Severity
                    $update.Put()
                }
            }
            else {
                Set-WmiInstance -Namespace root\Lenovo -Class Lenovo_updates -Arguments @{PackageID = $packageid; Title = $title; Status = $status; AdditionalInfo = $additionalInfo; Version = $version; Severity = $Severity} -PutType CreateOnly
            }
        }
        catch {
            "Did not add"
            $packageid + " " + $title + " " + $status
        }
    }

}


###########################################################################
#    Main
###########################################################################

# Create custom class if needed
[void](Get-WMIObject -Namespace root\Lenovo Lenovo_Updates -ErrorAction SilentlyContinue -ErrorVariable wmiclasserror)
if ($wmiclasserror) {
    try { 
        createclass 
    }
    catch {
        "Could not create WMI class"
        Exit 1
    }
}

addstatus

# Optional to execute a H/W inventory cycle - requires CM Client installed
#$SMSCli = [wmiclass] "\\.\root\ccm:SMS_Client"
#$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000001}")
