#Script by Mattias Westergren
# Info and prerequisite
# ONTAP provides a private REST API endpoint that can be used to access any CLI command trough skript languanges as Powershell, Python etc.
# This script uses the REST API CLI passtrough to fetch data and then convert it to a readable output, for autologin im using PoshKeePass Module to get data from KeePass that has passwords stored in an encrypted database.


#Skip certificate checks and trust all policys. We are on a private server afterall, NOT recomended on open platforms.
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


#Import PoshKeePass module for autologin, keep this way incase the module does not load for some reason.
Import-Module PoShKeePass -Force

#Output script, change path to what you prefer. Also assigns date to the file
$OutPutFile = "C:\Proact\Statusmail historik\2024\Netapp-$(get-date -f yyyy-MM-dd)_log.txt"
$i = 1
while (Test-Path $OutPutFile) {
    $OutPutFile =  "C:\Proact\Statusmail historik\2024\Netapp-$(get-date -f yyyy-MM-dd)_log$i.txt"
    $i++
}

# Output script to txtfile, also writes in terminal
function Write-ToConsoleAndFile {
    param(
        $Text,
        $File,
        $Color = "white"
    )
    Write-Host $Text -ForegroundColor $Color
    $Text | Out-File $File -Append -Force
}

#Add cluster IP/DNS (DNS prefered,more readable output) that you want the script to check, add them in lines one line for each cluster.
$Cluster_List = Get-Content "C:\Proact\clusterlist.txt"


# Store the Entries into a variable
$KpEntries = Get-KeePassEntry -KeePassEntryGroupPath 'Database' -DatabaseProfileName Tranås

# Define the entry titles from keepass for which you want to retrieve the passwords 
$EntryTitles = @("172.16.51.11", "172.16.51.21", "172.16.51.76", "172.16.51.12", "172.16.51.46")

# Empty variable to hold the passwords
$Passwords = @()

# Loop through each entry title and retrieve the password from $kpentries
foreach ($EntryTitle in $EntryTitles) {
    $Entry = $KpEntries | Where-Object { $_.Title -eq $EntryTitle }
    $Password = $Entry | Select-Object -ExpandProperty Password
    $Passwords += $Password
}

# Create credentials for each password variable, if more entries/clusterpasswords exist in keepass just add on more rows 6,7,8 etc
$Username = "admin"
$Username1 = "support106"
$Credential1 = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Passwords[0]
$Credential2 = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Passwords[1]
$Credential3 = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Passwords[2]
$Credential4 = New-Object System.Management.Automation.PSCredential -ArgumentList $Username1, $Passwords[3]
$Credential5 = New-Object System.Management.Automation.PSCredential -ArgumentList $Username1, $Passwords[4]
#$Credential6 = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Passwords[5]

Set-ExecutionPolicy Unrestricted -force | Out-Null

#will run below script on each cluster in the Cluster_list until all is run, if more clusters exist that need to be checked just add on more rows 6,7,8 etc
ForEach ($Cluster in $Cluster_List) {

        $CredObject = $null

        If ($Cluster -imatch "172.16.51.11") {
            $CredObject = $Credential1
        }
        elseif ($Cluster -imatch "172.16.51.21") {
            $CredObject = $Credential2
        }
        elseif ($Cluster -imatch "172.16.51.76") {
            $CredObject = $Credential3
        }
        elseif ($Cluster -imatch "172.16.51.12") {
            $CredObject = $Credential4
        }
        elseif ($Cluster -imatch "172.16.51.46") {
            $CredObject = $Credential5
        }
          #DEBUG LOGIN
        <#// For trouble shooting cluster connection. Check if we have a valid credential object. If problem here 1.Check IP/cluster name. 2. Check Keepass for errors 3. Check overall syntax of script in settings 4. Check if REST API has problems.
        #// If data is getting fetched as it should, then for now ignore any errors in the terminal.
        if ($CredObject) {
        Write-Host "Connecting to $Cluster with username: $($CredObject.UserName)"
        Try {
            Invoke-RestMethod "https://$Cluster" -Credential $CredObject
        } Catch {
            Write-Host "Error connecting to $($Cluster): $($_.Exception.Message)"
            continue
        }
    } else {
        Write-Host "No credentials found for $Cluster"
        return # Exit the script if no credentials were found for a cluster in the list
    }#>

    # Get today's date and version of ONTAP
    $Date = Get-Date -format yyyy.MM.dd.hh.mm
    Write-ToConsoleAndFile -text "TimeStamp:",$Date -file $OutputFile
    Write-ToConsoleAndFile -text "============= Ontap System Info ==============" -file $OutputFile

    $GetNode = "https://$Cluster/api/private/cli/node?fields=location,model,serialnumber,uptime,health,eligibility,&pretty=false"
    $NodeTable = Invoke-RestMethod $GetNode -Credential $CredObject

    $GetVersion = "https://$Cluster/api/private/cli/version?fields=node,version,&pretty=false"
    $VersionTable = Invoke-RestMethod $GetVersion -Credential $CredObject

    $GetAutosupport = "https://$Cluster/api/private/cli/autosupport?fields=state,&pretty=false"
    $AutosupportTable = Invoke-RestMethod $GetAutosupport -Credential $CredObject

    # Assuming a single AutoSupport state for the whole cluster
    $AutosupportState = $AutosupportTable.records.state

    # Table with node names versions
    $VersionMap = @{}
    foreach ($VersionInfo in $VersionTable.records) {
        $VersionMap[$VersionInfo.node] = $VersionInfo.version
    }

    #Track if any system's AutoSupport is disabled
    $AnyDisabledAutosupport = $false

    # Check for any "disabled" states
    foreach ($Record in $AutosupportTable.records) {
        if ($Record.state -eq "disable") {
            $AnyDisabledAutosupport = $true
        }
    }
    #AutoSupport state based on the findings
    $AutosupportState = if ($AnyDisabledAutosupport) { "Disable" } else { "Enable" }

    $NodeInfo = @()

    foreach ($Node in $NodeTable.records) {
        # Convert uptime from seconds to a more readable format
        $UptimeInSeconds = $Node.uptime
        $UptimeDays = [math]::Floor($UptimeInSeconds / (60 * 60 * 24))
        $UptimeHours = [math]::Floor(($UptimeInSeconds % (60 * 60 * 24)) / (60 * 60))
        $UptimeFormatted = "$UptimeDays days, $UptimeHours hours"

        # Retrieve the version for the current node
        $NodeVersion = $VersionMap[$Node.node]

        # Create a custom object for each node
        $NodeObject = [PSCustomObject]@{
            Node = $Node.node
            Location = $Node.location
            Model = $Node.model
            Version = $NodeVersion
            SerialNumber = $Node.serialnumber
            Uptime = $UptimeFormatted
            Health = $Node.health
            Eligibility = $Node.eligibility
            AutosupportState = $AutosupportState
        }

        # Add the node object to the NodeInfo array
        $NodeInfo += $NodeObject
    }

    # Format each node's information including AutoSupport state
    $FormattedOutput = $NodeInfo | ForEach-Object {
        $FormattedRecord = "`r`nNode: $($_.Node)`r`nVersion: $($_.Version)`r`nLocation: $($_.Location)`r`nModel: $($_.Model)`r`nSerialNumber: $($_.SerialNumber)`r`nUptime: $($_.Uptime)`r`nHealth: $($_.Health)`r`nEligibility: $($_.Eligibility)`r`nAutosupportState: $($_.AutosupportState)`r`n"
        return $FormattedRecord
    }

    # Output the formatted information
    Write-ToConsoleAndFile -text "$FormattedOutput" -file $OutputFile



        Write-ToConsoleAndFile -text "============= Aggregate information ==============" -file $OutputFile
    $GetAggregate = "https://$Cluster/api/private/cli/aggr?fields=aggregate,size,usedsize,node,root,volcount,diskcount,availsize,percent-used,raidstatus,&pretty=false"
    $AggregateTable = Invoke-RestMethod $GetAggregate -Credential $CredObject

    function RoundToNearestHalfOrFullTB($SizeInTB) {
        $Base = [math]::Floor($SizeInTB)
        $Fraction = $SizeInTB - $Base

        if ($Fraction -lt 0.05) {
            # Very close to the lower number, just round down
            return $Base
        } elseif ($Fraction -ge 0.95) {
            # Close enough to the next whole number, round up
            return [math]::Ceiling($SizeInTB)
        } elseif ($Fraction -ge 0.45) {
            # Closer to the higher half, but, round to the lower half
            return $Base + 0.5
        } else {
            # Not close enough to half, keep it as is but rounded down to the nearest half
            return $Base
        }
    }

    $AggregateInfo = @()

    foreach ($Record in $AggregateTable.records) {
        if ($Record.root) {
            continue
        }

        $TotalSizeTB = RoundToNearestHalfOrFullTB($Record.size / 1TB)
        $AvailSizeTB = RoundToNearestHalfOrFullTB($Record.availsize / 1TB)
        $UsedSizeTB = RoundToNearestHalfOrFullTB($Record.usedsize / 1TB)
        $UsedPercent = [math]::Round($Record.usedsize / $Record.size * 100, 0)

        $TotalSizeStr = if ($TotalSizeTB -eq [math]::Round($TotalSizeTB)) { "$TotalSizeTB TB" } else { "$TotalSizeTB TB" }
        $AvailSizeStr = if ($AvailSizeTB -eq [math]::Round($AvailSizeTB)) { "$AvailSizeTB TB" } else { "$AvailSizeTB TB" }
        $UsedSizeStr = if ($UsedSizeTB -eq [math]::Round($UsedSizeTB)) { "$UsedSizeTB TB" } else { "$UsedSizeTB TB" }

        $AggregateObject = [PSCustomObject]@{
            Aggregate = $Record.aggregate
            Node = $Record.node
            TotalSize = "${TotalSizeTB} TB"
            Available = "${AvailSizeTB} TB"
            Used = "${UsedPercent}%"
            Usedsize = "${UsedSizeStr} "
            Disks = $Record.diskcount
            Volumes = $Record.volcount
            RaidType = $Record.raidstatus
        }

        $AggregateInfo += $AggregateObject
    }

    # Convert to table format, convert to string, and append to file
    $AggregateSummary = $AggregateInfo | Format-Table -Property Node, Aggregate, TotalSize, Available, Used, Usedsize, Disks, Volumes, RaidType -AutoSize | Out-String
    Write-ToConsoleAndFile -text "$AggregateSummary" -file $OutputFile

    Write-ToConsoleAndFile -text "============= Overall Health Check ==============`r`n" -file $OutputFile

    Write-Host "============= Cluster ring check ==============" #Sorting in categories make terminal easier to look at

    # Get cluster ring health (shows a summarized comparison of the overall base node health, timings, synching to other nodes in the same cluster etc)
    $GetClusterRing = "https://$Cluster/api/private/cli/cluster/ring?fields=node,unitname,epoch,db_trnxs,db_epoch,online,master,&pretty=false"
    $ClusterRingTable = Invoke-RestMethod $GetClusterRing -Credential $CredObject
    $ClusterRingResult = $ClusterRingTable

    # Group records by unitname
    $GroupedRecords = $ClusterRingTable.records | Group-Object -Property unitname

    # Track overall health
    $OverallHealthOk = $true
    $Discrepancies = @()

    # Go over each group and compare records
    foreach ($Group in $GroupedRecords) {
        $UnitName = $Group.Name
        # Use the first record in the group as a reference for comparison
        $ReferenceRecord = $Group.Group[0]

        Write-Host "Comparing unitname: $UnitName"
        foreach ($Record in $Group.Group) {
            $ComparisonResult = "MATCH"
            if ($Record.epoch -ne $ReferenceRecord.epoch -or $Record.db_epoch -ne $ReferenceRecord.db_epoch -or $Record.db_trnxs -ne $ReferenceRecord.db_trnxs) {
                $OverallHealthOk = $false
                $ComparisonResult = "DISCREPANCY"
                $DiscrepancyMessage = "Discrepancy found in $UnitName [Record Node: $($Record.node)] epoch, db_epoch, or db_trnxs does not match reference."
                $Discrepancies += $DiscrepancyMessage
            }
            # Output for debugging
            Write-Host "[$ComparisonResult] Node: $($Record.node), Epoch: $($Record.epoch), DB_Epoch: $($Record.db_epoch), DB_Trnxs: $($Record.db_trnxs)"
        }
    }

    # Summarize findings
    if ($OverallHealthOk) {
        $RingHealthSummary = "Cluster ring health OK"
    } else {
        $RingHealthSummary = "Cluster ring health issues detected:`n" + ($Discrepancies -join "`n")
    }

    # Output health summary
    Write-ToConsoleAndFile -text "$RingHealthSummary `r`n" -file $OutputFile

    # Chassis health check
    Write-Host "============= Chassis FRU health check ==============`r`n" # Sorting in categories make the terminal easier to look at

    # Define the fields to retrieve for each chassis
    $ChassisFieldList = @(
        "node",
        "serial_number",
        "fru_name",
        "type",
        "name",
        "state",
        "status",
        "display_name",
        "monitor",
        "model",
        "shared",
        "chassis_id",
        "additional_info",
        "connected_nodes",
        "num_nodes"
    )

    # Convert the field list to a comma-separated string for the API request
    $ChassisFieldListString = $ChassisFieldList -join ","
    # Construct the API endpoint URL
    $GetChassisUrl = "https://$Cluster/api/private/cli/system/chassis/fru?fields=$ChassisFieldListString&pretty=false"
    # Invoke the REST method to get the chassis data
    $ChassisTable = Invoke-RestMethod $GetChassisUrl -Credential $CredObject

    # Initialize variables
    $ChassisHealthOk = $true
    $ChassisHealthDiscrepancies = @()

    # Check each chassis record
    foreach ($Record in $ChassisTable.records) {
        # Debug output before potentially skipping the record
        Write-Host "Evaluating chassis: $($Record.display_name) with state: $($Record.state) and status: $($Record.status)"

        if ($Record.state -notin @("ok", "GOOD") -or $Record.status -notin @("ok", "GOOD")) {
            $ChassisHealthOk = $false
            $DiscrepancyMessage = "Chassis health issue detected: $($Record.display_name) state is $($Record.state), status is $($Record.status).`r`nRecord Details: $(ConvertTo-Json $Record)"
        
            # Debug output for when a health issue is found
            Write-Host "Found issue: $DiscrepancyMessage"

            $ChassisHealthDiscrepancies += $DiscrepancyMessage
        }
    }

    # Summarize findings
    $ChassisSummary = if ($ChassisHealthOk) {
        "Chassis component check OK"
    } else {
        "Chassis health issues detected:`n" + ($ChassisHealthDiscrepancies -join "`n")
    }

    # Output summary for chassis health
    Write-ToConsoleAndFile -text "$ChassisSummary`r`n" -file $OutputFile

    # Memory FRU health check
    Write-Host "============= Memory FRU health check ==============`r`n"

    # Define the fields to retrieve for each memory check
    $MemoryFieldListString = "node,serial-number,fru-name,fru-type,fru-status,display-name,location,additional-info,reason"
    $GetFruMemoryUrl = "https://$Cluster/api/private/cli/system/fru-check?fields=$MemoryFieldListString&pretty=false"
    $FruMemoryTable = Invoke-RestMethod $GetFruMemoryUrl -Credential $CredObject

    # Initialize variables
    $MemoryHealthOk = $true
    $MemoryHealthDiscrepancies = @()

    # Check each memory FRU record
    foreach ($Record in $FruMemoryTable.records) {
        # Debug output to show it's checking the hardware
        Write-Host "Checking FRU Type: $($Record.fru_type) Name: $($Record.fru_name) Status: $($Record.fru_status)"

        if ($Record.fru_status -notin @("pass")) {
            $MemoryHealthOk = $false
            $DiscrepancyMessage = "Memory FRU issue detected in $($Record.fru_name) of type $($Record.fru_type) with status: $($Record.fru_status)."
        
            # Debug output for when a health issue is found
            Write-Host "Degraded hardware detected: $DiscrepancyMessage"

            $MemoryHealthDiscrepancies += $DiscrepancyMessage
        }
    }

    # Summarize findings
    $MemoryFruSummary = if ($MemoryHealthOk) {
        "Memory check OK"
    } else {
        "Memory FRU health issues detected:`n" + ($MemoryHealthDiscrepancies -join "`n")
    }

    # Output summary for memory FRU health
    Write-ToConsoleAndFile -text "$MemoryFruSummary`r`n" -file $OutputFile
    
         Write-Host "============= Subsystem health check ==============`r`n" #Sorting in categories make terminal easier to look at

    # Get subsystem overall health
    $GetSystem = "https://$Cluster/api/private/cli/system/health/subsystem?fields=health,subsystem,&pretty=false"
    $SystemTable = Invoke-RestMethod $GetSystem -Credential $CredObject

    # Initialize variables
    $SubsystemHealthOk = $true
    $HealthDiscrepancies = @()

    # Check each subsystem record
    foreach ($Record in $SystemTable.records) {
        # Debug output before potentially skipping the record
        Write-Host "Evaluating subsystem: $($Record.subsystem) with health status: $($Record.health)"

        # Skip specific subsystems based on name, workaround for Tranås internal disk issue..
        if ($Record.subsystem -like "*sas_connect*") {
            Write-Host "Skip sas_connect due to DISK REDUNDANCY FAILED issue: $($Record.subsystem)"
            continue
        }

        if ($Record.health -ne "ok") {
            $SubsystemHealthOk = $false
            $DiscrepancyMessage = "Subsystem health issue detected: $($Record.subsystem) health is $($Record.health)."
        
            # Debug output for when a health issue is found
            Write-Host "Found issue: $DiscrepancyMessage"

            $HealthDiscrepancies += $DiscrepancyMessage
        }
    }

    # Summarize findings
    if ($SubsystemHealthOk) {
        $SubsystemSummary = "Subsystem check OK"
    } else {
        $SubsystemSummary = "Subsystem health issues detected:`n" + ($HealthDiscrepancies -join "`n")
    }

        # Output summary for subsystem health
        Write-ToConsoleAndFile -text "$SubsystemSummary`r`n" -file $OutputFile
    
    Write-Host "============= Network port check ==============`r`n" # Sorting in categories make terminal easier to look at



    # Define the fields to retrieve for each chassis
    $PortFieldList = @(
    "node",
    "port",
    "link",
    "mtu",
    "autonegotiate-admin",
    "autonegotiate-oper",
    "duplex-admin",
    "duplex-oper",
    "speed-admin",
    "speed-oper",
    "flowcontrol-admin",
    "flowcontrol-oper",
    "mac",
    "type",
    "ifgrp-node",
    "ifgrp-port",
    "ifgrp-distr-func",
    "ifgrp-mode",
    "vlan-node",
    "vlan-port",
    "vlan-tag",
    "remote-device-id",
    "ipspace",
    "broadcast-domain",
    "mtu-admin",
    "health-status",
    "ignore-health-status",
    "health-degraded-reasons",
    "vm-network-name",
    "rdma-protocols"
    )

    # Convert the field list to a comma-separated string for the API request
    $GetPortInfoString = $PortFieldList -join ","

    # Get Port status
    $GetPortInfoUrl = "https://$Cluster/api/private/cli/network/port?fields=$GetPortInfoString,&pretty=false"
    $PortStatus = Invoke-RestMethod $GetPortInfoUrl -Credential $CredObject

    # Initialize variable to track overall port health
    $PortHealthOk = $true
    $PortProblemRecords = @()

    # Go over each port record and check conditions
    foreach ($PortRecord in $PortStatus.records) {
        Write-Host "Checking Port: $($PortRecord.port) on Node: $($PortRecord.node)"

        if ($PortRecord.link -eq "down" -and [string]::IsNullOrEmpty($PortRecord.broadcast_domain)) {
            Write-Host "Port Link is Down but Broadcast Domain is Empty, Ignoring"
            continue
        }

        if ($PortRecord.link -eq "up" -and $PortRecord.health_status -eq "healthy") {
            Write-Host "Port Link is Up and ports are healthy"
        } else {
            Write-Host "Issue Detected: Port Link is Down or Health Status is not healthy on Port: $($PortRecord.port)"
            # Add the full JSON representation of the problematic port record
            $PortProblemRecords += $PortRecord | ConvertTo-Json
            $PortHealthOk = $false
        }
    }

    # Summarize findings
    if ($PortHealthOk) {
        $PortSummary = "Port check OK."
    } else {
        $PortSummary = "Port issues detected:`n" + ($PortProblemRecords -join "`n")
    }

    # Port Output
    Write-ToConsoleAndFile -text "$PortSummary`r`n" -file $OutputFile


    Write-Host "============= Network interface check ==============`r`n" # Sorting in categories make terminal easier to look at


    # Get network status
    $GetNetworkInfo = "https://$Cluster/api/private/cli/network/interface?fields=broadcast-domain,is-home,status-admin,status-oper,vserver,curr-node,curr-port,firewall-policy,ipspace,failover-policy,auto-revert,&pretty=false"
    $NetworkStatus = Invoke-RestMethod $GetNetworkInfo -Credential $CredObject

    # Initialize variable to track overall network health
    $NetworkHealthOk = $true
    $ProblemRecords = @()

    # Define nodes to ignore when status_oper is 'down'
    $IgnoreNodes = @(
        "nmc1-01",
        "nmc1-02",
        "nmc2-01",
        "nmc2-02"
    )

    # Go over each network record and check conditions
    foreach ($Record in $NetworkStatus.records) {
        Write-Host "Checking Network Interface: $($Record.curr_port) on Node: $($Record.curr_node)"

        # Check if the node is in the ignore list and the operational status is 'down'
        if ($IgnoreNodes -contains $Record.curr_node -and $Record.status_oper -eq "down") {
            # Additional check for admin status when node is on ignore list
            if ($Record.status_admin -ne "up") {
                Write-Host "Node $($Record.curr_node) with port $($Record.curr_port) is down with Status_Admin also down. Reporting..."
                $ProblemRecords += $Record | ConvertTo-Json
                $NetworkHealthOk = $false
                continue
            } else {
                Write-Host "Node $($Record.curr_node) with port $($Record.curr_port) is in the ignore list with status down but Admin_Status up. Skipping..."
                continue
            }
        }

        # Check conditions only if broadcast_domain value is not empty, if empty ignore
        if ($Record.broadcast_domain) {
            Write-Host "Checking Broadcast Domain: $($Record.broadcast_domain)"
            if ($Record.status_oper -ne "up" -or $Record.is_home -ne $true -or $Record.status_admin -ne "up") {
                $AdditionalCheck = $true
                if ($Record.vserver) {
                    # Get Vserver info about the operational status and subtype of SVM
                    $GetVserverInfo = "https://$Cluster/api/private/cli/vserver?fields=vserver,operational-state-stopped-reason,comment,&pretty=false"
                    $VserverInfoStatus = Invoke-RestMethod $GetVserverInfo -Credential $CredObject
            
                    foreach ($VserverRecord in $VserverInfoStatus.records) {
                        if ($VserverRecord.vserver -eq $Record.vserver) {
                            # Check if the operational_state_stopped_reason is "dp_destination_not_started" or empty
                            if ($VserverRecord.operational_state_stopped_reason -eq "dp_destination_not_started" -or $VserverRecord.comment -eq "DR") {
                                $AdditionalCheck = $false
                                Write-Host "Skipping due to DR state for Vserver: $($VserverRecord.vserver)"
                                break
                            }
                        }
                    }
                }
        
                # If the additional check passes, proceed with reporting the problem
                if ($AdditionalCheck) {
                    Write-Host "Problem Detected: Admin Status: $($Record.status_admin), Operational Status: $($Record.status_oper), Is Home: $($Record.is_home)"
                    $NetworkHealthOk = $false
                    $ProblemRecords += $Record | ConvertTo-Json
                }
            }
        } else {
            Write-Host "Broadcast Domain not specified for Interface: $($Record.curr_port)"
        }
    }

    # Summarize findings
    if ($NetworkHealthOk) {
        $NetworkSummary = "Network Interface check OK"
    } else {
        $NetworkSummary = "Network Interface issues detected:`n" + ($ProblemRecords -join "`n")
    }

    # Network Output
    Write-ToConsoleAndFile -text "$NetworkSummary`r`n" -file $OutputFile

    Write-ToConsoleAndFile -text "============= Volumes Above 80% ==============`r`n" -file $OutputFile

    $GetVolumes = "https://$Cluster/api/private/cli/volume?fields=node,vserver,volume,aggregate,available,total,percent-used,autosize-mode,autosize-grow-threshold-percent,autosize-shrink-threshold-percent,&pretty=false"
    $VolumeTable = Invoke-RestMethod $GetVolumes -Credential $CredObject

    $FilteredVolumes = $VolumeTable.records | Where-Object {
        $AboveThreshold = $_.'percent_used' -gt 80
        $AutosizeOff = $_.autosize_mode -eq "off"
        $GrowShrink = $_.autosize_mode -eq 'grow_shrink'
        $GrowThresholdPopulated = $_.autosize_grow_threshold_percent -ne $null
        $ShrinkThresholdPopulated = $_.autosize_shrink_threshold_percent -ne $null

        $Result = $AboveThreshold -and (
            ($AutosizeOff -and $GrowThresholdPopulated -and $ShrinkThresholdPopulated) -or
            (-not $GrowThresholdPopulated -or -not $ShrinkThresholdPopulated) -and -not $GrowShrink
        )

        return $Result
    }

    if ($FilteredVolumes.Count -eq 0) {
        Write-ToConsoleAndFile -text "No volumes are above 80% `r`n" -file $OutputFile
    } else {
        Write-ToConsoleAndFile -text "Volumes above 80% without autogrow enabled, correction is needed `r`n" -file $OutputFile

        $VolumeInfo = @()
        
        #Function to ConvertTo-ReadableSize
        function ConvertTo-ReadableSize {
        param(
            [Parameter(Mandatory=$true)]
            [int64]$SizeInBytes
        )

        $sizes = @("Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        $order = 0

        while ($SizeInBytes -ge 1024 -and $order -lt $sizes.Count) {
            $order++
            $SizeInBytes = $SizeInBytes / 1024
        }

        "{0:N2} {1}" -f $SizeInBytes, $sizes[$order]
    }

    $bytes = 1500000
    $readableSize = ConvertTo-ReadableSize -SizeInBytes $bytes


    foreach ($Volume in $FilteredVolumes) {
        $AvailableSize = ConvertTo-ReadableSize $Volume.available
        $TotalSize = ConvertTo-ReadableSize $Volume.total
        $UsedPercent = "$($Volume.'percent_used')%"
        $AutosizeMode = $Volume.'autosize_mode'
        $GrowThreshold = $Volume.'autosize_grow_threshold_percent'
        $ShrinkThreshold = $Volume.'autosize_shrink_threshold_percent'
        $Dedupe = if ($Volume.'anti_ransomware_state' -eq 'enabled') { 'True' } else { 'False' }

        # Create a custom object for each volume
        $VolumeObject = [PSCustomObject]@{
            Node = $Volume.node
            Volume = $Volume.volume
            Total = $TotalSize
            Used = $UsedPercent
            Available = $AvailableSize
            Dedupe = $Dedupe
            Vserver = $Volume.vserver
            Autogrowstatus = $AutosizeMode

        }

        $VolumeInfo += $VolumeObject
    }
        # Output formatted records
        $VolumeInfo | Format-Table -Property Node, Volume, Total, Used, Available, Dedupe, Vserver, Autogrowstatus -AutoSize | Out-String | ForEach-Object { Write-ToConsoleAndFile -text $_ -file $OutputFile }
    }

    # Checking for inodes above 90% Ontap starts giving warnings at about 80% if the volume is needing to be raised.
    #SnapMirror Type-XDP destination volumes will increase their inode count when the SnapMirror source volume iused value is is greater than 90% of the destination volume's max inode count​​
    #The inode count will remain unchanged if the iused value of the source volume is not greater than approximately 90% of the max inode count of the destination volume
    # setting this to only report if above 90%, but if EMS messages being generated, it also should be looked at, could be a settings is missing on that volume so it does not autoraise at all.

    Write-ToConsoleAndFile -text "============= Inodes/files Above 90% ==============`r`n" -file $OutputFile
    $GetVolumes = "https://$Cluster/api/private/cli/volume?fields=node,vserver,volume,files,files-used,&pretty=false"
    $VolumeTable = Invoke-RestMethod $GetVolumes -Credential $CredObject

    $FilteredFilesVolumes = $VolumeTable.records | Where-Object {
        $FilesMax = $_.files
        $FilesUsed = $_.'files_used'
    
        # Debug output
        Write-Host "FilesMax: $FilesMax, FilesUsed: $FilesUsed"
    
        # Check if $FilesMax is not empty and not zero to avoid division by zero error
        if ([string]::IsNullOrEmpty($FilesMax) -eq $false -and $FilesMax -ne 0) {
            $FilesUsedPercent = ($FilesUsed / $FilesMax) * 100

            # Percent value to check for files above X value
            $FilesUsageAboveThreshold = $FilesUsedPercent -gt 90
            return $FilesUsageAboveThreshold
        }
        else {
            return $false  # Skip volumes where $FilesMax is empty or zero
        }
    }

    if ($FilteredFilesVolumes.Count -eq 0) {
        Write-ToConsoleAndFile -text "No volumes are above 90% file usage`r`n" -file $OutputFile
    } else {
        Write-ToConsoleAndFile -text "Volumes above 90% file usage, correction is needed `r`n" -file $OutputFile

        $FileUsageInfo = @()

        foreach ($Volume in $FilteredFilesVolumes) {
            $FilesUsedPercentFormatted = "{0:N2}%" -f (($Volume.'files_used' / $Volume.files) * 100)

            # Create a custom object for each volume
            $VolumeFileUsageObject = [PSCustomObject]@{
                Volume = $Volume.volume
                FilesMax = $Volume.files
                FilesUsed = $Volume.'files_used'
                UsedPercent = $FilesUsedPercentFormatted
                Vserver = $Volume.vserver
                Node = $Volume.node
            }

            $FileUsageInfo += $VolumeFileUsageObject
        }

        # Output formatted records for inodes
        $FileUsageInfo | Format-Table -Property Node, Volume, UsedPercent, FilesUsed, FilesMax,  Vserver -AutoSize | Out-String | ForEach-Object { Write-ToConsoleAndFile -text $_ -file $OutputFile }
    }


    # Checking for SnapMirror problems
    Write-ToConsoleAndFile -text "============= Snapmirror lagtime & problems ==============`r`n" -file $OutputFile

    # Prepare for API call
    $SnapMirrorFields = @(
        "source-path",
        "source-vserver",
        "source-volume",
        "destination-path",
        "destination-vserver",
        "destination-volume",
        "type",
        "vserver",
        "policy-type",
        "policy",
        "throttle",
        "state",
        "status",
        "newest-snapshot-timestamp",
        "exported-snapshot-timestamp",
        "healthy",
        "last-transfer-type",
        "last-transfer-size",
        "last-transfer-duration",
        "lag-time",
        "destination-volume-node",
        "update-successful-count",
        "update-failed-count",
        "resync-successful-count",
        "resync-failed-count",
        "break-successful-count",
        "break-failed-count",
        "total-transfer-bytes",
        "total-transfer-time-secs",
        "unhealthy-reason"
    )

    $SnapQueryString = $SnapMirrorFields -join ","
    $GetSnapmirrorUrl = "https://$Cluster/api/private/cli/snapmirror?fields=$SnapQueryString&pretty=false"
    $SnapmirrorData = Invoke-RestMethod -Uri $GetSnapmirrorUrl -Credential $CredObject

    # Function to convert ISO8601 duration to Days:Hours:Minutes:Seconds
    function Convert-ISO8601ToCustomFormat {
        param ([string]$Iso8601Duration)
        try {
            $LagTime = [System.Xml.XmlConvert]::ToTimeSpan($Iso8601Duration)
            $Days = $LagTime.Days
            $Hours = $LagTime.Hours.ToString().PadLeft(2, '0')
            $Minutes = $LagTime.Minutes.ToString().PadLeft(2, '0')
            $Seconds = $LagTime.Seconds.ToString().PadLeft(2, '0')
            return "${Days} days ${Hours}:${Minutes}:${Seconds}"
        }
        catch {
            Write-Host "Invalid ISO 8601 duration format: $Iso8601Duration"
            return "Invalid format"
        }
    }

    # Go over each SnapMirror entry
    foreach ($SnapmirrorEntry in $SnapmirrorData.records) {
        if (-not [string]::IsNullOrWhiteSpace($SnapmirrorEntry.lag_time)) {
            $LagTime = [System.Xml.XmlConvert]::ToTimeSpan($SnapmirrorEntry.lag_time)
            if ($LagTime.TotalHours -gt 24) {
                $ConvertedLagTime = Convert-ISO8601ToCustomFormat -Iso8601Duration $SnapmirrorEntry.lag_time
                $SourceLocation = ($SnapmirrorEntry.source_path -replace '.+:', '')
                $DestinationLocation = ($SnapmirrorEntry.destination_path -replace '.+:', '')
            
                $SnapEntry = [PSCustomObject]@{
                    SourceLocation = $SourceLocation
                    DestinationLocation = $DestinationLocation
                    LagTime = $ConvertedLagTime
                    Type = $SnapmirrorEntry.type
                    Vserver = $SnapmirrorEntry.vserver
                    PolicyType = $SnapmirrorEntry.policy_type
                    State = $SnapmirrorEntry.state
                    Status = $SnapmirrorEntry.status
                    Healthy = $SnapmirrorEntry.healthy
                    DestinationVolumeNode = $SnapmirrorEntry.destination_volume_node
                    UnhealthyReason = $($SnapMirrorEntry.unhealthy_reason)
                }

                # Formatted log entry string
                $UnhealthySnapmirror = [PSCustomObject]@{
                    Healthy = $($SnapEntry.Healthy)
                    SourceLocation = $($SnapEntry.SourceLocation)
                    DestinationLocation = $($SnapEntry.DestinationLocation)
                    LagTime = $($SnapEntry.LagTime)
                    Type = $($SnapEntry.Type)
                    Vserver = $($SnapEntry.Vserver)
                    PolicyType = $($SnapEntry.PolicyType)
                    State = $($SnapEntry.State)
                    Status = $($SnapEntry.Status)
                    DestinationVolumeNode = $($SnapEntry.DestinationVolumeNode)
                    UnhealthyReason = $($SnapEntry.UnhealthyReason)
                }

              # Outputting the formatted string
                Write-ToConsoleAndFile -text "Lag-time above 24hours found!`r`n"-file $OutputFile
                Write-ToConsoleAndFile -text $UnhealthySnapmirror -file $OutputFile     
            } else {
                Write-Host "Entry $($SnapmirrorEntry.source_path) Lag checked, below 24h $ConvertedLagTime"
            }
        } else {
            Write-Host "Entry $($SnapmirrorEntry.source_path) has no 'lag_time' value or it's invalid. check SnapmirrorData variable"
        }
    }
    # Output fetched SnapMirror data count
    Write-Host "Fetched SnapMirror Data: $($SnapmirrorData.records.Count) entries"
    Write-ToConsoleAndFile -text "No snapMirror problems found.`r`n" -file $OutPutFile

   # Snapshot check problems
    Write-ToConsoleAndFile -text "============= Snapshot problems ==============`r`n" -file $OutPutFile

    # Fields to retrieve
    $SnapFieldList = @(
    "node",
    "vserver",
    "volume",
    "snapshot",
    "create-time",
    "busy",
    "owners",
    "size",
    "blocks",
    "usedblocks",
    "comment",
    "is-7-mode",
    "snapmirror-label",
    "state",
    "is-constituent",
    "expiry-time",
    "snaplock-expiry-time"
    )

    # Keywords to track
    $SnapshotKeywords = @(
    "Veeam", 
    "Anti_ransomware_backup", 
    "ransomware"
    "anti-ransomware-main-backup"
    "Anti"
    )

    # Convert the field list to a comma-separated string for the API request
    $SnapFieldListString = $SnapFieldList -join ","
    $GetSnapshotUrl = "https://$Cluster/api/private/cli/snap?fields=$SnapFieldListString&pretty=false"
    # Invoke the REST method to get the snapshot data
    $SnapshotTable = Invoke-RestMethod $GetSnapshotUrl -Credential $CredObject

    $CurrentDate = Get-Date
    $FilteredSnapshots = @() # Initialize an array to hold matching snapshots

    foreach ($SnapshotRecord in $SnapshotTable.records) {

    # Exception for specific nodes if needed
    if ($SnapshotRecord.node -eq "cluster4-01" -or $SnapshotRecord.node -eq "cluster4-02") {
        # Log and continue to the next record without processing this one
        #Debug
        #Write-Host "Ignoring snapshot from node $($SnapshotRecord.node)."
        continue
    }

    # Directly parse the 'create_time' using the exact format in the record field (not optimal)
    $ParsedDateTime = [datetime]::ParseExact($SnapshotRecord.'create_time', 'yyyy-MM-ddTHH:mm:ssK', [Globalization.CultureInfo]::InvariantCulture)

    $SnapshotCreationAge = ($CurrentDate - $ParsedDateTime).Days

    $IsKeywordMatch = $false
    foreach ($Keyword in $SnapshotKeywords) {
        if ($SnapshotRecord.PsObject.Properties.Value -join " " -match $Keyword) {
            $IsKeywordMatch = $true
            break
        }
    }

    if ($IsKeywordMatch -and $SnapshotCreationAge -gt 30) {
        # Add the matching record to the array if it's older than 30 days and matches a keyword
        $FilteredSnapshots += $SnapshotRecord
        }
    }

    # Convert the array of matching snapshots to JSON
    $SnapshotsJson = $FilteredSnapshots | ConvertTo-Json
    $SnapshotsMatchCount = $FilteredSnapshots.Count

    if ($SnapshotsMatchCount -eq 0) {
        Write-ToConsoleAndFile -text "No Snapshot problems found.`r`n" -file $OutputFile
    } else {
        # Output JSON result and the count of matching snapshots
        Write-ToConsoleAndFile -text "Snapshot above 30 days:`r`n$SnapshotsJson `r`nFound Snapshots Count:$SnapshotsMatchCount`r`n"-file $OutputFile
    }


    # Checking for ransomware warnings
    Write-ToConsoleAndFile -text "============= Ransomware warnings ==============`r`n" -file $OutputFile

    # Setup for retrieving ransomware info
    $GetRansomwareInfoUrl = "https://$Cluster/api/private/cli/security/anti-ransomware/volume?fields=state,vserver,volume,attack-timeline,attack-probability,no-of-attacks,dry-run-start-time&pretty=false"
    $RansomwareTable = Invoke-RestMethod $GetRansomwareInfoUrl -Credential $CredObject

    $RansomWareMessage = @(
    "Ransomware Warning detected! Restore snapshot has been created!
    The identified file is unexpected in your workload and should be treated as a potential attack!
    In the case of a suspected attack, you must determine whether it is an attack or false positive, respond if it is, and restore protected data before clearing the notices!

    1.verify the time and severity of the attack:
    2.check EMS messages:
    event log show -message-name callhome.arw.activity.seen
    3.Generate an attack report and note the output location:
    security anti-ransomware volume attack generate-report -volume vol_name -dest-path file_location/
    4. Respond to the attack accordingly. Check documentation for more information.

    https://docs.netapp.com/us-en/ontap/anti-ransomware/recover-data-task.html
    https://kb.netapp.com/onprem/ontap/da/NAS/Understanding_ARP_snapshot_protection_and_attack_detection`r`n"
    )


    # Check if the records array is empty or if $RansomwareTable is null
    if (-not $RansomwareTable -or -not $RansomwareTable.records -or $RansomwareTable.records.Count -eq 0) {
        Write-ToConsoleAndFile -text "No ransomware data available or records are empty.`r`n" -file $OutputFile
    } else {
        # Initialize a variable to track if all records are OK
        $AllRecordsAreOK = $true

        # Process each record in the ransomware table
        foreach ($Record in $RansomwareTable.records) {
            # Check if 'attack_probability' exists and is neither null, empty, 'low', nor 'none'
            if ($null -ne $Record.PSObject.Properties['attack_probability'] -and 
                $Record.attack_probability -ne "low" -and 
                $Record.attack_probability -ne "none" -and
                -not [string]::IsNullOrWhiteSpace($Record.attack_probability)) {
                # Record does not meet the 'ignore' criteria, process it
                $AllRecordsAreOK = $false

                # Prepare the output string with relevant information
                $OutputString = "Vserver: $($Record.vserver)`r`n" +
                                "Volume: $($Record.volume)`r`n" +
                                "State: $($Record.state)`r`n" +
                                "AttackProbability: $($Record.attack_probability)`r`n" +
                                "AttackTimeline: $($Record.attack_timeline)`r`n" +
                                "NumberOfAttacks: $($Record.no_of_attacks)`r`n"
            
                # Log the details of records with notable 'attack_probability'
                Write-ToConsoleAndFile -text "$RansomWareMessage`r`n$OutputString" -file $OutputFile
            }
        }

        # If all records are OK (no notable 'attack_probability'), log a confirmation message
        if ($AllRecordsAreOK) {
            Write-ToConsoleAndFile -text "No highlevel ransomware warnings found`r`n" -file $OutputFile
        }


    # Checking for relevant EMS messages
    Write-ToConsoleAndFile -text "============= !!! Important EMS warning messages to txt log !!! ==============`r`n " -file $OutPutFile
    Write-ToConsoleAndFile -text "See powershell console-window for more good-to-know EMS messages (Only the last 48 hours gets printed)`r`n " -file $OutPutFile


    # Define function to check if a record's timestamp is within the specified time frame
    function IsRecordWithinTimeFrame {
        param (
            [string]$RecordTime,
            [int]$DaysBack = 0
        )
    
        $ParsedRecordTime = [datetime]::ParseExact($RecordTime, "yyyy-MM-ddTHH:mm:sszzz", $null)
        $StartTime = (Get-Date).Date.AddDays(-$DaysBack)
        $EndTime = (Get-Date).Date.AddDays(1).AddSeconds(-1)
    
        return $ParsedRecordTime -ge $StartTime -and $ParsedRecordTime -le $EndTime
    }

    # Keywords to ignore in "alert" severity records
    $IgnoreKeywordsForAlert = @(
        "mgwd",
        "vifmgr",
        "raid.autoPart.disabled",
        "dsa_disc",
        "vifmgr.lifdown.noports"
    )

    # Keywords to ignore in "error" severity records
    $IgnoreKeywordsForError = @(
        "cf.fsm.takeoverByPartnerDisabled",
        "vifmgr",
        "wafl_spcd_main",
        "intr",
        ".certificate.expired",
        "sp.upd.bad.fw.package",
        "mgwd",
        "sis.chkpoint.restore.failed",
        "secd.nfsAuth.noNameMap",
        "Nblade.cifsShrConnectFailed",
        "dsa_disc",
        "cf.hwassist.missedKeepAlive",
        "cf.fsm.takeoverOfPartnerDisabled",
        "asup.aods.response.timeOut",
        "netif.tcp.conn.bad.checksum",
        "scan_tsse_wkr",
        "secd.rpc.authRequest.blocked",
        "secd.cifsAuth.problem",
        "asup.post.drop"
    )

    # Priority keywords list that will check for mention of anything in the list
    $PriorityKeywords = @(
        "ransomware",
        "offline"
        "anti-ransomware",
        "emergency"
    )

    $EventLogFields = @(
    "time",
    "node",
    "message-name",
    "event",
    "action",
    "seqnum",
    "severity",
    "source",
    "description"
    )

    $EventLogString = $EventLogFields -join ","
    $GetEventLogUrl = "https://$Cluster/api/private/cli/event/log?fields=$EventLogString&pretty=false"
    $EventLogTable = Invoke-RestMethod $GetEventLogUrl -Credential $CredObject

    # Function to check for priority keywords
    function Contains-PriorityKeyword {
        param (
            [PSCustomObject]$Record,
            [string[]]$PriorityKeywords
        )
        
        $FieldsToCheck = @('node', 'seqnum', 'time', 'source', 'message_name', 'event', 'action')
        foreach ($Field in $FieldsToCheck) {
            $FieldValue = [string]$Record.$Field
            foreach ($Keyword in $PriorityKeywords) {
                if ($FieldValue -like "*$Keyword*") {
                    return $True
                }
            }
        }
        return $False
    }

    # Function to determine if a record should be ignored
    function Should-IgnoreRecord {
        param (
            [PSCustomObject]$Record,
            [string[]]$IgnoreKeywords
        )
    
        $FieldsToCheck = @('node', 'seqnum', 'time', 'source', 'message_name', 'event', 'action')
        foreach ($Field in $FieldsToCheck) {
            $FieldValue = [string]$Record.$Field
            foreach ($Keyword in $IgnoreKeywords) {
                if ($FieldValue -like "*$Keyword*") {
                    return $True
                }
            }
        }
        return $False
    }

    # Processing records
    $PriorityRecords = @()
    $OtherRecords = @()

    foreach ($Record in $EventLogTable.records) {

        # Adjust DaysBack to a higher number to get more EMS messages to the console/txt log, 0 is default value will only show message from 00:00:00 this day
        $TimeFrameMatch = IsRecordWithinTimeFrame -RecordTime $Record.time -DaysBack 1
    
        # Severity match set records
        $SeverityMatch = $Record.severity -eq "alert" -or $Record.severity -eq "error" -or $Record.severity -eq "emergency"
    
        if ($SeverityMatch -and $TimeFrameMatch) {
            $ContainsPriorityKeyword = Contains-PriorityKeyword -Record $Record -PriorityKeywords $PriorityKeywords
            $FilterIgnore = Should-IgnoreRecord -Record $Record -IgnoreKeywords ($IgnoreKeywordsForAlert + $IgnoreKeywordsForError)
        
            if ($ContainsPriorityKeyword) {
                $PriorityRecords += $Record
            } elseif (-not $FilterIgnore) {
                $OtherRecords += $Record
            }
        }
    }

    $AllRecords = $PriorityRecords + $OtherRecords

    # Format each record's information for output
    $FormattedOutput = $AllRecords | ForEach-Object {
        $FormattedRecord = "Node: $($_.node)`r`nSeqNum: $($_.seqnum)`r`nTime: $($_.time)`r`nSeverity: $($_.severity)`r`nSource: $($_.source)`r`nMessageName: $($_.message_name)`r`nEvent: $($_.event)`r`nAction: $($_.action)`r`n"
        return $FormattedRecord
    }

    # Combine all formatted records into a single string for output
    $RecordsSummary = $FormattedOutput -join "`r`n"

    # Output the combined formatted string to the console and to the file
    Write-ToConsoleAndFile -text $RecordsSummary -file $OutPutFile

    Write-Host "============= !!! Filtered EMS warning messages to console ONLY !!! ============== `r`n" #Sorting in categories make terminal easier to look at

    # Optionally, convert and print combined records to JSON for console output
    $AllRecordsJson = $AllRecords | ConvertTo-Json
    $TotalRecordsCount = $AllRecords.Count

    # Print combined records JSON and total count to the console
    Write-Host "Combined Records:`r`n$AllRecordsJson`r`nTotal Records Count: $TotalRecordsCount"

    Write-ToConsoleAndFile -text "***END***END***END***END***END***END***END***END***END***END***END***END***`r`n" -file $OutPutFile
   
    }   

}

#//Clears all variables before ending script, shutting down powershell will  also clear memory
Get-Variable | Where-Object { $_.Name -ne '^' } | Remove-Variable -ErrorAction SilentlyContinue -Force

