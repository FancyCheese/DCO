<#
.SYNOPSIS
    Collects Sysmon process creation and network connection logs from WEF collector and exports them into a CSV
.DESCRIPTION
    Use this commandlet pull Sysmon logs from either a local or remote system that is forwarding Sysmon Events.
    A directory named Symon_logs will be created in the current users Desktop.
    
    By default the Process Creation log EventID 1 and the Network Connections EventID 3 
    will be pulled and exported into a CSV.
.EXAMPLE
    ------------------------EXAMPLE 1-------------------------------------------------------------
    PS C:\> Get-SysmonLog -ComputerName 153MEUSRV.153MEU.USMC.MIL
    This will pull the default Sysmon Event logs from the 153MEUSRV and output them to the default 
    output directory %USERPROFILE%\Desktop\Sysmon_Logs

    ------------------------EXAMPLE 2------------------------------------------------------------
    PS C:\> Get-SysmonLog -ComputerName 153MEUSRV.153MEU.USMC.MIL -FilePath C:\
    This example will do the same as above, but output the logs into the C:\ directory
.INPUTS
    System.String 

.OUTPUTS
    Sysmon_Process_Create.csv

    Sysmon_Network_Connect.csv    
.NOTES
    V1.0 Updated 20180611 by "Cheese" SSgt Manchego 
    TO DO:
    *Should remove the export to CSV portion of script to allow for
    manipulation of live objects and let the user export as desired.

    If receiving RPC unavailable errors, ensure that the target's Firewall is allowing
    Remote Event Log Management (predefined rule avilaible in windows firewall) 
    #>

function Get-SysmonLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        #[alias= ('WEFCollector')]
        [string]$ComputerName = 'localhost',
        
        #Future project, allow user specifed logIDs to pull
        #[int]$LogID =,  

        [string]$FilePath = "$env:USERPROFILE"
    )

    begin {

        Write-Verbose -Message "Creating a directory $OutputDir to store the Sysmon Logs"

        $OutputDir = "$FilePath\Desktop\Sysmon_Logs"

        if (!(Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force
        }
    }
    
    process {
        $ProcCreate = @{ LogName= 'ForwardedEvents' ; ID = '1' }
        $ProcOutput = "$OutputDir" + "\Sysmon_Process_Create.csv" 
        $NetConnect = @{ LogName = 'ForwardedEvents' ; ID = '3' }
        $NetOutput = "$OutputDir" + "\Sysmon_Network_Connect.csv"
        $Counter1 = 0
        $Counter2 = 0
        Write-Verbose "Grabbing the Sysmon logs from $ComputerName, this may take some time depending on the size of the logs"

        
        #Pull sysmon process creation events 
        $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $ProcCreate  -EA 0 
        foreach ($Event in $Events) {
            $Counter1++
            Write-Progress -Activity "Gathering Sysmon Process Create Logs" -PercentComplete (($Counter1 / $Events.count) * 100)
            #Export and append events to csv
            $Event | Export-Csv -NoTypeInformation $ProcOutput -Append -ErrorAction SilentlyContinue
        }
        
        #Pull sysmon network connection events, used $Log variable name to avoid 
        $Logs = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $NetConnect  -ErrorAction SilentlyContinue
        foreach ($Log in $Logs) {
            $Counter2++
            Write-Progress -Activity "Gathering Sysmon Network Connection Logs" -PercentComplete (($Counter2 / $Logs.count) * 100)
            $Log | Export-Csv -NoTypeInformation $NetOutput -Append -EA 0
        }

        #Pull sysmon process creation events and output to csv
        #Get-WinEvent -ComputerName $ComputerName -FilterHashtable $ProcCreate  -EA 0 | Export-Csv -NoTypeInformation $ProcOutput -Append -EA 0

        #Pull network connection sysmon events and ouput to csv
        #Get-WinEvent -ComputerName $ComputerName -FilterHashtable $NetConnect  -EA 0 | Export-Csv -NoTypeInformation $NetOutput -Append -EA 0
        
    }
    
    end {
        Write-Verbose "Complete! The logs can be found in $OutputDir"
    }
}
