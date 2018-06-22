<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>

function Get-SysmonLogStack {
    [CmdletBinding()]
    param (
        # Name of WEF Collector to pull Sysmon logs from
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true,
                   Position = 0)]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        # ID of Sysmon log to pull, default to process creation
        [Parameter(Mandatory = $true)]
        [ValidateSet(1,2,3,4,5,6,7,8,9)]
        [int]$LogID = 1
    )
    
    begin {}
    
    process {
        try {
            #Handles needed to be able to pull owner
            #$Properties = "Name","CommandLIne","ProcessID","ParentProcessID","ExecutablePath","Handle"
            $LogFilter = @{ LogName= 'ForwardedEvents' ; ID = $LogID }
            #$Counter = 0

            $Logs = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $LogFilter -ErrorAction SilentlyContinue 
            
            ForEach ($Log in $Logs) {
                    [XML]$Event = $Log.ToXml()
                    $Start_Time = $Event.Event.EventData.Data.'#text'[0]
                    $Process_ID = $Event.Event.EventData.Data.'#text'[2]
                    $Proc_Name  = $Event.Event.EventData.Data.'#text'[3]
                    $Proc_CMD   = $Event.Event.EventData.Data.'#text'[8]
                    $Proc_HASH  = $Event.Event.EventData.Data.'#text'[15]
                    $Par_PID    = $Event.Event.EventData.Data.'#text'[17]
                    $Par_Name   = $Event.Event.EventData.Data.'#text'[18]
                    $Par_CMD    = $Event.Event.EventData.Data.'#text'[21]
        
                    #Create a custom object for each XML object, each object will represent a column in the exported CSV
                    [PSCustomObject]@{Computer       = "$Computer";
                                      PID            = "$Process_ID";
                                      Parent_PID     = "$Par_PID";
                                      Process_Name   = "$Proc_Name";
                                      Parent_Process = "$Par_Name";
                                      Command_Line   = "$Proc_CMD";
                                      Parent_CMDLine = "$Par_CMD";
                                      Process_Hash   = "$Proc_HASH";
                                      UTC_StartTime  = "$Start_Time" 
                                      
                                     }

            }
        }
        catch {
            Write-Verbose -Message "Could not retrieve the logs from $($ComputerName)"
        }
        
    }
    
    end {}
}