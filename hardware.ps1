param([ValidateSet('hardware','drivers','processes','connections','sensors')][string]$Mode='hardware')
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
try {
    switch ($Mode) {
        'hardware' {
            $result = @{
                cpu = @(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed)
                gpu = @(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,VideoProcessor,PNPDeviceID)
                board = @(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version)
                bios = @(Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate)
                ram = @(Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,Capacity,Speed,ConfiguredClockSpeed,PartNumber)
                disks = @(Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,InterfaceType,Status,DeviceID)
                adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled | Select-Object Description,MACAddress,IPAddress,DefaultIPGateway)
            }
        }
        'drivers' { $result = @{rows = @(Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName,ServiceType)} }
        'processes' { $result = @{rows = @(Get-CimInstance Win32_Process | ForEach-Object { @{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;memory_bytes=$_.WorkingSetSize} })} }
        'connections' { $result = @{rows = @(Get-NetTCPConnection | ForEach-Object { @{protocol='TCP';local=@($_.LocalAddress,$_.LocalPort);remote=@($_.RemoteAddress,$_.RemotePort);state=[string]$_.State;pid=$_.OwningProcess} }); note='TCP table; install psutil for UDP owners too.'} }
        'sensors' {
            $result = @{sensors=@();note='Run LibreHardwareMonitor with WMI enabled to expose sensors.'}
            try { $result.sensors = @(Get-CimInstance -Namespace root\LibreHardwareMonitor -ClassName Sensor | ForEach-Object { @{name=$_.Name;type=$_.SensorType;value=$_.Value;unit=$(switch ($_.SensorType) {'Temperature' {'C'} 'Fan' {'RPM'} 'Load' {'%'} 'Power' {'W'} default {''}})} });$result.note='' } catch {}
        }
    }
    $result | ConvertTo-Json -Depth 8 -Compress
} catch { @{note=$_.Exception.Message;rows=@()} | ConvertTo-Json -Depth 5 -Compress }
