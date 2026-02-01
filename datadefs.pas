UNIT DataDefs;
{
  AUTHOR:  Brian Kellogg

  MIT licensed

  Unit holding data definitions AND manipulations
}

{$mode ObjFPC}{$H+}

INTERFACE

USES
  Classes, SysUtils;

TYPE
  TDataDefs = CLASS
    PUBLIC
      CONST
        NUM_CMDS = 44;
      TYPE
        CommandArray = ARRAY[1..NUM_CMDS, 1..2] OF String;
      CONST
           CMDS: CommandArray = (
              (
                'whoami /all',
                'Currently logged in user info'
              ),
              (
                'hostname',
                'Name OF device'
              ),
              (
                'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
                'Print OS name AND Version'
              ),
              (
                'gpresult /Z',
                'Dump super verbose Group Policy info'
              ),
              (
                'net users',
                'Dump list OF user accounts'
              ),
              (
                'wmic useraccount get name,sid',
                'Dump user sids'
              ),
              (
                'powershell -c "Get-LocalUser | Format-Table Name,Enabled,LastLogon,SID"',
                'Dump specified information on users'
              ),
              (
                'net localgroup Administrators',
                'Dump Administrators group membership'
              ),
              (
                'net localgroup "Remote Desktop Users"',
                'Dump RDP group membership'
              ),
              (
                'net localgroup "Backup Operators"',
                'Dump Backup Operators group membership'
              ),
              (
                'net share',
                'List available SMB shares'
              ),
              (
                'ipconfig /all',
                'List all NIC invormation'
              ),
              (
                'route print',
                'List all OS routing information'
              ),
              (
                'netstat -ano',
                'Show network socket information'
              ),
              (
                'netsh firewall show state',
                'Defender firewall state'
              ),
              (
                'netsh firewall show config',
                'Defender firewall config'
              ),
              (
                'arp -a',
                'Local ARP cache entries'
              ),
              (
                'type c:\Windows\System32\drivers\etc\hosts',
                'Hosts file contents'
              ),
              (
                'set',
                'Environment variables'
              ),
              (
                'wmic service get Name,PathName,Started,StartMode,StartName,Status',
                'Service information'
              ),
              (
                'schtasks /query /fo LIST /v',
                'Scheduled Tasks configuration'
              ),
              (
                'tasklist /SVC',
                'Running process information'
              ),
              (
                'wmic qfe get HotFixID',
                'Install OS hotfixes'
              ),
              (
                'driverquery /v',
                'OS driver information'
              ),
              (
                'reg query HKLM /f password /t REG_SZ /s',
                'Search registry local machine hive FOR keys with "password" IN the name'
              ),
              (
                'reg query HKCU /f password /t REG_SZ /s',
                'Search registry user hive FOR keys with "password" IN the name'
              ),
              (
                'powershell -c "Get-ChildItem C:\Users -Recurse -Depth 3 | Select-Object -ExpandProperty fullname | Sort-Object"',
                'List home directory contents'
              ),
              (
                'cd \ & dir /s *password* == *cred* == *vnc* == *account*',
                'Search C: drive FOR various strings'
              ),
              (
                'powershell -c "Get-MpPreference"',
                'Get Defender settings'
              ),
              (
                'query user',
                'Identify other users with active sessions on this system'
              ),
              (
                'cmdkey /list',
                'List stored usernames and credentials'
              ),
              (
                'powershell -c "Get-MpComputerStatus"',
                'Check Defender engine version and signature status'
              ),
              (
                'wmic product get name,version',
                'List all installed software and versions'
              ),
              (
                'net localgroup',
                'List all local groups available on the system'
              ),
              (
                'powershell -c "Get-PSDrive -PSProvider FileSystem"',
                'Identify mapped network drives and hidden partitions'
              ),
              (
                'net session',
                'List active sessions (requires elevated privileges)'
              ),
              (
                'powershell -c "Get-History"',
                'View command history for the current PowerShell session'
              ),
              (
                'doskey /history',
                'View command history for the current CMD session'
              ),
              (
                'net config workstation',
                'Verify current domain and logon server information'
              ),
              (
                'wmic startup list full',
                'Dump all startup persistence entries'
              ),
              (
                'sc query state= all',
                'List all services, including stopped ones'
              ),
              (
                'powershell -c "Test-NetConnection -ComputerName 127.0.0.1 -Port 445"',
                'Check if local SMB port is listening'
              ),
              (
                'wevtutil qe System /c:5 /rd:true /f:text',
                'Extract the last 5 system event logs'
              ),
              (
                'powershell -c "Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,AddressFamily"',
                'Display IP addresses for all network interfaces'
              )
        );
      FUNCTION FormatOutput(output: AnsiString): AnsiString;
    PRIVATE
  END;

IMPLEMENTATION
// format output
FUNCTION TDataDefs.FormatOutput(output: AnsiString): AnsiString;
BEGIN
  result:= output;
END;

END.

