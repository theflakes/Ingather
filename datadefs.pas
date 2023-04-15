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
        NUM_CMDS = 28;
      TYPE
        CommandArray = ARRAY[1..NUM_CMDS, 1..2] OF string;
      CONST
	      CMDS: CommandArray = (
          (
            'whoami /all',
            'Currently logged IN user info'
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
            'Dump super verbos Group Policy info'
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
            'TYPE c:\Windows\System32\drivers\etc\hosts',
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

