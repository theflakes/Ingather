unit DataDefs;
{
  AUTHOR:  Brian Kellogg

  MIT licensed

  Unit holding data definitions and manipulations
}

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

type
  TDataDefs = class
    public
      const
        NUM_CMDS = 28;
      type
        CommandArray = array[1..NUM_CMDS, 1..2] of string;
      const
	      CMDS: CommandArray = (
          (
            'whoami /all',
            'Currently logged in user info'
          ),
          (
            'hostname',
            'Name of device'
          ),
          (
            'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
            'Print OS name and Version'
          ),
          (
            'gpresult /Z',
            'Dump super verbos Group Policy info'
          ),
          (
            'net users',
            'Dump list of user accounts'
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
            'Search registry local machine hive for keys with "password" in the name'
          ),
          (
            'reg query HKCU /f password /t REG_SZ /s',
            'Search registry user hive for keys with "password" in the name'
          ),
          (
            'powershell -c "Get-ChildItem C:\Users -Recurse -Depth 3 | Select-Object -ExpandProperty fullname | Sort-Object"',
            'List home directory contents'
          ),
          (
            'cd \ & dir /s *password* == *cred* == *vnc* == *account*',
            'Search C: drive for various strings'
          )
	      );
      function FormatOutput(output: AnsiString): AnsiString;
    private
  end;

implementation
// format output
function TDataDefs.FormatOutput(output: AnsiString): AnsiString;
begin
  result:= output;
end;

end.

