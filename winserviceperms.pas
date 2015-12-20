unit WinServicePerms;
{
  See:  https://support.microsoft.com/en-us/kb/914392
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;
type
  TWinServicePerms = class
    public
      function Users(userAbbr: string): string;
      function Perms(permAbbr: string): string;
    private
  end;

implementation
function TWinServicePerms.Users(userAbbr: string): string;
begin
  case userAbbr of
    'DA': result:= 'Domain Administrators';
    'DG': result:= 'Domain Guests';
    'DU': result:= 'Domain Users';
    'ED': result:= 'Enterprise Domain Controllers';
    'DD': result:= 'Domain Controllers';
    'DC': result:= 'Domain Computers';
    'BA': result:= 'Built-in (Local ) Administrators';
    'BG': result:= 'Built-in (Local ) Guests';
    'BU': result:= 'Built-in (Local ) Users';
    'LA': result:= 'Local Administrator Account';
    'LG': result:= 'Local Guest Account';
    'AO': result:= 'Account Operators';
    'BO': result:= 'Backup Operators';
    'PO': result:= 'Printer Operators';
    'SO': result:= 'Server Operators';
    'AU': result:= 'Authenticated Users';
    'PS': result:= 'Personal Self';
    'CO': result:= 'Creator Owner';
    'CG': result:= 'Creator Group';
    'SY': result:= 'Local System';
    'PU': result:= 'Power Users';
    'WD': result:= 'Everyone (World)';
    'RE': result:= 'Replicator';
    'IU': result:= 'Interactive Logon User';
    'NU': result:= 'Network Logon User';
    'SU': result:= 'Service Logon User';
    'RC': result:= 'Restricted Code';
    'WR': result:= 'Write Restricted Code';
    'AN': result:= 'Anonymous Logon';
    'SA': result:= 'Schema Administrators';
    'CA': result:= 'Certificate Services Administrators';
    'RS': result:= 'Remote Access Servers Group';
    'EA': result:= 'Enterprise Administrators';
    'PA': result:= 'Group Policy Administrators';
    'RU': result:= 'Alias to Allow Previous Windows 2000';
    'LS': result:= 'Local Service Account (for Services)';
    'NS': result:= 'Network Service Account (for Services)';
    'RD': result:= 'Remote Desktop Users (for Terminal Services)';
    'NO': result:= 'Network Configuration Operators';
    'MU': result:= 'Performance Monitor Users';
    'LU': result:= 'Performance Log Users';
    'IS': result:= 'Anonymous Internet Users';
    'CY': result:= 'Crypto Operators';
    'OW': result:= 'Owner Rights SID';
    'RM': result:= 'RMS Service';
    else result:= 'User/Group not found!';
  end;
end;

function TWinServicePerms.Perms(permAbbr: string): string;
begin
  case permAbbr of
    'CC': result:= 'QueryConf';
    'DC': result:= 'ChangeConf';
    'LC': result:= 'QueryStat';
    'SW': result:= 'EnumDeps';
    'RP': result:= 'Start';
    'WP': result:= 'Stop';
    'DT': result:= 'Pause';
    'LO': result:= 'Interrogate';
    'CR': result:= 'UserDefined';
    'GA': result:= 'GenericAll';
    'GX': result:= 'GenericExecute';
    'GW': result:= 'GenericWrite';
    'GR': result:= 'GenericRead';
    'SD': result:= 'Del';
    'RC': result:= 'RCtl';
    'WD': result:= 'WDac';
    'WO': result:= 'WOwn';
    else result:= 'Permission not found!';
  end;
end;

end.

