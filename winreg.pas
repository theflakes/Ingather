unit WinReg;
 {
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, registry, regexpr;
type
  TWinReg = class
    public
      function GetOSVersion: AnsiString;
      function GetUACStatus: AnsiString;
      function GetRDPStatus: AnsiString;
      function GetWDigestCleartextPWStatus: AnsiString;
      function GetMSIAlwaysInstallElevatedStatus: AnsiString;
      procedure GetAutoLogon;
      procedure GetSNMP;
      procedure GetVNCPasswords;
    private
      const DFLT_CLEARTEXT_PW     = '(?-s)^Windows.+(XP|Vista|7|2008|8|2012)'; // Win versions with default cleartext passwords
      const NON_DFLT_CLEARTEXT_PW = '(?-s)^Windows.+(8.1|2012 R2)';            // Win versions that will be matched in the above regex that do not store cleartext passwords
      function ReadKeyLIint(HKEY: LongWord; regPath: string; key: string): LongInt;
      function ReadKeyAnsi(HKEY: LongWord; regPath: string; key: string): AnsiString;
      function ReadKeyBool(HKEY: LongWord; regPath: string; key: string): boolean;
      function ReadKeyDouble(HKEY: LongWord; regPath: string; key: string): double;
      function ReadKeyDTime(HKEY: LongWord; regPath: string; key: string): TDateTime;
      function ReadKeyDate(HKEY: LongWord; regPath: string; key: string): TDate;
      function ReadKeyTime(HKEY: LongWord; regPath: string; key: string): TTime;
      function ReadKeyBin(HKEY: LongWord; regPath: string; key: string; bufSize: integer): LongInt;
      procedure EnumSubKeys(HKEY: LongWord; key: string; SubKeyNames: TStrings);
  end;

implementation
function TWinReg.GetOSVersion: AnsiString;
var
  winVer: AnsiString;
begin
  winVer:= ReadKeyAnsi(HKEY_LOCAL_MACHINE, '\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName');
  result:= winVer;
end;

// search registry for VNC passwords
procedure TWinReg.GetVNCPasswords;
var
  value: AnsiString;
begin
  writeln('VNC Registry Passwords:');
  value:= ReadKeyAnsi(HKEY_LOCAL_MACHINE, '\SOFTWARE\RealVNC\vncserver', 'Password');
  if value = 'NF' then
    writeln(' \_> RealVNC :: no password found.')
  else
    writeln(' \_> RealVNC :: '+value);
  value:= ReadKeyAnsi(HKEY_CURRENT_USER, '\Software\TightVNC\Server', 'Password');
  if value = 'NF' then
    writeln(' \_> TightVNC :: no password found.')
  else
    writeln(' \_> TightVNC :: '+value);
  value:= ReadKeyAnsi(HKEY_CURRENT_USER, '\Software\TightVNC\Server', 'PasswordViewOnly');
  if value = 'NF' then
    writeln(' \_> TightVNC :: no view-only password found.')
  else
    writeln(' \_> TightVNC view-only :: '+value);
end;

// is auto logon enabled, if so, get the information
procedure TWinReg.GetAutoLogon;
var
  value: AnsiString;
begin
  value:= ReadKeyAnsi(HKEY_LOCAL_MACHINE, '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'AutoAdminLogon');
  if value = '1' then begin
    writeln('Autologon enabled ---');
    value:= ReadKeyAnsi(HKEY_LOCAL_MACHINE, '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultUserName');
    writeln(' \_Username: '+value);
    value:= ReadKeyAnsi(HKEY_LOCAL_MACHINE, '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultPassword');
    writeln(' \_Password: '+value);
    value:= ReadKeyAnsi(HKEY_LOCAL_MACHINE, '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultDomainName');
    writeln(' \_Domain: '+value);
  end else
    writeln('Autologon not enabled.');
end;

function TWinReg.GetUACStatus: AnsiString;
var
  value: LongInt;
begin
  value:= ReadKeyLIint(HKEY_LOCAL_MACHINE, '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA');
  if value = 1 then
    result:= 'UAC is enabled!!!'
  else if value = 0 then
    result:= 'UAC is disabled!!!';
end;

function TWinReg.GetRDPStatus: AnsiString;
var
  value: LongInt;
begin
  value:= ReadKeyLIint(HKEY_LOCAL_MACHINE, '\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections');
  if value = 0 then
    result:= 'RDP is enabled!!!'
  else if value = 1 then
    result:= 'RDP is disabled!!!';
end;

function TWinReg.GetWDigestCleartextPWStatus: AnsiString;
var
  value: LongInt;
  findVulnOS: TRegExpr;
  findNonVulnOS :TRegExpr;
begin
  findVulnOS:= TRegExpr.Create;
  findNonVulnOS:= TRegExpr.Create;
  findVulnOS.Expression:= DFLT_CLEARTEXT_PW;
  findNonVulnOS.Expression:= NON_DFLT_CLEARTEXT_PW;
  value:= ReadKeyLIint(HKEY_LOCAL_MACHINE, '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential');
  if value = 0 then
    result:= 'WDigest cleartext passwords disabled.'
  else if value = 1 then
    result:= 'WDigest cleartext passwords enabled!!!'
  else if findVulnOS.Exec(GetOSVersion) and not findNonVulnOS.Exec(GetOSVersion) then
    result:= 'WDigest cleartext passwords enabled!!!'
  else
    result:= 'WDigest cleartext passwords disabled.';
end;

function TWinReg.GetMSIAlwaysInstallElevatedStatus: AnsiString;
var
  HKLMvalue: LongInt;
  HKLUvalue: LongInt;
begin
  HKLMvalue:= ReadKeyLIint(HKEY_LOCAL_MACHINE, '\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated');
  HKLUvalue:= ReadKeyLIint(HKEY_CURRENT_USER, '\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated');
  if (HKLMvalue = 1) and (HKLUvalue = 1) then
    result:= 'MSI installs always elevated vulnerability found.'
  else
    result:= 'Not vulnerable to ''always elevated MSI install'' vulnerability.';
end;

procedure TWinReg.GetSNMP;
var
  communities  : TStringList;
  name         : string;
  value        : double;
begin
  communities:= TStringList.Create;
  EnumSubKeys(HKEY_LOCAL_MACHINE, '\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities', communities); // read all sub keys
  writeln('SNMP Communities:');
  if communities.Count = 0 then
    writeln(' \_> No SNMP communities set.')
  else
    for name in communities do begin
      write(' \_> '+name);
      value:= ReadKeyDouble(HKEY_LOCAL_MACHINE, '\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities', name); // get subkey's value
      case FloatToStr(value) of // SNMP community allowed access
        '4': writeln(' :: read');
        '8': writeln(' :: read/write');
        '1': writeln(' :: no access');
        '-1': writeln(' :: no registry value defined');
        else writeln(' :: undefined');
      end;
    end;
end;

// read all sub keys in a registry key
procedure TWinReg.EnumSubKeys(HKEY: LongWord; key: string; SubKeyNames: TStrings);
var
  Registry      : TRegistry;
begin
  SubKeyNames.Clear;
  Registry := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(key) then
    Registry.GetKeyNames(SubKeyNames);
  Registry.Free;
end;

function TWinReg.ReadKeyLIint(HKEY: LongWord; regPath: string; key: string): LongInt;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadInteger(key)
  else
    result:= -1;
  Registry.Free;
end;

function TWinReg.ReadKeyAnsi(HKEY: LongWord; regPath: string; key: string): AnsiString;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadString(key)
  else
    result:= 'NF';
  Registry.Free;
end;

function TWinReg.ReadKeyBool(HKEY: LongWord; regPath: string; key: string): boolean;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadBool(key)
  else
    result:= false;
  Registry.Free;
end;

function TWinReg.ReadKeyDouble(HKEY: LongWord; regPath: string; key: string): double;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadFloat(key)
  else
    result:= -1;
  Registry.Free;
end;

function TWinReg.ReadKeyDTime(HKEY: LongWord; regPath: string; key: string): TDateTime;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadDateTime(key);
  Registry.Free;
end;

function TWinReg.ReadKeyDate(HKEY: LongWord; regPath: string; key: string): TDate;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadDate(key);
  Registry.Free;
end;

function TWinReg.ReadKeyTime(HKEY: LongWord; regPath: string; key: string): TTime;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadTime(key);
  Registry.Free;
end;

function TWinReg.ReadKeyBin(HKEY: LongWord; regPath: string; key: string; bufSize: integer): LongInt;
var
  Registry: TRegistry;
  Buffer  : array of byte;
begin
  SetLength(Buffer, bufSize);
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  if Registry.OpenKeyReadOnly(regPath) and Registry.ValueExists(key) then
    result:= Registry.ReadBinaryData(key, Buffer, bufSize);
  Registry.Free;
end;

end.

