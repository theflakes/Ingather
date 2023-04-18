UNIT WinReg;
 {
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils, registry, regexpr;
TYPE
  TWinReg = CLASS
    PUBLIC
      FUNCTION GetOSVersion: AnsiString;
      FUNCTION GetUACStatus: AnsiString;
      FUNCTION GetRDPStatus: AnsiString;
      FUNCTION GetWDigestCleartextPWStatus: AnsiString;
      FUNCTION GetMSIAlwaysInstallElevatedStatus: AnsiString;
      FUNCTION GetAutoLogon: AnsiString;
      FUNCTION GetSNMP: AnsiString;
      FUNCTION GetVNCPasswords: AnsiString;
      FUNCTION GetPasswordlessNetLogon: AnsiString;
    PRIVATE
      // Win versions with default cleartext passwords
      CONST DFLT_CLEARTEXT_PW     = '(?-s)^Windows.+(XP|Vista|7|2008|8|2012)';
      // Win versions that will be matched in the above regex that do not store cleartext passwords
      CONST NON_DFLT_CLEARTEXT_PW = '(?-s)^Windows.+(8.1|2012 R2)';
      FUNCTION ReadKeyLIint(HKEY: LongWord; regPath: String; key: String): LongInt;
      FUNCTION ReadKeyAnsi(HKEY: LongWord; regPath: String; key: String): AnsiString;
      FUNCTION ReadKeyBool(HKEY: LongWord; regPath: String; key: String): Boolean;
      FUNCTION ReadKeyDouble(HKEY: LongWord; regPath: String; key: String): Double;
      FUNCTION ReadKeyDTime(HKEY: LongWord; regPath: String; key: String): TDateTime;
      FUNCTION ReadKeyDate(HKEY: LongWord; regPath: String; key: String): TDate;
      FUNCTION ReadKeyTime(HKEY: LongWord; regPath: String; key: String): TTime;
      FUNCTION ReadKeyBin(HKEY: LongWord; regPath: String; key: String; bufSize: integer): LongInt;
      PROCEDURE EnumSubKeys(HKEY: LongWord; key: String; SubKeyNames: TStrings);
  END;

IMPLEMENTATION
FUNCTION TWinReg.GetOSVersion: AnsiString;
VAR
  winVer: AnsiString;
BEGIN
  winVer:= ReadKeyAnsi(
              HKEY_LOCAL_MACHINE,
              '\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
              'ProductName'
            );
  result:= winVer;
END;

// search registry for VNC passwords
FUNCTION TWinReg.GetVNCPasswords: AnsiString;
VAR
  value: AnsiString = '';
  output: AnsiString = '';
BEGIN
  output:= concat(output, '[*] VNC Registry Passwords:' + sLineBreak);
  value:= ReadKeyAnsi(
            HKEY_LOCAL_MACHINE,
            '\SOFTWARE\RealVNC\vncserver',
            'Password'
          );
  output:= concat(output, '[**] RealVNC :: ' + value + sLineBreak);
  value:= ReadKeyAnsi(
            HKEY_CURRENT_USER,
            '\Software\TightVNC\Server',
            'Password'
          );
  output:= concat(output, '[**] TightVNC :: ' + value + sLineBreak);
  value:= ReadKeyAnsi(
            HKEY_CURRENT_USER,
            '\Software\TightVNC\Server',
            'PasswordViewOnly'
          );
  output:= concat(output, '[**] TightVNC view-only :: '+ value + sLineBreak);
  result:= output;
END;

// is auto logon enabled, if so, get the information
FUNCTION TWinReg.GetAutoLogon: AnsiString;
VAR
  value: AnsiString = '';
  output: AnsiString = '';
BEGIN
  value:= ReadKeyAnsi(
            HKEY_LOCAL_MACHINE,
            '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
            'AutoAdminLogon'
          );
  IF value = '1' THEN BEGIN
    output:= concat(output, '[!] Autologon enabled' + sLineBreak);
    value:= ReadKeyAnsi(
              HKEY_LOCAL_MACHINE,
              '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
              'DefaultUserName'
            );
    output:= concat(output, '[**] Username: '+value + sLineBreak);
    value:= ReadKeyAnsi(
              HKEY_LOCAL_MACHINE,
              '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
              'DefaultPassword'
            );
    output:= concat(output, '[**] Password: '+value + sLineBreak);
    value:= ReadKeyAnsi(
              HKEY_LOCAL_MACHINE,
              '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
              'DefaultDomainName'
            );
    output:= concat(output, '[**] Domain: '+value + sLineBreak);
  END ELSE
    output:= concat(output, '[*] Autologon NOT enabled.' + sLineBreak);
  result:= output;
END;

FUNCTION TWinReg.GetUACStatus: AnsiString;
VAR
  value: LongInt;
BEGIN
  result:= '';
  value:= ReadKeyLIint(
            HKEY_LOCAL_MACHINE,
            '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
            'EnableLUA'
          );
  IF value = 1 THEN
    result:= '[*] UAC is enabled'
  ELSE IF value = 0 THEN
    result:= '[!] UAC is disabled';
END;

FUNCTION TWinReg.GetPasswordlessNetLogon: AnsiString;
VAR
  value: LongInt;
BEGIN
  value:= ReadKeyLIint(
            HKEY_LOCAL_MACHINE,
            '\SYSTEM\CurrentControlSet\Control\Lsa',
            'LimitBlankPasswordUse'
          );
  IF value = 0 THEN
    result:= '[!] Passwordless network logon enabled'
  ELSE
    result:= '[*] Passwordless network logon disabled';
END;

FUNCTION TWinReg.GetRDPStatus: AnsiString;
VAR
  value: LongInt;
BEGIN
  result:= '';
  value:= ReadKeyLIint(
            HKEY_LOCAL_MACHINE,
            '\SYSTEM\CurrentControlSet\Control\Terminal Server',
            'fDenyTSConnections'
          );
  IF value = 0 THEN
    result:= '[!] RDP is enabled'
  ELSE IF value = 1 THEN
    result:= '[*] RDP is disabled';
END;

FUNCTION TWinReg.GetWDigestCleartextPWStatus: AnsiString;
VAR
  value: LongInt;
  findVulnOS: TRegExpr;
  findNonVulnOS :TRegExpr;
BEGIN
  findVulnOS:= TRegExpr.Create;
  findNonVulnOS:= TRegExpr.Create;
  findVulnOS.Expression:= DFLT_CLEARTEXT_PW;
  findNonVulnOS.Expression:= NON_DFLT_CLEARTEXT_PW;
  value:= ReadKeyLIint(
            HKEY_LOCAL_MACHINE,
            '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
            'UseLogonCredential'
          );
  IF value = 0 THEN
    result:= '[*] WDigest cleartext passwords disabled.'
  ELSE IF value = 1 THEN
    result:= '[!] WDigest cleartext passwords enabled'
  ELSE IF findVulnOS.Exec(GetOSVersion) AND NOT findNonVulnOS.Exec(GetOSVersion) THEN
    result:= '[!] WDigest cleartext passwords enabled'
  ELSE
    result:= '[*] WDigest cleartext passwords disabled.';
END;

FUNCTION TWinReg.GetMSIAlwaysInstallElevatedStatus: AnsiString;
VAR
  HKLMvalue: LongInt;
  HKLUvalue: LongInt;
BEGIN
  HKLMvalue:= ReadKeyLIint(
                HKEY_LOCAL_MACHINE,
                '\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated'
              );
  HKLUvalue:= ReadKeyLIint(
                HKEY_CURRENT_USER,
                '\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated'
              );
  IF (HKLMvalue = 1) AND (HKLUvalue = 1) THEN
    result:= '[!] MSI installs always elevated vulnerability found.'
  ELSE
    result:= '[*] Not vulnerable to "always elevated MSI install" vulnerability.';
END;

FUNCTION TWinReg.GetSNMP: AnsiString;
VAR
  communities  : TStringList;
  name         : String;
  value        : Double;
  output       : AnsiString = '';
BEGIN
  communities:= TStringList.Create;
  EnumSubKeys(
    HKEY_LOCAL_MACHINE,
    '\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities',
    communities
  ); // read all sub keys
  output:= concat(output, '[*] SNMP Communities:' + sLineBreak);
  IF communities.Count = 0 THEN
    output:= concat(output, '[**] No SNMP communities set.' + sLineBreak)
  ELSE
    FOR name IN communities DO BEGIN
      output:= concat(output, '[**] '+name + sLineBreak);
      value:= ReadKeyDouble(
                HKEY_LOCAL_MACHINE,
                '\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities',
                name
              ); // get subkey's value
      CASE FloatToStr(value) OF // SNMP community allowed access
        '4': output:= concat(output, '[**] :: read' + sLineBreak);
        '8': output:= concat(output, '[!!] :: read/write' + sLineBreak);
        '1': output:= concat(output, '[**] :: no access' + sLineBreak);
        '-1': output:= concat(output, '[**] :: no registry value defined' + sLineBreak);
        ELSE output:= concat(output, '[**] :: undefined' + sLineBreak);
      END;
    END;
  result:= output;
END;

// read all sub keys IN a registry key
PROCEDURE TWinReg.EnumSubKeys(HKEY: LongWord; key: String; SubKeyNames: TStrings);
VAR
  Registry      : TRegistry;
BEGIN
  SubKeyNames.Clear;
  Registry := TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(key) THEN
    Registry.GetKeyNames(SubKeyNames);
  Registry.Free;
END;

GENERIC FUNCTION ReadKey<T>(HKEY: LongWord; regPath: String; key: String): T;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadInteger(key)
  ELSE
    result:= -1;
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyLIint(HKEY: LongWord; regPath: String; key: String): LongInt;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadInteger(key)
  ELSE
    result:= -1;
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyAnsi(HKEY: LongWord; regPath: String; key: String): AnsiString;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadString(key)
  ELSE
    result:= 'Not Found';
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyBool(HKEY: LongWord; regPath: String; key: String): Boolean;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadBool(key)
  ELSE
    result:= false;
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyDouble(HKEY: LongWord; regPath: String; key: String): Double;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadFloat(key)
  ELSE
    result:= -1;
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyDTime(HKEY: LongWord; regPath: String; key: String): TDateTime;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadDateTime(key);
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyDate(HKEY: LongWord; regPath: String; key: String): TDate;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadDate(key);
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyTime(HKEY: LongWord; regPath: String; key: String): TTime;
VAR
  Registry: TRegistry;
BEGIN
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadTime(key);
  Registry.Free;
END;

FUNCTION TWinReg.ReadKeyBin(HKEY: LongWord; regPath: String; key: String; bufSize: integer): LongInt;
VAR
  Registry: TRegistry;
  Buffer  : ARRAY OF byte;
BEGIN
  SetLength(Buffer, bufSize);
  Registry:= TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  Registry.RootKey:= HKEY;
  IF Registry.OpenKeyReadOnly(regPath) AND Registry.ValueExists(key) THEN
    result:= Registry.ReadBinaryData(key, Buffer, bufSize);
  Registry.Free;
END;

END.

