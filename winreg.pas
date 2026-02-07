UNIT WinReg;

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
      FUNCTION GetStartupPersistence: AnsiString;
    PRIVATE
      CONST DFLT_CLEARTEXT_PW     = '(?-s)^Windows.+(XP|Vista|7|2008|8|2012)';
      CONST NON_DFLT_CLEARTEXT_PW = '(?-s)^Windows.+(8.1|2012 R2)';

      // Generic method: The 'generic' keyword is required here in objfpc mode
      generic FUNCTION ReadValue<T>(HKEY: PtrUInt; regPath: String; key: String; DefaultVal: T): T;

      // Smart string reader: Determines type at runtime
      FUNCTION ReadAnyAsString(HKEY: PtrUInt; regPath: String; key: String): AnsiString;

      PROCEDURE EnumSubKeys(HKEY: PtrUInt; key: String; SubKeyNames: TStrings);
      FUNCTION EnumerateRunKey(Root: PtrUInt; DisplayRoot, Path: String): AnsiString;
  END;

IMPLEMENTATION

FUNCTION TWinReg.GetOSVersion: AnsiString;
BEGIN
  // Use PtrUInt to avoid range errors with HKEY constants
  Result := ReadAnyAsString(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName');
END;

{ ---------------------------------------------------------------------------
  STARTUP ENUMERATION LOGIC
  --------------------------------------------------------------------------- }

FUNCTION TWinReg.GetStartupPersistence: AnsiString;
VAR
  UserSIDs: TStringList;
  i, j, k: Integer;
  TargetKey: String;
  Roots: ARRAY[0..1] OF PtrUInt;
  RootNames: ARRAY[0..1] OF String;
  RunPaths: ARRAY[0..3] OF String;
BEGIN
  Result := '[*] Startup Persistence Enumeration:' + sLineBreak;
  UserSIDs := TStringList.Create;

  // Use PtrUInt for HKEY constants to avoid range errors
  Roots[0] := PtrUInt(HKEY_LOCAL_MACHINE); RootNames[0] := 'HKLM';
  Roots[1] := PtrUInt(HKEY_USERS);         RootNames[1] := 'HKU';

  RunPaths[0] := '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';
  RunPaths[1] := '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';
  RunPaths[2] := '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';
  RunPaths[3] := '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';

  TRY
    FOR i := 0 TO 1 DO
    BEGIN
      IF i = 0 THEN
      BEGIN
        FOR k := 0 TO High(RunPaths) DO
          Result := Result + EnumerateRunKey(Roots[i], RootNames[i], RunPaths[k]);
      END
      ELSE
      BEGIN
        EnumSubKeys(Roots[i], '', UserSIDs);
        FOR j := 0 TO UserSIDs.Count - 1 DO
        BEGIN
          IF Pos('_Classes', UserSIDs[j]) > 0 THEN Continue;
          FOR k := 0 TO High(RunPaths) DO
          BEGIN
            TargetKey := UserSIDs[j] + RunPaths[k];
            Result := Result + EnumerateRunKey(Roots[i], RootNames[i] + '\' + UserSIDs[j], TargetKey);
          END;
        END;
      END;
    END;
  FINALLY
    UserSIDs.Free;
  END;
END;

FUNCTION TWinReg.EnumerateRunKey(Root: PtrUInt; DisplayRoot, Path: String): AnsiString;
VAR
  Reg: TRegistry;
  Names: TStringList;
  m: Integer;
  ValData: String;
BEGIN
  Result := '';
  Names := TStringList.Create;
  Reg := TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  TRY
    Reg.RootKey := Root;
    IF Reg.OpenKeyReadOnly(Path) THEN
    BEGIN
      Reg.GetValueNames(Names);
      FOR m := 0 TO Names.Count - 1 DO
      BEGIN
        ValData := ReadAnyAsString(Root, Path, Names[m]);
        Result := Result + Format('[**] [%s] %s :: %s', [DisplayRoot, Names[m], ValData]) + sLineBreak;
      END;
    END;
  FINALLY
    Names.Free;
    Reg.Free;
  END;
END;

{ ---------------------------------------------------------------------------
  GENERIC AND SMART HELPERS
  --------------------------------------------------------------------------- }

generic FUNCTION TWinReg.ReadValue<T>(HKEY: PtrUInt; regPath: String; key: String; DefaultVal: T): T;
VAR
  Reg: TRegistry;
  DType: TRegDataType;
BEGIN
  Result := DefaultVal;
  Reg := TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  TRY
    Reg.RootKey := HKEY;
    IF Reg.OpenKeyReadOnly(regPath) AND Reg.ValueExists(key) THEN
    BEGIN
      DType := Reg.GetDataType(key);
      CASE DType OF
        rdString, rdExpandString: PAnsiString(@Result)^ := Reg.ReadString(key);
        rdInteger: PLongInt(@Result)^ := Reg.ReadInteger(key);
        rdBinary:  Reg.ReadBinaryData(key, Result, SizeOf(T));
      END;
    END;
  FINALLY
    Reg.Free;
  END;
END;

FUNCTION TWinReg.ReadAnyAsString(HKEY: PtrUInt; regPath: String; key: String): AnsiString;
VAR
  Reg: TRegistry;
  DType: TRegDataType;
BEGIN
  Result := '';
  Reg := TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  TRY
    Reg.RootKey := HKEY;
    IF Reg.OpenKeyReadOnly(regPath) AND Reg.ValueExists(key) THEN
    BEGIN
      DType := Reg.GetDataType(key);
      CASE DType OF
        rdString, rdExpandString: Result := Reg.ReadString(key);
        rdInteger: Result := IntToStr(Reg.ReadInteger(key));
        rdBinary:  Result := '[Binary Data]';
        ELSE Result := '[Type ID ' + IntToStr(Ord(DType)) + ']';
      END;
    END;
  FINALLY
    Reg.Free;
  END;
END;

PROCEDURE TWinReg.EnumSubKeys(HKEY: PtrUInt; key: String; SubKeyNames: TStrings);
VAR Reg: TRegistry;
BEGIN
  SubKeyNames.Clear;
  Reg := TRegistry.Create(KEY_READ OR KEY_WOW64_64KEY);
  TRY
    Reg.RootKey := HKEY;
    IF Reg.OpenKeyReadOnly(key) THEN Reg.GetKeyNames(SubKeyNames);
  FINALLY
    Reg.Free;
  END;
END;

FUNCTION TWinReg.GetVNCPasswords: AnsiString;
VAR val: AnsiString;
BEGIN
  Result := '[*] VNC Registry Passwords:' + sLineBreak;
  val := ReadAnyAsString(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\RealVNC\vncserver', 'Password');
  Result := Result + '[**] RealVNC :: ' + val + sLineBreak;
  val := ReadAnyAsString(PtrUInt(HKEY_CURRENT_USER), '\Software\TightVNC\Server', 'Password');
  Result := Result + '[**] TightVNC :: ' + val + sLineBreak;
  val := ReadAnyAsString(PtrUInt(HKEY_CURRENT_USER), '\Software\TightVNC\Server', 'PasswordViewOnly');
  Result := Result + '[**] TightVNC view-only :: '+ val + sLineBreak;
END;

FUNCTION TWinReg.GetAutoLogon: AnsiString;
VAR status: AnsiString;
BEGIN
  status := ReadAnyAsString(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'AutoAdminLogon');
  IF status = '1' THEN BEGIN
    Result := '[!] Autologon enabled' + sLineBreak;
    Result := Result + '[**] Username: ' + ReadAnyAsString(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultUserName') + sLineBreak;
    Result := Result + '[**] Password: ' + ReadAnyAsString(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultPassword') + sLineBreak;
    Result := Result + '[**] Domain: '   + ReadAnyAsString(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultDomainName') + sLineBreak;
  END ELSE
    Result := '[*] Autologon NOT enabled.' + sLineBreak;
END;

FUNCTION TWinReg.GetUACStatus: AnsiString;
VAR val: LongInt;
BEGIN
  val := specialize ReadValue<LongInt>(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA', -1);
  IF val = 1 THEN Result := '[*] UAC is enabled'
  ELSE IF val = 0 THEN Result := '[!] UAC is disabled'
  ELSE Result := '[?] UAC status unknown';
END;

FUNCTION TWinReg.GetPasswordlessNetLogon: AnsiString;
BEGIN
  IF (specialize ReadValue<LongInt>(PtrUInt(HKEY_LOCAL_MACHINE), '\SYSTEM\CurrentControlSet\Control\Lsa', 'LimitBlankPasswordUse', 1) = 0) THEN
    Result := '[!] Passwordless network logon enabled'
  ELSE
    Result := '[*] Passwordless network logon disabled';
END;

FUNCTION TWinReg.GetRDPStatus: AnsiString;
VAR val: LongInt;
BEGIN
  val := specialize ReadValue<LongInt>(PtrUInt(HKEY_LOCAL_MACHINE), '\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections', -1);
  IF val = 0 THEN Result := '[!] RDP is enabled'
  ELSE IF val = 1 THEN Result := '[*] RDP is disabled'
  ELSE Result := '[?] RDP status unknown';
END;

FUNCTION TWinReg.GetWDigestCleartextPWStatus: AnsiString;
VAR
  val: LongInt;
  findVulnOS, findNonVulnOS: TRegExpr;
BEGIN
  val := specialize ReadValue<LongInt>(PtrUInt(HKEY_LOCAL_MACHINE), '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', -1);
  IF val = 1 THEN Exit('[!] WDigest cleartext passwords enabled');
  IF val = 0 THEN Exit('[*] WDigest cleartext passwords disabled.');

  findVulnOS := TRegExpr.Create(DFLT_CLEARTEXT_PW);
  findNonVulnOS := TRegExpr.Create(NON_DFLT_CLEARTEXT_PW);
  TRY
    IF findVulnOS.Exec(GetOSVersion) AND NOT findNonVulnOS.Exec(GetOSVersion) THEN
      Result := '[!] WDigest cleartext passwords enabled'
    ELSE
      Result := '[*] WDigest cleartext passwords disabled.';
  FINALLY
    findVulnOS.Free;
    findNonVulnOS.Free;
  END;
END;

FUNCTION TWinReg.GetMSIAlwaysInstallElevatedStatus: AnsiString;
VAR hklm, hkcu: LongInt;
BEGIN
  hklm := specialize ReadValue<LongInt>(PtrUInt(HKEY_LOCAL_MACHINE), '\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 0);
  hkcu := specialize ReadValue<LongInt>(PtrUInt(HKEY_CURRENT_USER), '\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 0);
  IF (hklm = 1) AND (hkcu = 1) THEN
    Result := '[!] MSI installs always elevated vulnerability found.'
  ELSE
    Result := '[*] Not vulnerable to "always elevated MSI install" vulnerability.';
END;

FUNCTION TWinReg.GetSNMP: AnsiString;
VAR
  communities: TStringList;
  name: String;
  val: LongInt;
BEGIN
  communities := TStringList.Create;
  TRY
    EnumSubKeys(PtrUInt(HKEY_LOCAL_MACHINE), '\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities', communities);
    Result := '[*] SNMP Communities:' + sLineBreak;
    IF communities.Count = 0 THEN
      Result := Result + '[**] No SNMP communities set.' + sLineBreak
    ELSE
      FOR name IN communities DO BEGIN
        val := specialize ReadValue<LongInt>(PtrUInt(HKEY_LOCAL_MACHINE), '\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities', name, -1);
        Result := Result + '[**] ' + name + ' :: ';
        CASE val OF
          4: Result := Result + 'read' + sLineBreak;
          8: Result := Result + 'read/write' + sLineBreak;
          1: Result := Result + 'no access' + sLineBreak;
          ELSE Result := Result + 'undefined' + sLineBreak;
        END;
      END;
  FINALLY
    communities.Free;
  END;
END;

END.
