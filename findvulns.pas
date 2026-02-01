UNIT FindVulns;
{
 AUTHOR:  Brian Kellogg

 MIT licensed

 Priv escalation howto:
      http://fuzzysecurity.com/tutorials/16.html

 ClearText PWs:
      http://blogs.technet.com/b/srd/archive/2014/06/05/an-overview-OF-kb2871997.aspx
      http://blogs.technet.com/b/kfalde/archive/2014/11/01/kb2871997-AND-wdigest-part-1.aspx

 service permission information: https://support.microsoft.com/en-us/kb/914392
 Service best practices:
      Limit service DACLs to only those users who need a particular access TYPE.
      Be especially cautious with the following rights.
      If these rights are granted to a user OR to a group that has low rights,
      the rights can be used to elevate to LocalSystem on the computer:
      ChangeConf (DC)
      WDac (WD)
      WOwn (WO)
      GenericWrite (GW)
      GenericALL (GA)
}
{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils, regexpr, FileUtil, WinServices, WinReg, WinFileSystem;
TYPE
  TFindVulns = CLASS
    PUBLIC
      FUNCTION GetVulnServices: AnsiString;
      FUNCTION GetRegVulns: AnsiString;
      FUNCTION CheckEnvPathPerms: AnsiString;
      FUNCTION GetFSVulns: AnsiString;
      FUNCTION StringInArray(LookFor: String; LookIn: ARRAY OF String): Boolean;
    PRIVATE
      CONST SVC_CHK_QUOTES              = '(?-s)^"';
      CONST SVC_CHK_PATH_SPACE          = '(?-s)^\S+.exe';
      CONST SVC_EXTRACT_PATH            = '(?-s)^.+.exe"*';
      CONST SVC_VULN_ACCOUNTS_NUM       = 13;
      CONST SVC_NOT_VULN_ACCOUNTS_NUM   = 16;
      CONST SVC_VULN_PERMS_NUM          = 5;
      CONST SVC_NOT_VULN_ACCOUNTS: ARRAY[1..SVC_NOT_VULN_ACCOUNTS_NUM] OF String =(
              'Local System', 'Domain Administrators',
              'Enterprise Domain Controllers', 'Domain Controllers',
              'Built-IN (Local ) Administrators', 'Local Administrator Account',
              'Creator Owner', 'Creator Group', 'Power Users', 'Replicator',
              'Restricted Code', 'Write Restricted Code', 'Schema Administrators',
              'Certificate Services Administrators', 'Enterprise Administrators',
              'Group Policy Administrators'
              );
      CONST SVC_VULN_ACCOUNTS: ARRAY[1..SVC_VULN_ACCOUNTS_NUM] OF String = (
              'Domain Guests', 'Domain Users', 'Domain Computers',
              'Built-IN (Local ) Guests', 'Built-IN (Local ) Users',
              'Local Guest Account', 'Printer Operators', 'Authenticated Users',
              'Everyone (World)', 'Interactive Logon User', 'Anonymous Logon',
              'Remote Desktop Users (FOR Terminal Services)',
              'Anonymous Internet Users'
              );
      CONST SVC_VULN_PERMS: ARRAY[1..SVC_VULN_PERMS_NUM] OF String = (
              'ChangeConf', 'WDac', 'WOwn', 'GenericWrite', 'GenericAll'
              );
      FUNCTION NFCheck(checkThis: String; str: String): AnsiString;
      FUNCTION ServiceExtractPath(path: String): String;
      FUNCTION ServiceCheckPath(path: String): Boolean;
  END;

IMPLEMENTATION
// extract the executable path from the service startup directive
FUNCTION TFindVulns.ServiceExtractPath(path: String): String;
VAR
  regex: TRegExpr;
BEGIN
  result:= '';
  regex:= TRegExpr.Create;
  regex.Expression:= SVC_EXTRACT_PATH;
  IF regex.Exec(path) THEN
    result:= regex.Match[0];
  regex.Free;
END;

// find services with paths containing spaces and is not quoted
FUNCTION TFindVulns.ServiceCheckPath(path: String): Boolean;
VAR
  regexNoQuotes : TRegExpr;
  regexNoSpace : TRegExpr;
BEGIN
  result:= true;
  regexNoQuotes:= TRegExpr.Create;
  regexNoQuotes.Expression:= SVC_CHK_QUOTES;
  regexNoSpace:= TRegExpr.Create;
  regexNoSpace.Expression:= SVC_CHK_PATH_SPACE;
  IF regexNoQuotes.Exec(path) THEN
    result:= false
  ELSE
    IF regexNoSpace.Exec(path) THEN
      result:= false
    ELSE
      result:= true;
  regexNoQuotes.Free;
  regexNoSpace.Free;
END;

FUNCTION TFindVulns.StringInArray(
                                  LookFor: String;
                                  LookIn: ARRAY OF String
                                  ): Boolean;
VAR
  compare: String;
BEGIN
  FOR compare IN Lookin DO BEGIN
    IF LookFor = compare THEN BEGIN
       result:= true;
       EXIT;
    END;
  END;
  result := false;
END;

FUNCTION TFindVulns.GetVulnServices: AnsiString;
VAR
  WinSVCs: TWinServices;
  WinFS: TWinFileSystem;
  i: Integer;
  x: Integer;
  y: Integer;
  writeOnce: Boolean;
  path: String;
  output: AnsiString = '';
BEGIN
  WinSVCs:= TWinServices.Create;
  WinFS:= TWinFileSystem.Create;
  WinSVCs.GetServicesInfo;
  // lets check for service vulnerabilities
  FOR i:= Low(WinSVCs.Services) to High(WinSVCs.Services) DO BEGIN
    output:= concat(output, '[*] ' + WinSVCs.Services[i].Name + sLineBreak);
    output:= concat(
              output,
              '[**] Account run as :: ' +
              WinSVCs.Services[i].StartName +
              sLineBreak);
    path:= ServiceExtractPath(WinSVCs.Services[i].Path.PathName);
    WinSVCs.Services[i].Path.Writeable:= WinFS.CheckDirectoryIsWriteable(path);
    WinSVCs.Services[i].Path.Unquoted:= ServiceCheckPath(path);
    // check FOR service permission vulns, loop through each service's DACL
    FOR x:= Low(WinSVCs.Services[i].dacl) to
            High(WinSVCs.Services[i].dacl) DO BEGIN
      IF WinSVCs.Services[i].dacl[x].allow THEN BEGIN
        IF NOT StringInArray(WinSVCs.Services[i].dacl[x].entry,
                              SVC_NOT_VULN_ACCOUNTS) THEN BEGIN
          writeOnce := true;
          // loop through each entry IN the DACL
          FOR y:= Low(WinSVCs.Services[i].dacl[x].perms) to
                  High(WinSVCs.Services[i].dacl[x].perms) DO BEGIN
            IF StringInArray(WinSVCs.Services[i].dacl[x].perms[y],
                            SVC_VULN_PERMS) THEN BEGIN
              // only write the account name once
              IF writeOnce THEN BEGIN
                output:= concat(output, '[!!] Account with CONF/OWN perms :: ' +
                                WinSVCs.Services[i].dacl[x].entry);
                writeOnce := false;
              END;
              output:= concat(output, ' :: '+WinSVCs.Services[i].dacl[x].perms[y]);
            END;
          END;
          IF NOT writeOnce THEN
            output:= concat(output, sLineBreak);
        END;
      END;
    END;
    // check FOR service path vulns
    IF WinSVCs.Services[i].Path.PathName <> '' THEN
      IF WinSVCs.Services[i].Path.Writeable OR
          WinSVCs.Services[i].Path.Unquoted THEN BEGIN
        output:= concat(output, '[**] '+WinSVCs.Services[i].Path.PathName +
                        sLineBreak);
        IF WinSVCs.Services[i].Path.Writeable THEN
          output:= concat(output, '[!!] Service path is writable by you!!!' +
                          sLineBreak);
        IF WinSVCs.Services[i].Path.Unquoted THEN
          output:= concat(output, '[!!] Service path has spaces AND is unquoted!!!' +
                          sLineBreak);
      END;
    output:= concat(output, sLineBreak);
  END;
  result:= output;
  WinFS.Free;
  WinSVCs.Free;
END;

FUNCTION TFindVulns.GetRegVulns: AnsiString;
VAR
  RegVulns: TWinReg;
  output: AnsiString = '';
BEGIN
  RegVulns:= TWinReg.Create;
  output:= concat(output, '[*] ' + RegVulns.GetOSVersion + sLineBreak);
  output:= concat(output, RegVulns.GetUACStatus + sLineBreak);
  output:= concat(output, RegVulns.GetRDPStatus + sLineBreak);
  output:= concat(output, RegVulns.GetWDigestCleartextPWStatus + sLineBreak);
  output:= concat(output, RegVulns.GetMSIAlwaysInstallElevatedStatus + sLineBreak);
  output:= concat(output, RegVulns.GetAutoLogon + sLineBreak);
  output:= concat(output, RegVulns.GetSNMP + sLineBreak);
  output:= concat(output, RegVulns.GetVNCPasswords + sLineBreak);
  output:= concat(output, RegVulns.GetPasswordlessNetLogon + sLineBreak);
  output:= concat(output, RegVulns.GetStartupPersistence + sLineBreak);
  result:= output;
  RegVulns.Free;
END;

FUNCTION TFindVulns.CheckEnvPathPerms: AnsiString;
VAR
  WinFS    : TWinFileSystem;
  path     : AnsiString;
  pathList : TStringList;
  output   : AnsiString = '';
BEGIN
  WinFS:= TWinFileSystem.Create;
  pathList:= TStringList.Create;
  WinFS.GetPathList(pathList);
  output:= concat(output,
            '[*] Directories IN ENV PATH variable that are writeable by you.' +
            sLineBreak);
  FOR path IN pathList DO
    IF WinFS.CheckDirectoryIsWriteable(path) THEN
      output:= concat(output, '[!!] ' + path + sLineBreak);
  result:= output;
  pathList.Free;
  WinFS.Free;
END;

// check if INI file value is found AND print appropriate output
FUNCTION TFindVulns.NFCheck(checkThis: String; str: String): AnsiString;
VAR
  output: AnsiString = '';
BEGIN
  CASE checkThis OF
    'Not Found': output:= concat(output,
                          '[**] INI file exists but value NOT found' +
                          sLineBreak);
    ELSE output:= concat(output, '[!!] ' + str + ' :: ' + checkThis + sLineBreak);
  END;
  result:= output;
END;

// look FOR vulns inf the filesystem and files
// this procedure needs to be smarter
FUNCTION TFindVulns.GetFSVulns: AnsiString;
VAR
  FSVulns    : TWinFileSystem;
  PWcheck    : String;
  output     : AnsiString = '';
BEGIN
  FSVulns:= TWinFileSystem.Create;
  output:= concat(output, '[*] UltraVNC passwords found IN INI file:' + sLineBreak);
  IF FileExists('C:\Program Files\UltraVNC\ultravnc.ini') THEN BEGIN
    PWcheck:= FSVulns.ReadINI('C:\Program Files\UltraVNC\ultravnc.ini',
                              'ultravnc', 'passwd', 'NF');
    NFCheck(PWcheck, 'Password');
    PWcheck:= FSVulns.ReadINI('C:\Program Files\UltraVNC\ultravnc.ini',
                              'ultravnc', 'passwd2', 'NF');
    NFCheck(PWcheck, 'Password');
    FSVulns.Free;
  END ELSE
    output:= concat(output, '[**] UltraVNC INI file NOT found.' +
                    sLineBreak + sLineBreak);
  output:= concat(output, '[*] Looking FOR admin password IN sysprep files:' +
                  sLineBreak);
  IF FileExists('C:\sysprep.ini') THEN BEGIN
    PWcheck:= FSVulns.ReadINI('C:\sysprep.ini', 'GuiUnattended',
                              'AdminPassword', 'NF');
    NFCheck(PWcheck, 'Password');
  END ELSE
    output:= concat(output, '[**] C:\sysprep.ini file NOT found.' + sLineBreak);
  output:= concat(output, FSVulns.ReadXML('C:\sysprep\sysprep.xml',
                  'LocalAccounts'));
  result:= output;
  FSVulns.Free;
END;

END.
