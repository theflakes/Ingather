unit FindVulns;
{
 AUTHOR:  Brian Kellogg

 MIT licensed

 Priv escalation howto:
      http://fuzzysecurity.com/tutorials/16.html

 ClearText PWs:
      http://blogs.technet.com/b/srd/archive/2014/06/05/an-overview-of-kb2871997.aspx
      http://blogs.technet.com/b/kfalde/archive/2014/11/01/kb2871997-and-wdigest-part-1.aspx

 service permission information: https://support.microsoft.com/en-us/kb/914392
 Service best practices:
      Limit service DACLs to only those users who need a particular access type.
      Be especially cautious with the following rights.
      If these rights are granted to a user or to a group that has low rights,
      the rights can be used to elevate to LocalSystem on the computer:
      ChangeConf (DC)
      WDac (WD)
      WOwn (WO)
      GenericWrite (GW)
      GenericALL (GA)
}
{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, regexpr, FileUtil, WinServices, WinReg, WinFileSystem;
type
  TFindVulns = class
    public
      function GetVulnServices: AnsiString;
      function GetRegVulns: AnsiString;
      function CheckEnvPathPerms: AnsiString;
      function GetFSVulns: AnsiString;
      function StringInArray(LookFor: string; LookIn: array of string): boolean;
    private
      const SVC_CHK_QUOTES              = '(?-s)^"';
      const SVC_CHK_PATH_SPACE          = '(?-s)^\S+.exe';
      const SVC_EXTRACT_PATH            = '(?-s)^.+.exe"*';
      const SVC_VULN_ACCOUNTS_NUM       = 13;
      const SVC_NOT_VULN_ACCOUNTS_NUM   = 16;
      const SVC_VULN_PERMS_NUM          = 5;
      const SVC_NOT_VULN_ACCOUNTS: array[1..SVC_NOT_VULN_ACCOUNTS_NUM] of string =(
              'Local System', 'Domain Administrators',
              'Enterprise Domain Controllers', 'Domain Controllers',
              'Built-in (Local ) Administrators', 'Local Administrator Account',
              'Creator Owner', 'Creator Group', 'Power Users', 'Replicator',
              'Restricted Code', 'Write Restricted Code', 'Schema Administrators',
              'Certificate Services Administrators', 'Enterprise Administrators',
              'Group Policy Administrators'
              );
      const SVC_VULN_ACCOUNTS: array[1..SVC_VULN_ACCOUNTS_NUM] of string = (
              'Domain Guests', 'Domain Users', 'Domain Computers',
              'Built-in (Local ) Guests', 'Built-in (Local ) Users',
              'Local Guest Account', 'Printer Operators', 'Authenticated Users',
              'Everyone (World)', 'Interactive Logon User', 'Anonymous Logon',
              'Remote Desktop Users (for Terminal Services)',
              'Anonymous Internet Users'
              );
      const SVC_VULN_PERMS: array[1..SVC_VULN_PERMS_NUM] of string = (
              'ChangeConf', 'WDac', 'WOwn', 'GenericWrite', 'GenericAll'
              );
      function NFCheck(checkThis: string; str: string): AnsiString;
      function ServiceExtractPath(path: string): string;
      function ServiceCheckPath(path: string): Boolean;
  end;

implementation
// extract the executable path from the service startup directive
function TFindVulns.ServiceExtractPath(path: string): string;
var
  regex: TRegExpr;
begin
  result:= '';
  regex:= TRegExpr.Create;
  regex.Expression:= SVC_EXTRACT_PATH;
  if regex.Exec(path) then
    result:= regex.Match[0];
  regex.Free;
end;

// find services with paths containing spaces and is not quoted
function TFindVulns.ServiceCheckPath(path: string): Boolean;
var
  regexNoQuotes : TRegExpr;
  regexNoSpace : TRegExpr;
begin
  result:= true;
  regexNoQuotes:= TRegExpr.Create;
  regexNoQuotes.Expression:= SVC_CHK_QUOTES;
  regexNoSpace:= TRegExpr.Create;
  regexNoSpace.Expression:= SVC_CHK_PATH_SPACE;
  if regexNoQuotes.Exec(path) then
    result:= false
  else
    if regexNoSpace.Exec(path) then
      result:= false
    else
      result:= true;
  regexNoQuotes.Free;
  regexNoSpace.Free;
end;

function TFindVulns.StringInArray(
                                  LookFor: string;
                                  LookIn: array of string
                                  ): boolean;
var
  compare: string;
begin
  for compare in Lookin do begin
    if LookFor = compare then begin
       result:= true;
       exit;
    end;
  end;
  result := false;
end;

function TFindVulns.GetVulnServices: AnsiString;
var
  WinSVCs: TWinServices;
  WinFS: TWinFileSystem;
  i: integer;
  x: integer;
  y: integer;
  writeOnce: boolean;
  path: string;
  output: AnsiString = '';
begin
  WinSVCs:= TWinServices.Create;
  WinFS:= TWinFileSystem.Create;
  WinSVCs.GetServicesInfo;
  // lets check for service vulnerabilities
  for i:= Low(WinSVCs.Services) to High(WinSVCs.Services) do begin
    output:= concat(output, '[*] ' + WinSVCs.Services[i].Name + sLineBreak);
    output:= concat(
              output,
              '[**] Account run as :: ' +
              WinSVCs.Services[i].StartName +
              sLineBreak);
    path:= ServiceExtractPath(WinSVCs.Services[i].Path.PathName);
    WinSVCs.Services[i].Path.Writeable:= WinFS.CheckDirectoryIsWriteable(path);
    WinSVCs.Services[i].Path.Unquoted:= ServiceCheckPath(path);
    // check for service permission vulns, loop through each service's DACL
    for x:= Low(WinSVCs.Services[i].dacl) to
            High(WinSVCs.Services[i].dacl) do begin
      if WinSVCs.Services[i].dacl[x].allow then begin
        if not StringInArray(WinSVCs.Services[i].dacl[x].entry,
                              SVC_NOT_VULN_ACCOUNTS) then begin
          writeOnce := true;
          // loop through each entry in the DACL
          for y:= Low(WinSVCs.Services[i].dacl[x].perms) to
                  High(WinSVCs.Services[i].dacl[x].perms) do begin
            if StringInArray(WinSVCs.Services[i].dacl[x].perms[y],
                            SVC_VULN_PERMS) then begin
              // only write the account name once
              if writeOnce then begin
                output:= concat(output, '[!!] Account with CONF/OWN perms :: ' +
                                WinSVCs.Services[i].dacl[x].entry);
                writeOnce := false;
              end;
              output:= concat(output, ' :: '+WinSVCs.Services[i].dacl[x].perms[y]);
            end;
          end;
          if not writeOnce then
            output:= concat(output, sLineBreak);
        end;
      end;
    end;
    // check for service path vulns
    if WinSVCs.Services[i].Path.PathName <> '' then
      if WinSVCs.Services[i].Path.Writeable or
          WinSVCs.Services[i].Path.Unquoted then begin
        output:= concat(output, '[**] '+WinSVCs.Services[i].Path.PathName +
                        sLineBreak);
        if WinSVCs.Services[i].Path.Writeable then
          output:= concat(output, '[!!] Service path is writable by you!!!' +
                          sLineBreak);
        if WinSVCs.Services[i].Path.Unquoted then
          output:= concat(output, '[!!] Service path has spaces and is unquoted!!!' +
                          sLineBreak);
      end;
    output:= concat(output, sLineBreak);
  end;
  result:= output;
  WinFS.Free;
  WinSVCs.Free;
end;

function TFindVulns.GetRegVulns: AnsiString;
var
  RegVulns: TWinReg;
  output: AnsiString = '';
begin
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
  result:= output;
  RegVulns.Free;
end;

function TFindVulns.CheckEnvPathPerms: AnsiString;
var
  WinFS    : TWinFileSystem;
  path     : AnsiString;
  pathList : TStringList;
  output   : AnsiString = '';
begin
  WinFS:= TWinFileSystem.Create;
  pathList:= TStringList.Create;
  WinFS.GetPathList(pathList);
  output:= concat(output,
            '[*] Directories in ENV PATH variable that are writeable by you.' +
            sLineBreak);
  for path in pathList do
    if WinFS.CheckDirectoryIsWriteable(path) then
      output:= concat(output, '[!!] ' + path + sLineBreak);
  result:= output;
  pathList.Free;
  WinFS.Free;
end;

// check if INI file value is found and print appropriate output
function TFindVulns.NFCheck(checkThis: string; str: string): AnsiString;
var
  output: AnsiString = '';
begin
  case checkThis of
    'Not Found': output:= concat(output,
                          '[**] INI file exists but value not found' +
                          sLineBreak);
    else output:= concat(output, '[!!] ' + str + ' :: ' + checkThis + sLineBreak);
  end;
  result:= output;
end;

// look for vulns in the filesystem and files
// this procedure needs to be smarter
function TFindVulns.GetFSVulns: AnsiString;
var
  FSVulns    : TWinFileSystem;
  PWcheck    : String;
  output     : AnsiString = '';
begin
  FSVulns:= TWinFileSystem.Create;
  output:= concat(output, '[*] UltraVNC passwords found in INI file:' + sLineBreak);
  if FileExists('C:\Program Files\UltraVNC\ultravnc.ini') then begin
    PWcheck:= FSVulns.ReadINI('C:\Program Files\UltraVNC\ultravnc.ini',
                              'ultravnc', 'passwd', 'NF');
    NFCheck(PWcheck, 'Password');
    PWcheck:= FSVulns.ReadINI('C:\Program Files\UltraVNC\ultravnc.ini',
                              'ultravnc', 'passwd2', 'NF');
    NFCheck(PWcheck, 'Password');
    FSVulns.Free;
  end else
    output:= concat(output, '[**] UltraVNC INI file not found.' +
                    sLineBreak + sLineBreak);
  output:= concat(output, '[*] Looking for admin password in sysprep files:' +
                  sLineBreak);
  if FileExists('C:\sysprep.ini') then begin
    PWcheck:= FSVulns.ReadINI('C:\sysprep.ini', 'GuiUnattended',
                              'AdminPassword', 'NF');
    NFCheck(PWcheck, 'Password');
  end else
    output:= concat(output, '[**] C:\sysprep.ini file not found.' + sLineBreak);
  output:= concat(output, FSVulns.ReadXML('C:\sysprep\sysprep.xml',
                  'LocalAccounts'));
  result:= output;
  FSVulns.Free;
end;

end.
