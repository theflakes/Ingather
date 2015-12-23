unit FindVulns;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}
{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, regexpr, FileUtil, WinServices, WinReg;
type
  TFindVulns = class
    public
      procedure getVulnServices;
      procedure getRegVulns;
      function StringInArray(LookFor: string; LookIn: array of string): boolean;
    private
      const SVC_CHK_QUOTES              = '(?-s)^"';
      const SVC_CHK_PATH_SPACE          = '(?-s)^\S+.exe';
      const SVC_EXTRACT_PATH            = '(?-s)^.+.exe"*';
      const SVC_VULN_ACCOUNTS_NUM       = 13;
      const SVC_NOT_VULN_ACCOUNTS_NUM   = 16;
      const SVC_VULN_PERMS_NUM          = 3;
      const SVC_NOT_VULN_ACCOUNTS: array[1..SVC_NOT_VULN_ACCOUNTS_NUM] of string = ('Local System', 'Domain Administrators', 'Enterprise Domain Controllers', 'Domain Controllers', 'Built-in (Local ) Administrators', 'Local Administrator Account', 'Creator Owner', 'Creator Group', 'Power Users', 'Replicator', 'Restricted Code', 'Write Restricted Code', 'Schema Administrators', 'Certificate Services Administrators', 'Enterprise Administrators', 'Group Policy Administrators');
      const SVC_VULN_ACCOUNTS: array[1..SVC_VULN_ACCOUNTS_NUM] of string = ('Domain Guests', 'Domain Users', 'Domain Computers', 'Built-in (Local ) Guests', 'Built-in (Local ) Users', 'Local Guest Account', 'Printer Operators', 'Authenticated Users', 'Everyone (World)', 'Interactive Logon User', 'Anonymous Logon', 'Remote Desktop Users (for Terminal Services)', 'Anonymous Internet Users');
      const SVC_VULN_PERMS: array[1..SVC_VULN_PERMS_NUM] of string = ('ChangeConf', 'WDac', 'WOwn');
      function ServiceExtractPath(path: string): string;
      function ServiceCheckPath(path: String) : Boolean;
      function ServiceCheckPathPerms(path: String): Boolean;
      function RemoveQuotes(const S: string; const QuoteChar: Char): string;
  end;

implementation
function TFindVulns.RemoveQuotes(const S: string; const QuoteChar: Char): string;
var
  Len: Integer;
begin
  Result := S;
  Len := Length(Result);
  if (Len < 2) then Exit;                    //Quoted text must have at least 2 chars
  if (Result[1] <> QuoteChar) then Exit;     //Text is not quoted
  if (Result[Len] <> QuoteChar) then Exit;   //Text is not quoted
  System.Delete(Result, Len, 1);
  System.Delete(Result, 1, 1);
  Result := StringReplace(Result, QuoteChar+QuoteChar, QuoteChar, [rfReplaceAll]);
end;

// extract the executable path from the service startup directive
function TFindVulns.ServiceExtractPath(path: string): string;
var
  regex: TRegExpr;
begin
  regex:= TRegExpr.Create;
  regex.Expression:= SVC_EXTRACT_PATH;
  if regex.Exec(path) then
    result:= regex.Match[0];
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

// evaluate service path permissions
function TFindVulns.ServiceCheckPathPerms(path: string): Boolean;
begin
  path:= RemoveQuotes(path, '"');
  if FileIsWritable(path) then
    result:= true
  else
    result:= false;
end;

function TFindVulns.StringInArray(LookFor: string; LookIn: array of string): boolean;
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

procedure TFindVulns.getVulnServices;
var
  WinSVCs: TWinServices;
  i: integer;
  x: integer;
  y: integer;
  writeOnce: boolean;
  path: string;
begin
  WinSVCs:= TWinServices.Create;
  WinSVCs.GetServicesInfo;
  // lets check for service vulnerabilities
  for i:= Low(WinSVCs.Services) to High(WinSVCs.Services) do begin
    writeln(WinSVCs.Services[i].Name);
    writeln('--------------------------------------------');
    writeln('|-> Account run as :: '+WinSVCs.Services[i].StartName);
    path:= ServiceExtractPath(WinSVCs.Services[i].Path.PathName);
    WinSVCs.Services[i].Path.Writeable:= ServiceCheckPathPerms(path);
    WinSVCs.Services[i].Path.Unquoted:= ServiceCheckPath(path);
    // check for service permission vulns, loop through each service's DACL
    for x:= Low(WinSVCs.Services[i].dacl) to High(WinSVCs.Services[i].dacl) do begin
      if WinSVCs.Services[i].dacl[x].allow then begin
        if not StringInArray(WinSVCs.Services[i].dacl[x].entry, SVC_NOT_VULN_ACCOUNTS) then begin
          writeOnce := true;
          // loop through each entry in the DACL
          for y:= Low(WinSVCs.Services[i].dacl[x].perms) to High(WinSVCs.Services[i].dacl[x].perms) do begin
            if StringInArray(WinSVCs.Services[i].dacl[x].perms[y], SVC_VULN_PERMS) then begin
              // only write the account name once
              if writeOnce then begin
                write('|-> Account with CONF/OWN perms :: '+WinSVCs.Services[i].dacl[x].entry);
                writeOnce := false;
              end;
              write(' :: '+WinSVCs.Services[i].dacl[x].perms[y]);
            end;
          end;
          if not writeOnce then
            writeln;
        end;
      end;
    end;
    // check for service path vulns
    if WinSVCs.Services[i].Path.PathName <> '' then
      if WinSVCs.Services[i].Path.Writeable or WinSVCs.Services[i].Path.Unquoted then begin
        writeln('|-> '+WinSVCs.Services[i].Path.PathName);
        if WinSVCs.Services[i].Path.Writeable then
          writeln(' \_> Service path is writable by you!!!');
        if WinSVCs.Services[i].Path.Unquoted then
          writeln(' \_> Service path has spaces and is unquoted!!!');;
      end;
    writeln
  end;
  WinSVCs.Free;
end;

procedure TFindVulns.getRegVulns;
var
  RegVulns: TWinReg;
begin
  RegVulns:= TWinReg.Create;
  writeln(RegVulns.GetOSVersion);
  writeln(RegVulns.GetUACStatus);
  writeln(RegVulns.GetRDPStatus);
  writeln(RegVulns.GetWDigestCleartextPWStatus);
  writeln(RegVulns.GetMSIAlwaysInstallElevatedStatus);
  RegVulns.Free;
end;

end.
