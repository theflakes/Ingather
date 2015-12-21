unit FindVulns;
{
 wmic service get Name,PathName,Started,StartMode,StartName,Status
 sc sdshow wudfsvc
}
{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, regexpr, FileUtil, WinServices;
type
  TFindVulns = class
    public
      procedure getVulnServices;
    private
      const SVC_CHK_QUOTES           = '(?-s)^"';
      const SVC_CHK_PATH_SPACE       = '(?-s)^\S+.exe';
      const SVC_EXTRACT_PATH         = '(?-s)^.+.exe"*';
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

procedure TFindVulns.getVulnServices;
var
  WinSVCs: TWinServices;
  i: integer;
  path: string;
begin
  WinSVCs:= TWinServices.Create;
  WinSVCs.GetServicesInfo;
  // lets check for service path vulnerabilities
  for i:= Low(WinSVCs.Services) to High(WinSVCs.Services) do begin
    path:= ServiceExtractPath(WinSVCs.Services[i].Path.PathName);
    WinSVCs.Services[i].Path.Writeable:= ServiceCheckPathPerms(path);
    WinSVCs.Services[i].Path.Unquoted:= ServiceCheckPath(path);
  end;
  for i:= Low(WinSVCs.Services) to High(WinSVCs.Services) do begin
    if WinSVCs.Services[i].Path.PathName <> '' then
      if WinSVCs.Services[i].Path.Writeable or WinSVCs.Services[i].Path.Unquoted then begin
        writeln(WinSVCs.Services[i].Name);
        writeln('--------------------------------------------');
        writeln('|-> '+WinSVCs.Services[i].Path.PathName);
        if WinSVCs.Services[i].Path.Writeable then
          writeln(' \_> Service path is writable by you!!!');
        if WinSVCs.Services[i].Path.Unquoted then
          writeln(' \_> Service path has spaces and is unquoted!!!');
        writeln;
      end;
  end;
  WinSVCs.Free;
end;

end.
