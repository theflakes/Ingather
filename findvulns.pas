unit FindVulns;
{
 sc sdshow wudfsvc
}
{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, regexpr, RunCMD, FileUtil, WinServicePerms;
type
  TFindVulns = class
    public
      procedure getVulnServices(Output : AnsiString);
    private
      const SVC_NAME_REGEX           = '(?-s)SERVICE_NAME: .+';
      const SVC_NAME_REMOVE          = 'SERVICE_NAME: ';
      const SVC_PATH_REGEX           = '(?-s)BINARY_PATH_NAME   : .+';
      const SVC_PATH_REMOVE          = 'BINARY_PATH_NAME   : ';
      const SVC_QRY_CONF             = 'sc qc ';
      const SVC_CHK_QUOTES           = '(?-s)^"';
      const SVC_CHK_PATH_SPACE       = '(?-s)^\S+.exe';
      const SVC_EXTRACT_PATH         = '(?-s)^.+.exe"*';
      const SVC_QRY_PERMS            = 'sc sdshow ';
      const SVC_PERM_REGEX           = '(?-sg)\(\S+\)';
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

// find services with paths containing spaces and is not quoted
function TFindVulns.ServiceCheckPath(path: String): Boolean;
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
function TFindVulns.ServiceCheckPathPerms(path: String): Boolean;
var
  regexQuotes  : TRegExpr;
begin
  regexQuotes:= TRegExpr.Create;
  regexQuotes.Expression:= SVC_EXTRACT_PATH;
  if regexQuotes.Exec(path) then begin
    path:= regexQuotes.Match[0];
    writeln('|-> '+path);
    path:= RemoveQuotes(path, '"');
  end;
  if FileIsWritable(path) then
    result:= true
  else
    result:= false;
  regexQuotes.Free;
end;

procedure TFindVulns.getVulnServices(output : AnsiString);
var
  outerRegex     : TRegExpr;
  innerRegex     : TRegExpr;
  cmdOut         : AnsiString;
  tmpStr         : AnsiString;
  service        : AnsiString;
  cmd            : TRunCMD;
begin
  cmd:= TRunCMD.Create;
  outerRegex:= TRegExpr.Create;
  outerRegex.Expression:= SVC_NAME_REGEX;
  if outerRegex.Exec(output) then
    repeat
      begin
        tmpStr:= '';
        service:= StringReplace(outerRegex.Match[0], SVC_NAME_REMOVE, '', []);
        writeln('');
        writeln(service);
        writeln('-----------------------------------------');
        cmdOut:= cmd.GetOutput(SVC_QRY_CONF, service);
        innerRegex:= TRegExpr.Create;
        innerRegex.Expression:= SVC_PATH_REGEX;
        if innerRegex.Exec(cmdOut) then begin
          tmpStr:= StringReplace(innerRegex.Match[0], SVC_PATH_REMOVE, '', []);
          if ServiceCheckPathPerms(tmpStr) then writeln(' \_ Service executable is writable!!!');
          if ServiceCheckPath(tmpStr) then writeln(' \_ Unquoted service path!!! ');
        end;
        cmdOut:= cmd.GetOutput(SVC_QRY_PERMS, service);
        innerRegex.Expression:= SVC_PERM_REGEX;
        while innerRegex.Exec(cmdOut) do
          begin
          writeln(innerRegex.Match[0]);
          cmdOut:= StringReplace(cmdOut, innerRegex.Match[0], '', []);
          end;
        innerRegex.Free;
      end;
    until
      not outerRegex.ExecNext;
  outerRegex.Free;
  cmd.Free;
end;

end.
