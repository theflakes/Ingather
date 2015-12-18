unit FindVulns;
{
 sc sdshow wudfsvc
 sc qc wudfsvc
 icacls directory

}
{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, regexpr, RunCMD;
type
  TFindVulns = class
    public
      procedure getVulnServices(Output : AnsiString);
      function StreamToString(Stream: TStream): AnsiString;
    private
      const SVC_NAME_REGEX           = '(?-s)SERVICE_NAME: .+';
      const SVC_NAME_REMOVE          = 'SERVICE_NAME: ';
      const SVC_PATH_REGEX           = '(?-s)BINARY_PATH_NAME   : .+';
      const SVC_PATH_REMOVE          = 'BINARY_PATH_NAME   : ';
      const SVC_QUERY_CONF           = 'sc qc ';
      var cmd                        : TRunCMD;
      function ServiceCheckPath      : Boolean;
      function ServiceCheckPathPerms : Boolean;
      function ServiceCheckPerms     : Boolean;
  end;

implementation
function TFindVulns.StreamToString(Stream: TStream): AnsiString;
var
    len: Integer;
begin
    Stream.Position:= 0;
    len:= Stream.Size - Stream.Position;
    SetLength(Result, len);
    if len > 0 then Stream.ReadBuffer(Result[1], len);
end;

function TFindVulns.ServiceCheckPath: Boolean;
begin

end;

function TFindVulns.ServiceCheckPathPerms: Boolean;
begin

end;

function TFindVulns.ServiceCheckPerms: Boolean;
begin

end;

procedure TFindVulns.getVulnServices(output : AnsiString);
var
  outerRegex     : TRegExpr;
  innerRegex     : TRegExpr;
  RunThis        : String;
  OutputStream   : TStream;
  cmdOut         : AnsiString;
  tmpStr         : AnsiString;
begin
  outerRegex:= TRegExpr.Create;
  outerRegex.Expression:= SVC_NAME_REGEX;
  if outerRegex.Exec(output) then
    repeat
      begin
        tmpStr:= '';
        tmpStr:= StringReplace(outerRegex.Match[0], SVC_NAME_REMOVE, '', []);
        writeln(tmpStr);
        RunThis:= concat(SVC_QUERY_CONF, '"', tmpStr, '"');
        OutputStream:= cmd.Run(RunThis);
        cmdOut:= StreamToString(OutputStream);
        innerRegex:= TRegExpr.Create;
        innerRegex.Expression:= SVC_PATH_REGEX;
        if innerRegex.Exec(cmdOut) then begin
          tmpStr:= StringReplace(innerRegex.Match[0], SVC_PATH_REMOVE, '', []);
          writeln(tmpStr);
        end;
        innerRegex.Free;
        OutputStream.Free;
      end;
    until
      not outerRegex.ExecNext;
  outerRegex.Free;
end;

end.
