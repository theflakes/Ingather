unit NetIO;

{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils, blcksock, synsock, regexpr;
type
  TNetIO = class
    public
      procedure SendIt(ip: AnsiString; port: AnsiString; Output: AnsiString);
      procedure GetIt(Source: String; Dest: String);
    private
      Function StringToStream(const AString: string): TStream;
      Function isIP(ip: AnsiString): Boolean;
      Function isPort(port: AnsiString): Boolean;
  end;


implementation
// Convert string to stream for network comms
Function TNetIO.StringToStream(const AString: string): TStream;
begin
  Result := TStringStream.Create(AString);
end;

Function TNetIO.isIP(ip: AnsiString): Boolean;
var
  IPregex: TRegExpr;
begin
  IPregex := TRegExpr.Create;
  IPregex.Expression := '^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$';
  if IPregex.Exec(ip) then
    Result := true
  else
    Result := false;
  IPregex.Free
end;

Function TNetIO.isPort(port: AnsiString): Boolean;
begin
  if (strToint(port) >= 0) and (strToint(port) <= 65535) then
    Result := true
  else
    Result := false;
end;

procedure TNetIO.SendIt(ip: AnsiString; port: AnsiString; output : AnsiString);
var
  Client    : TTCPBlockSocket;
  StrStream : TStream;
begin
  // send to another computer listening on the specified IP:Port with nc -vlp 4444
  if isIP(ip) then begin
    if isPort(port) then begin
      Client := TTCPBlockSocket.Create;
      Client.RaiseExcept := True;
      Client.Connect(IP, Port);
      StrStream := StringToStream(output);
      Client.SendStreamRAW(StrStream);
      Client.CloseSocket;
      Client.Free;
    end
    else begin
      writeln;
      writeln('>>>>>>>>>>>>>>>>>>>>>>>>>>>>');
      writeln('---> Invalid port!!!');
      writeln('<<<<<<<<<<<<<<<<<<<<<<<<<<<<');
      writeln;
    end;
  end
  else begin
    writeln;
    writeln('>>>>>>>>>>>>>>>>>>>>>>>>>>>>');
    writeln('---> Invalid IP address!!!');
    writeln('<<<<<<<<<<<<<<<<<<<<<<<<<<<<');
    writeln;
  end;
end;

// external Windows function for HTTP download
function URLDownloadToFile(pCaller: pointer; URL: PChar; FileName: PChar; Reserved: DWORD; lpfnCB : pointer): HResult; stdcall; external 'urlmon.dll' name 'URLDownloadToFileA';

procedure TNetIO.GetIt(Source: String; Dest: String);
begin
 if URLDownloadToFile(nil, PChar(Source), PChar(Dest), 0, nil)=0 then
   writeln('Download ok!')
 else
   writeln('Error downloading '+Source);
end;

end.
