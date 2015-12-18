unit NetIO;

{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils, blcksock, synsock, regexpr, httpsend, strutils;
type
  TNetIO = class
    public
      procedure SendIt(ip: AnsiString; port: AnsiString; Output: AnsiString);
      procedure WinHTTPGet(Source: String; Dest: String);
      function DownloadHTTP(URL, TargetFile: string): String;
    private
      function StringToStream(const AString: string): TStream;
      function isIP(ip: AnsiString): Boolean;
      function isPort(port: AnsiString): Boolean;
      function FoundLocationStr(headers: TStringlist; out FoundPos: integer): integer;
  end;


implementation
// Convert string to stream for network comms
Function TNetIO.StringToStream(const AString: string): TStream;
begin
  Result:= TStringStream.Create(AString);
end;

Function TNetIO.isIP(ip: AnsiString): Boolean;
var
  IPregex: TRegExpr;
begin
  IPregex:= TRegExpr.Create;
  IPregex.Expression:= '^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$';
  if IPregex.Exec(ip) then
    Result:= true
  else
    Result:= false;
  IPregex.Free
end;

Function TNetIO.isPort(port: AnsiString): Boolean;
begin
  if (strToint(port) >= 0) and (strToint(port) <= 65535) then
    Result:= true
  else
    Result:= false;
end;

procedure TNetIO.SendIt(ip: AnsiString; port: AnsiString; output : AnsiString);
var
  Client    : TTCPBlockSocket;
  StrStream : TStream;
begin
  // send to another computer listening on the specified IP:Port with nc -vlp 4444
  if isIP(ip) then begin
    if isPort(port) then begin
      Client:= TTCPBlockSocket.Create;
      Client.RaiseExcept:= True;
      Client.Connect(IP, Port);
      StrStream:= StringToStream(output);
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

// use Windows built in function for HTTP download
procedure TNetIO.WinHTTPGet(Source: String; Dest: String);
begin
 if URLDownloadToFile(nil, PChar(Source), PChar(Dest), 0, nil)=0 then
   writeln('Download ok!')
 else
   writeln('Error downloading '+Source);
end;

// private function to find 'Location:' in redirect error header...
function TNetIO.FoundLocationStr(headers: TStringlist; out FoundPos: integer): integer;
var i: integer;
begin
  result:= -1;  //for safety
  // find lind redirect URL is on
  for i:= 0 to Headers.Count do
  begin
    FoundPos:= FindPart('Location: ', Headers.Strings[i]);
    if FoundPos > 0 then //has to be above 0 otherwise nothing was found
    begin
      result:= i; //return the line number that "Location: " is on
      exit; //exit this function only the first time that iLoc is > 0
    end;
  end;
end;

// FP Synapse built-in HTTP download function, deals with HTTP redirects
function TNetIO.DownloadHTTP(URL, TargetFile: String): String;
const
  MaxRetries    = 3;
var
  HTTPGetResult : Boolean;
  http          : THTTPSend;
  RetryAttempt  : Integer;
  FoundStrPos   : Integer;
  FoundLine     : Integer;
begin
  RetryAttempt:= 1;
  http:= THTTPSend.Create;
  try
    try
      // Try to get the file
      HTTPGetResult:= http.HTTPMethod('GET', URL);
      while (HTTPGetResult = False) and (RetryAttempt < MaxRetries) do
      begin
        Sleep(500 * RetryAttempt);
        HTTPGetResult:= http.HTTPMethod('GET', URL);
        RetryAttempt:= RetryAttempt + 1;
      end;
      // If we have an answer from the server, check if the file was sent to us
      case http.Resultcode of
        100..299:
          begin
            http.Document.SaveToFile(TargetFile);
            result:= 'File downloaded.';
          end; //informational, success
        301, 302, 307:
          begin
            FoundStrPos:= 0;
            FoundLine:= FoundLocationStr(http.Headers, FoundStrPos);
            if (FoundLine >= 0) and (FoundLine <= http.Headers.count) then
            begin
              result:= StringReplace(Http.Headers.Strings[FoundLine],'Location: ','',[]); //strip the line with 'Location: http: someurl.com' down to JUST the URL
              result:= DownloadHTTP(result, TargetFile); // There be recursion here to handle nested redirects!!!
            end else
              result:= 'Could not find redirect URL!!!'; //couldn't find redirect URL Location in header
          end;
        400..499: result:= 'File download failed!!!'; // client error; 404 not found etc
        500..599: result:= 'File download failed!!!'; // internal server error
        else result:= 'File download failed!!!';
      end;
    except
      // We don't care for the reason for this error; the download failed.
      result:= 'File download failed!!!';
    end;
  finally
    http.Free;
  end;
end;

end.
