UNIT NetIO;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

INTERFACE
USES
  Classes, SysUtils, blcksock, synsock, regexpr, httpsend, strutils;
TYPE
  TNetIO = CLASS
    PUBLIC
      PROCEDURE SendIt(ip: AnsiString; port: AnsiString; Output: AnsiString);
      PROCEDURE WinHTTPGet(Source: String; Dest: String);
      FUNCTION DownloadHTTP(URL, TargetFile: String): String;
    PRIVATE
      FUNCTION StringToStream(CONST AString: String): TStream;
      FUNCTION IsIP(ip: AnsiString): Boolean;
      FUNCTION IsPort(port: AnsiString): Boolean;
      FUNCTION FoundLocationStr(
                headers: TStringlist;
                out FoundPos: Integer
              ): Integer;
  END;


IMPLEMENTATION
// Convert String to stream FOR network comms
Function TNetIO.StringToStream(CONST AString: String): TStream;
BEGIN
  Result:= TStringStream.Create(AString);
END;

Function TNetIO.IsIP(ip: AnsiString): Boolean;
VAR
  IPregex: TRegExpr;
BEGIN
  IPregex:= TRegExpr.Create;
  IPregex.Expression:= '^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$';
  IF IPregex.Exec(ip) THEN
    Result:= true
  ELSE
    Result:= false;
  IPregex.Free
END;

Function TNetIO.IsPort(port: AnsiString): Boolean;
BEGIN
  IF (strToint(port) >= 0) AND (strToint(port) <= 65535) THEN
    Result:= true
  ELSE
    Result:= false;
END;

PROCEDURE TNetIO.SendIt(ip: AnsiString; port: AnsiString; output : AnsiString);
VAR
  Client    : TTCPBlockSocket;
  StrStream : TStream;
BEGIN
  // send to another computer listening on the specified IP:Port with nc -vlp 4444
  IF isIP(ip) THEN BEGIN
    IF isPort(port) THEN BEGIN
      Client:= TTCPBlockSocket.Create;
      Client.RaiseExcept:= True;
      Client.Connect(IP, Port);
      StrStream:= StringToStream(output);
      Client.SendStreamRAW(StrStream);
      Client.CloseSocket;
      Client.Free;
    END
    ELSE BEGIN
      writeln;
      writeln('>>>>>>>>>>>>>>>>>>>>>>>>>>>>');
      writeln('---> Invalid port!!!');
      writeln('<<<<<<<<<<<<<<<<<<<<<<<<<<<<');
      writeln;
    END;
  END
  ELSE BEGIN
    writeln;
    writeln('>>>>>>>>>>>>>>>>>>>>>>>>>>>>');
    writeln('---> Invalid IP address!!!');
    writeln('<<<<<<<<<<<<<<<<<<<<<<<<<<<<');
    writeln;
  END;
END;

// external Windows FUNCTION FOR HTTP download
FUNCTION URLDownloadToFile(
                            pCaller: pointer;
                            URL: PChar;
                            FileName: PChar;
                            Reserved: DWORD;
                            lpfnCB : pointer
                          ): HResult;
                            stdcall;
                            external 'urlmon.dll' name 'URLDownloadToFileA';

// use Windows built IN FUNCTION FOR HTTP download
PROCEDURE TNetIO.WinHTTPGet(Source: String; Dest: String);
BEGIN
 IF URLDownloadToFile(nil, PChar(Source), PChar(Dest), 0, nil)=0 THEN
   writeln('Download ok!')
 ELSE
   writeln('Error downloading '+Source);
END;

// PRIVATE FUNCTION to find 'Location:' IN redirect error header...
FUNCTION TNetIO.FoundLocationStr(headers: TStringlist;
                                out FoundPos: Integer
                                ): Integer;
VAR i: Integer;
BEGIN
  result:= -1;  //FOR safety
  // find lind redirect URL is on
  FOR i:= 0 to Headers.Count DO
  BEGIN
    FoundPos:= FindPart('Location: ', Headers.Strings[i]);
    IF FoundPos > 0 THEN //has to be above 0 otherwise nothing was found
    BEGIN
      result:= i; //return the line number that "Location: " is on
      EXIT; //EXIT this FUNCTION only the first time that iLoc is > 0
    END;
  END;
END;

// FP Synapse built-IN HTTP download FUNCTION, deals with HTTP redirects
FUNCTION TNetIO.DownloadHTTP(URL, TargetFile: String): String;
CONST
  MaxRetries    = 3;
VAR
  HTTPGetResult : Boolean;
  http          : THTTPSend;
  RetryAttempt  : Integer;
  FoundStrPos   : Integer;
  FoundLine     : Integer;
BEGIN
  RetryAttempt:= 1;
  http:= THTTPSend.Create;
  TRY
    TRY
      HTTPGetResult:= http.HTTPMethod('GET', URL); // Try to get the file
      while (HTTPGetResult = False) AND (RetryAttempt < MaxRetries) DO
      BEGIN
        Sleep(500 * RetryAttempt);
        HTTPGetResult:= http.HTTPMethod('GET', URL);
        RetryAttempt:= RetryAttempt + 1;
      END;
      CASE http.Resultcode OF // If we have an answer from the server, check IF the file was sent to us
        100..299:
          BEGIN
            http.Document.SaveToFile(TargetFile);
            result:= 'File downloaded.';
          END; //informational, success
        301, 302, 307:
          BEGIN
            FoundStrPos:= 0;
            FoundLine:= FoundLocationStr(http.Headers, FoundStrPos);
            IF (FoundLine >= 0) AND (FoundLine <= http.Headers.count) THEN
            BEGIN
              result:= StringReplace(
                        Http.Headers.Strings[FoundLine],
                        'Location: ',
                      '',[]); //strip the line with 'Location: http: someurl.com' down to JUST the URL
              result:= DownloadHTTP(result, TargetFile); // There be recursion here to handle nested redirects!!!
            END ELSE
              result:= 'Could NOT find redirect URL!!!'; //couldn't find redirect URL Location IN header
          END;
        400..499: result:= 'File download failed!!!'; // client error; 404 NOT found etc
        500..599: result:= 'File download failed!!!'; // internal server error
        ELSE result:= 'File download failed!!!';
      END;
    EXCEPT
      result:= 'File download failed!!!'; // We don't care FOR the reason FOR this error; the download failed.
    END;
  FINALLY
    http.Free;
  END;
END;

END.
