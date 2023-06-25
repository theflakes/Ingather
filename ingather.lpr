PROGRAM Ingather;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

USES
  Classes, SysUtils, CustApp, WinUsers, RunAs, NetIO, FindVulns, RunCMD,
  WinFileSystem, StrUtils, DataDefs
  { you can add units after this };

TYPE
  { TIngather }
  TIngather = CLASS(TCustomApplication)
  PROTECTED
    PROCEDURE DoRun; OVERRIDE;
  PUBLIC
    CONSTRUCTOR Create(TheOwner: TComponent); OVERRIDE;
    DESTRUCTOR Destroy; OVERRIDE;
    PROCEDURE WriteHelp; VIRTUAL;
  PRIVATE
    FUNCTION PrintHeader(cmd: String): AnsiString;
    FUNCTION PrintEnums(cmds: TDataDefs.CommandArray): AnsiString;
    PROCEDURE DownloadFile();
    FUNCTION IsAdmin(): AnsiString;
    FUNCTION RunEnums(): AnsiString;
    FUNCTION RunCmd(): AnsiString;
    FUNCTION RunCmds(): AnsiString;
    FUNCTION Tx(output: AnsiString): Boolean;
    FUNCTION SaveOutput(output: AnsiString): Boolean;
  END;

{ TIngather }
// Main PROGRAM flow control
PROCEDURE TIngather.DoRun;
VAR
  ErrorMsg        : String = '';
  output          : AnsiString = '';
  ScreenPrint     : Boolean = true;
BEGIN
  // quick check parameters
  ErrorMsg:= CheckOptions(
    'c:d:ehi:lo:p:s:z', 'command: download: enum help ip: list out: port: save:'
    );
  IF (ErrorMsg <> '') OR (HasOption('h','help')) OR (ParamCount = 0) THEN BEGIN
    IF (ErrorMsg <> '') THEN writeln(ErrorMsg);
    WriteHelp;
    Terminate;
    Exit;
  END;

  // Is user an admin
  output:= concat(output, IsAdmin());

  IF HasOption('l', 'list') THEN BEGIN
    output:= concat(output, PrintHeader('Enumeration Commands'));
    output:= concat(output, PrintEnums(TDataDefs.CMDS));
  END;

  // download file
  IF HasOption('d', 'download') AND HasOption('s','save') THEN BEGIN
    DownloadFile;
  END;

  // Do vulnerability enumeration on host
  IF HasOption('c', 'command') THEN BEGIN
    output:= concat(output, RunCmd());
  END;

  IF HasOption('e', 'enum') THEN BEGIN
    // run system enumeration analysis
    output:= concat(output, RunEnums());
    // run basic enumeration commands
    output:= concat(output, RunCmds());
  END;

  // Send output to another computer?
  IF HasOption('i', 'ip') AND HasOption('p','port') THEN ScreenPrint:= Tx(output);
  // Write all command outputs to a file?
  IF HasOption('o', 'out') THEN ScreenPrint:= SaveOutput(output);
  // no other output specified, so output to console
  IF ScreenPrint THEN writeln(output);

  Terminate;
END;

FUNCTION TIngather.IsAdmin(): AnsiString;
VAR
  escalate: TRunAs;
BEGIN
  result:= '';
  escalate:= TRunAs.Create;
  IF escalate.IsUserAdmin THEN
    result:= concat(result, '[!] You are an admin' + sLineBreak)
  ELSE
    result:= concat(result, '[*] You are NOT an admin.' + sLineBreak);
  escalate.Free;
END;

PROCEDURE TIngather.DownloadFile();
VAR
  ErrorMsg: String = '';
  nwrk    : TNetIO;
  download: String = '';
  save    : String = '';
BEGIN
  nwrk:= TNetIO.Create;
  download:= Self.GetOptionValue('d','download');
  save:= Self.GetOptionValue('s','save');
  IF HasOption('z') THEN
    nwrk.WinHTTPGet(download, save)
  ELSE BEGIN
    ErrorMsg:= nwrk.DownloadHTTP(download, save);
    writeln(ErrorMsg);
  END;
  nwrk.Free;
END;

FUNCTION TIngather.RunEnums(): AnsiString;
VAR
  vulns : TFindVulns;
BEGIN
  result:= '';
  vulns:= TFindVulns.Create;
  writeln('[*] Inspecting the registry');
  result:= concat(result, vulns.GetRegVulns + sLineBreak);
  writeln('[*] Inspecting environment paths');
  result:= concat(result, vulns.CheckEnvPathPerms + sLineBreak);
  writeln('[*] Inspecting filesystem');
  result:= concat(result, vulns.GetFSVulns + sLineBreak);
  writeln('[*] Inspecting service configurations');
  result:= concat(result, vulns.GetVulnServices + sLineBreak);
  vulns.Free;
END;

FUNCTION TIngather.RunCmd(): AnsiString;
VAR
  execute: TRunCMD;
  command: String = '';
BEGIN
  execute:= TRunCMD.Create;
  writeln('[*] Running custom commands');
  command:= Self.GetOptionValue('c','command');
  result:= execute.getOutput(command, '', false);
  execute.Free;
END;

FUNCTION TIngather.RunCmds(): AnsiString;
VAR
  x      : Integer;
  execute: TRunCMD;
BEGIN
  writeln('[*] Running misc. enumeration commands');
  result:= '';
  execute:= TRunCMD.Create;
  FOR x:= 1 to TDataDefs.NUM_CMDS DO BEGIN
    result:= concat(result, PrintHeader(TDataDefs.CMDS[x][1]));
    result:= concat(result, execute.getOutput(TDataDefs.CMDS[x][1], '', false));
    result:= concat(result, sLineBreak)
  END;
  execute.Free;
END;

FUNCTION TIngather.Tx(output: AnsiString): Boolean;
VAR
  ip  : AnsiString = '';
  port: AnsiString = '';
  nwrk: TNetIO;
BEGIN
  nwrk:= TNetIO.Create;
  ip:= Self.GetOptionValue('i','ip');
  port:= Self.GetOptionValue('p','port');
  writeln('[*] sending all output to ' + ip + ':' + port);
  nwrk.SendIt(ip, port, output);
  nwrk.Free;
  result:= false;
END;

FUNCTION TIngather.SaveOutput(output: AnsiString): Boolean;
VAR
  outfile: AnsiString;
  tfOut  : TextFile;
BEGIN
  outfile:= Self.GetOptionValue('o','out');
  AssignFile(tfOut, outfile);
  rewrite(tfOut);
  writeln(tfOut, output);
  writeln('[*] Wrote output to file');
  result:= false;
END;

FUNCTION TIngather.PrintHeader(cmd: String): AnsiString;
BEGIN
  result:= '';
  result:= concat(result, '[*] '+cmd+sLineBreak);
END;

FUNCTION TIngather.PrintEnums(cmds: TDataDefs.CommandArray): AnsiString;
VAR
  x: Integer;
BEGIN
  result:= '';
  FOR x:= 1 to TDataDefs.NUM_CMDS DO BEGIN
    result:= concat(result, '[**] Command: '+cmds[x][1]+sLineBreak);
    result:= concat(result, ' Description: '+cmds[x][2]+sLineBreak);
  END;
END;

PROCEDURE TIngather.WriteHelp;
VAR
  help: AnsiString;
BEGIN
  help:= LineEnding +
          'Author : Brian Kellogg' + LineEnding +
          'License: MIT' + LineEnding +
          'Purpose: Gather various forensic information.' + LineEnding +
          LineEnding +
          'Usage:' + LineEnding +
          '  Ingather.exe -i 1.1.1.1 -p 4444 --enum --out="output.txt"' + LineEnding +
          '  Ingather.exe -i 1.1.1.1 -p 4444 --enum --out="output.txt"' + LineEnding +
          '  Ingather.exe -c "ipconfig /all" -i 1.1.1.1 -p 4444' + LineEnding +
          LineEnding +
          'Download file over HTTP:' + LineEnding +
          '  -d, --download : download file' + LineEnding +
          '  -s, --save     : location to save downloaded file to' + LineEnding +
          '  -z,            : use the Windows HTTP download function' + LineEnding +
          '                   otherwise use custom HTTP download function' + LineEnding +
          'Run options:' + LineEnding +
          '  -c, --command  : run custom command' + LineEnding +
          '  -e, --enum     : run all builtin enumerations' + LineEnding +
          'Output options:' + LineEnding +
          '  -i, --ip       : destination IP address' + LineEnding +
          '  -p, --port     : destination port' + LineEnding +
          '  -o, --out      : write enumeration command outputs to file' + LineEnding +
          '  If output to file or network is specified,' + LineEnding +
          '  screen output will be suppressed.' + LineEnding +
          'Info:' + LineEnding +
          '  -h, --help     : print this help message' + LineEnding +
          '  -l, --list     : print default enum commands and descriptions' + LineEnding +
          LineEnding;
  write(help);
END;

CONSTRUCTOR TIngather.Create(TheOwner: TComponent);
BEGIN
  inherited Create(TheOwner);
  StopOnException:= True;
END;

DESTRUCTOR TIngather.Destroy;
BEGIN
  inherited Destroy;
END;

VAR
  Application: TIngather;

{$R *.res}

BEGIN
  Application:= TIngather.Create(nil);
  Application.Title:= 'Ingather';
  Application.Run;
  Application.Free;
END.
