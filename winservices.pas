unit WinServices;
{
 AUTHOR:  Brian Kellogg

 MIT licensed

 service permission information: https://support.microsoft.com/en-us/kb/914392

 Best practices:
  Limit service DACLs to only those users who need a particular access type.
  Be especially cautious with the following rights.
  If these rights are granted to a user or to a group that has low rights,
  the rights can be used to elevate to LocalSystem on the computer:
  ChangeConf (DC)
  WDac (WD)
  WOwn (WO)
  GenericWrite (GW)
  GenericALL (GA)
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, regexpr, RunCMD, Misc;
type
  TdaclVulns = record
    config: boolean;
    escalate: boolean;
  end;

  Tdacl = record
    allow: boolean;
    entry: string;
    perms: array of string;
    vulns: TdaclVulns;
  end;

  TPathName = record
    PathName: string;
    Unquoted: boolean;
    Writeable: boolean;
  end;

  TService = record
    Name: string;
    Path: TPathName;
    Started: string;
    StartMode: string;
    StartName: string;
    Status: string;
    dacl: array of Tdacl;
  end;

  TWinServices = class
    public
      Services: array of TService;
      procedure GetServicesInfo;
    private
      function Users(userAbbr: string): string;
      function Perms(permAbbr: string): string;
      procedure GetServicePerms;
      procedure SplitPermAbbreviaions(Str: string; ListOfStrings: TStrings);
      const SVC_QRY_CONF             = 'wmic service ';
      const SVC_QRY_PERMS            = 'sc sdshow ';
      const SVC_PERM_REGEX           = '(?-sg)\((A|D)\S+\)';
      const SVC_LINE_REGEX           = '(?-s).+,.+,.+,.+,.+,.+,.+';
      const SVC_LINE_PART_REGEX      = '(?-sg).+,';
  end;

// convert user/group abbreviations to user/group names
implementation
function TWinServices.Users(userAbbr: string): string;
begin
  case userAbbr of
    'DA': result:= 'Domain Administrators';
    'DG': result:= 'Domain Guests';
    'DU': result:= 'Domain Users';
    'ED': result:= 'Enterprise Domain Controllers';
    'DD': result:= 'Domain Controllers';
    'DC': result:= 'Domain Computers';
    'BA': result:= 'Built-in (Local ) Administrators';
    'BG': result:= 'Built-in (Local ) Guests';
    'BU': result:= 'Built-in (Local ) Users';
    'LA': result:= 'Local Administrator Account';
    'LG': result:= 'Local Guest Account';
    'AO': result:= 'Account Operators';
    'BO': result:= 'Backup Operators';
    'PO': result:= 'Printer Operators';
    'SO': result:= 'Server Operators';
    'AU': result:= 'Authenticated Users';
    'PS': result:= 'Personal Self';
    'CO': result:= 'Creator Owner';
    'CG': result:= 'Creator Group';
    'SY': result:= 'Local System';
    'PU': result:= 'Power Users';
    'WD': result:= 'Everyone (World)';
    'RE': result:= 'Replicator';
    'IU': result:= 'Interactive Logon User';
    'NU': result:= 'Network Logon User';
    'SU': result:= 'Service Logon User';
    'RC': result:= 'Restricted Code';
    'WR': result:= 'Write Restricted Code';
    'AN': result:= 'Anonymous Logon';
    'SA': result:= 'Schema Administrators';
    'CA': result:= 'Certificate Services Administrators';
    'RS': result:= 'Remote Access Servers Group';
    'EA': result:= 'Enterprise Administrators';
    'PA': result:= 'Group Policy Administrators';
    'RU': result:= 'Alias to Allow Previous Windows 2000';
    'LS': result:= 'Local Service Account (for Services)';
    'NS': result:= 'Network Service Account (for Services)';
    'RD': result:= 'Remote Desktop Users (for Terminal Services)';
    'NO': result:= 'Network Configuration Operators';
    'MU': result:= 'Performance Monitor Users';
    'LU': result:= 'Performance Log Users';
    'IS': result:= 'Anonymous Internet Users';
    'CY': result:= 'Crypto Operators';
    'OW': result:= 'Owner Rights SID';
    'RM': result:= 'RMS Service';
    else result:= userAbbr;
  end;
end;

// convert service permissions abbreviations to full names
function TWinServices.Perms(permAbbr: string): string;
begin
  case permAbbr of
    'CC': result:= 'QueryConf';
    'DC': result:= 'ChangeConf';
    'LC': result:= 'QueryStat';
    'SW': result:= 'EnumDeps';
    'RP': result:= 'Start';
    'WP': result:= 'Stop';
    'DT': result:= 'Pause';
    'LO': result:= 'Interrogate';
    'CR': result:= 'UserDefined';
    'GA': result:= 'GenericAll';
    'GX': result:= 'GenericExecute';
    'GW': result:= 'GenericWrite';
    'GR': result:= 'GenericRead';
    'SD': result:= 'Del';
    'RC': result:= 'RCtl';
    'WD': result:= 'WDac';
    'WO': result:= 'WOwn';
    else result:= permAbbr;
  end;
end;

// split service permissions into their two letter abbreviations
procedure TWinServices.SplitPermAbbreviaions(Str: string; ListOfStrings: TStrings);
begin
  ListOfStrings.Clear;
  while Length(Str) >= 2 do begin
    ListOfStrings.Add(leftstr((Str),2));
    Delete(Str, 1, 2);
  end;
end;

procedure TWinServices.GetServicePerms;
var
  i              : integer;
  daclIndex      : integer;     // track array of dacls
  permIndex      : integer;     // track permissions per dacl
  cmd            : TRunCMD;
  cmdOut         : AnsiString;
  tmpStr         : string;
  regex          : TRegExpr;
  list           : TStringList;
  permList       : TStringList;
  perm           : string;
  strSplit       : TMisc;
begin
  cmd:= TRunCMD.Create;
  regex:= TRegExpr.Create;
  list:= TStringList.Create;
  permList:= TStringList.Create;
  strSplit:= TMisc.Create;
  regex.Expression:= SVC_PERM_REGEX;
  for i:= Low(Services) to High(Services) do begin
    daclIndex:= 0;
    cmdOut:= cmd.GetOutput(SVC_QRY_PERMS, Services[i].Name, false);
    // lets work through all of the dacls for the service
    if regex.Exec(cmdOut) then
      repeat begin
        permIndex:= 0;
        tmpStr:= StringReplace(regex.Match[0], '(', '', []);
        tmpStr:= StringReplace(tmpStr, ')', '', []);
        strSplit.Split(';', tmpStr, list);
        SetLength(Services[i].dacl, daclIndex + 1);  // set new length for dynamic array
        // is this an allow or deny dacl?
        if list.Strings[0] = 'A' then
          Services[i].dacl[daclIndex].allow:= true
        else if list.Strings[0] = 'D' then
          Services[i].dacl[daclIndex].allow:= false;
        // user or group dacl applies to for the service
        Services[i].dacl[daclIndex].entry:= Users(list.Strings[5]);
        // split service permissions into their sets of two
        SplitPermAbbreviaions(list.Strings[2], permList);
        // find the long name for each 2 charecter permission abbreviation
        for perm in permList do begin
          SetLength(Services[i].dacl[daclIndex].perms, permIndex + 1);  // set new length for dynamic array
          Services[i].dacl[daclIndex].perms[permIndex]:= Perms(perm);
          permIndex:= permIndex + 1;
        end;
        daclIndex:= daclIndex + 1;
      end until not regex.ExecNext;
  end;
  strSplit.Free;
  regex.Free;
  permList.Free;
  list.Free;
  cmd.Free;
end;

// populate services array of records with all of the services' information
procedure TWinServices.GetServicesInfo;
var
  cmd            : TRunCMD;
  cmdOut         : AnsiString;
  outerRegex     : TRegExpr;
  innerRegex     : TRegExpr;
  i              : integer = 0;
  count          : integer;     // used to assign the innerRegex find to the correct field in the Service record
  outerMatch     : string;
  innerMatch     : string;
begin
  cmd:= TRunCMD.Create;
  outerRegex:= TRegExpr.Create;
  outerRegex.Expression:= SVC_LINE_REGEX;
  innerRegex:= TRegExpr.Create;
  innerRegex.Expression:= SVC_LINE_PART_REGEX;
  // setup output for the "wmic service get" command as csv to parse
  cmdOut:= cmd.GetOutput(SVC_QRY_CONF,
                        'get Name,PathName,Started,StartMode,StartName,Status /format:csv',
                        false);
  if outerRegex.Exec(cmdOut) then
    while outerRegex.ExecNext do begin       // skip first row as it is the header row
      SetLength(Services, i + 1);            // set new length for dynamic array
      count:= 1;
      outerMatch:= outerRegex.Match[0]+',';  // add a "," at the end of the string so that the regex matches on the last entry
      if innerRegex.Exec(outerMatch) then    // cannot use split function as it eats the quotation marks
        while innerRegex.ExecNext do begin   // skip first row as it is the computer name
          innerMatch:= StringReplace(innerRegex.Match[0], ',', '', []);
          case count of
            1: Services[i].Name:= innerMatch;
            2: Services[i].Path.PathName:= innerMatch;
            3: Services[i].Started:= innerMatch;
            4: Services[i].StartMode:= innerMatch;
            5: Services[i].StartName:= innerMatch;
            6: Services[i].Status:= innerMatch;
          end;
          // delete the current innerRegex find so it isn't used again and again and ...
          outerMatch:= StringReplace(outerMatch, innerRegex.Match[0], '', []);
          count:= count + 1;
        end;
      i:= i + 1;
    end;
  GetServicePerms;
  innerRegex.Free;
  outerRegex.Free;
  cmd.Free;
end;

end.

