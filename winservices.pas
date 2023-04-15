UNIT WinServices;
{
 AUTHOR:  Brian Kellogg

 MIT licensed

 service permission information: https://support.microsoft.com/en-us/kb/914392

 Best practices:
  Limit service DACLs to only those users who need a particular access TYPE.
  Be especially cautious with the following rights.
  If these rights are granted to a user OR to a group that has low rights,
  the rights can be used to elevate to LocalSystem on the computer:
  ChangeConf (DC)
  WDac (WD)
  WOwn (WO)
  GenericWrite (GW)
  GenericALL (GA)
}

{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils, regexpr, RunCMD, Misc;
TYPE
  TdaclVulns = RECORD
    config: boolean;
    escalate: boolean;
  END;

  Tdacl = RECORD
    allow: boolean;
    entry: string;
    perms: ARRAY OF string;
    vulns: TdaclVulns;
  END;

  TPathName = RECORD
    PathName: string;
    Unquoted: boolean;
    Writeable: boolean;
  END;

  TService = RECORD
    Name: string;
    Path: TPathName;
    Started: string;
    StartMode: string;
    StartName: string;
    Status: string;
    dacl: ARRAY OF Tdacl;
  END;

  TWinServices = CLASS
    PUBLIC
      Services: ARRAY OF TService;
      PROCEDURE GetServicesInfo;
    PRIVATE
      FUNCTION Users(userAbbr: string): string;
      FUNCTION Perms(permAbbr: string): string;
      PROCEDURE GetServicePerms;
      PROCEDURE SplitPermAbbreviaions(Str: string; ListOfStrings: TStrings);
      CONST SVC_QRY_CONF             = 'wmic service ';
      CONST SVC_QRY_PERMS            = 'sc sdshow ';
      CONST SVC_PERM_REGEX           = '(?-sg)\((A|D)\S+\)';
      CONST SVC_LINE_REGEX           = '(?-s).+,.+,.+,.+,.+,.+,.+';
      CONST SVC_LINE_PART_REGEX      = '(?-sg).+,';
  END;

// convert user/group abbreviations to user/group names
IMPLEMENTATION
FUNCTION TWinServices.Users(userAbbr: string): string;
BEGIN
  CASE userAbbr OF
    'DA': result:= 'Domain Administrators';
    'DG': result:= 'Domain Guests';
    'DU': result:= 'Domain Users';
    'ED': result:= 'Enterprise Domain Controllers';
    'DD': result:= 'Domain Controllers';
    'DC': result:= 'Domain Computers';
    'BA': result:= 'Built-IN (Local ) Administrators';
    'BG': result:= 'Built-IN (Local ) Guests';
    'BU': result:= 'Built-IN (Local ) Users';
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
    'LS': result:= 'Local Service Account (FOR Services)';
    'NS': result:= 'Network Service Account (FOR Services)';
    'RD': result:= 'Remote Desktop Users (FOR Terminal Services)';
    'NO': result:= 'Network Configuration Operators';
    'MU': result:= 'Performance Monitor Users';
    'LU': result:= 'Performance Log Users';
    'IS': result:= 'Anonymous Internet Users';
    'CY': result:= 'Crypto Operators';
    'OW': result:= 'Owner Rights SID';
    'RM': result:= 'RMS Service';
    ELSE result:= userAbbr;
  END;
END;

// convert service permissions abbreviations to full names
FUNCTION TWinServices.Perms(permAbbr: string): string;
BEGIN
  CASE permAbbr OF
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
    ELSE result:= permAbbr;
  END;
END;

// split service permissions into their two letter abbreviations
PROCEDURE TWinServices.SplitPermAbbreviaions(Str: string; ListOfStrings: TStrings);
BEGIN
  ListOfStrings.Clear;
  while Length(Str) >= 2 DO BEGIN
    ListOfStrings.Add(leftstr((Str),2));
    Delete(Str, 1, 2);
  END;
END;

PROCEDURE TWinServices.GetServicePerms;
VAR
  i              : integer;
  daclIndex      : integer;     // track ARRAY OF dacls
  permIndex      : integer;     // track permissions per dacl
  cmd            : TRunCMD;
  cmdOut         : AnsiString;
  tmpStr         : string;
  regex          : TRegExpr;
  list           : TStringList;
  permList       : TStringList;
  perm           : string;
  strSplit       : TMisc;
BEGIN
  cmd:= TRunCMD.Create;
  regex:= TRegExpr.Create;
  list:= TStringList.Create;
  permList:= TStringList.Create;
  strSplit:= TMisc.Create;
  regex.Expression:= SVC_PERM_REGEX;
  FOR i:= Low(Services) to High(Services) DO BEGIN
    daclIndex:= 0;
    cmdOut:= cmd.GetOutput(SVC_QRY_PERMS, Services[i].Name, false);
    // lets work through all OF the dacls FOR the service
    IF regex.Exec(cmdOut) THEN
      REPEAT BEGIN
        permIndex:= 0;
        tmpStr:= StringReplace(regex.Match[0], '(', '', []);
        tmpStr:= StringReplace(tmpStr, ')', '', []);
        strSplit.Split(';', tmpStr, list);
        SetLength(Services[i].dacl, daclIndex + 1);  // set new length FOR dynamic ARRAY
        // is this an allow OR deny dacl?
        IF list.Strings[0] = 'A' THEN
          Services[i].dacl[daclIndex].allow:= true
        ELSE IF list.Strings[0] = 'D' THEN
          Services[i].dacl[daclIndex].allow:= false;
        // user OR group dacl applies to FOR the service
        Services[i].dacl[daclIndex].entry:= Users(list.Strings[5]);
        // split service permissions into their sets OF two
        SplitPermAbbreviaions(list.Strings[2], permList);
        // find the long name FOR each 2 charecter permission abbreviation
        FOR perm IN permList DO BEGIN
          SetLength(Services[i].dacl[daclIndex].perms, permIndex + 1);  // set new length FOR dynamic ARRAY
          Services[i].dacl[daclIndex].perms[permIndex]:= Perms(perm);
          permIndex:= permIndex + 1;
        END;
        daclIndex:= daclIndex + 1;
      END UNTIL NOT regex.ExecNext;
  END;
  strSplit.Free;
  regex.Free;
  permList.Free;
  list.Free;
  cmd.Free;
END;

// populate services ARRAY OF records with all OF the services' information
PROCEDURE TWinServices.GetServicesInfo;
VAR
  cmd            : TRunCMD;
  cmdOut         : AnsiString;
  outerRegex     : TRegExpr;
  innerRegex     : TRegExpr;
  i              : integer = 0;
  count          : integer;     // used to assign the innerRegex find to the correct field IN the Service RECORD
  outerMatch     : string;
  innerMatch     : string;
BEGIN
  cmd:= TRunCMD.Create;
  outerRegex:= TRegExpr.Create;
  outerRegex.Expression:= SVC_LINE_REGEX;
  innerRegex:= TRegExpr.Create;
  innerRegex.Expression:= SVC_LINE_PART_REGEX;
  // setup output FOR the "wmic service get" command as csv to parse
  cmdOut:= cmd.GetOutput(SVC_QRY_CONF,
                        'get Name,PathName,Started,StartMode,StartName,Status /format:csv',
                        false);
  IF outerRegex.Exec(cmdOut) THEN
    while outerRegex.ExecNext DO BEGIN       // skip first row as it is the header row
      SetLength(Services, i + 1);            // set new length FOR dynamic ARRAY
      count:= 1;
      outerMatch:= outerRegex.Match[0]+',';  // add a "," at the END OF the string so that the regex matches on the last entry
      IF innerRegex.Exec(outerMatch) THEN    // cannot use split FUNCTION as it eats the quotation marks
        while innerRegex.ExecNext DO BEGIN   // skip first row as it is the computer name
          innerMatch:= StringReplace(innerRegex.Match[0], ',', '', []);
          CASE count OF
            1: Services[i].Name:= innerMatch;
            2: Services[i].Path.PathName:= innerMatch;
            3: Services[i].Started:= innerMatch;
            4: Services[i].StartMode:= innerMatch;
            5: Services[i].StartName:= innerMatch;
            6: Services[i].Status:= innerMatch;
          END;
          // delete the current innerRegex find so it isn't used again AND again AND ...
          outerMatch:= StringReplace(outerMatch, innerRegex.Match[0], '', []);
          count:= count + 1;
        END;
      i:= i + 1;
    END;
  GetServicePerms;
  innerRegex.Free;
  outerRegex.Free;
  cmd.Free;
END;

END.

