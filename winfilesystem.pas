unit WinFileSystem;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Dos, Misc, INIFiles;
type
  TWinFileSystem = class
     public
       procedure GetPathList(pathList: TStrings);
       function ReadINI(iniFile: string; section:string; value: string; default: string): AnsiString;
     private
       function GetPath: AnsiString;
  end;

implementation
function TWinFileSystem.GetPath: AnsiString;
begin
  result:= GetEnv('PATH');
end;

procedure TWinFileSystem.GetPathList(pathList: TStrings);
var
  path     : AnsiString;
  strSplit : TMisc;
begin
  strSplit:= TMisc.Create;
  path:= GetPath;
  strSplit.Split(';', path, pathList);
  strSplit.Free;
end;

function TWinFileSystem.ReadINI(iniFile: string; section:string; value: string; default: string): AnsiString;
Var
 INI: TINIFile;
begin
  INI:= TINIFile.Create(iniFile);
  result:= INI.ReadString(section, value, default);
  Ini.Free;
end;

end.

