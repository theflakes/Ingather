unit WinDevice;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Dos, Misc;
type
  TWinDevice = class
     public
       procedure GetPathList(pathList: TStrings);
     private
       function GetPath: AnsiString;
  end;

implementation
function TWinDevice.GetPath: AnsiString;
begin
  result:= GetEnv('PATH');
end;

procedure TWinDevice.GetPathList(pathList: TStrings);
var
  path     : AnsiString;
  strSplit : TMisc;
begin
  strSplit:= TMisc.Create;
  path:= GetPath;
  strSplit.Split(';', path, pathList);
  strSplit.Free;
end;

end.

