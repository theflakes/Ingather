unit WinFileSystem;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Dos, Misc, INIFiles, DOM, XMLRead, FileUtil;
type
  TWinFileSystem = class
     public
       procedure GetPathList(pathList: TStrings);
       function ReadINI(iniFile: string; section:string; value: string; default: string): AnsiString;
       procedure ReadXML(xmlFile: string; node: string);
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

procedure TWinFileSystem.ReadXML(xmlFile: string; node: string);
var
  PassNode: TDOMNode;
  Doc: TXMLDocument;
begin
  if FileExists(xmlFile) then begin
    ReadXMLFile(Doc, xmlFile);
    PassNode := Doc.DocumentElement.FindNode(node);
    if PassNode.TextContent = '' then
      writeln(PassNode.TextContent)
    else
      writeln(' \_> '+xmlFile+' file exists but '+node+' not found');
    Doc.Free;
  end else
    writeln(' \_> '+xmlFile+' file not found.');
end;

end.

