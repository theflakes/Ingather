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
       function CheckFileIsWriteable(path: string): Boolean;
       function CheckDirectoryIsWriteable(path: string): Boolean;
       function RemoveQuotes(const S: string; const QuoteChar: Char): string;
       procedure ReadXML(xmlFile: string; node: string);
     private
       function GetPath: AnsiString;
  end;

implementation
function TWinFileSystem.RemoveQuotes(const S: string; const QuoteChar: Char): string;
var
  Len: Integer;
begin
  Result := S;
  Len := Length(Result);
  if (Len < 2) then Exit;                    //Quoted text must have at least 2 chars
  if (Result[1] <> QuoteChar) then Exit;     //Text is not quoted
  if (Result[Len] <> QuoteChar) then Exit;   //Text is not quoted
  System.Delete(Result, Len, 1);
  System.Delete(Result, 1, 1);
  Result := StringReplace(Result, QuoteChar+QuoteChar, QuoteChar, [rfReplaceAll]);
end;

function TWinFileSystem.CheckFileIsWriteable(path: string): Boolean;
begin
  path:= RemoveQuotes(path, '"');
  if FileIsWritable(path) then
    result:= true
  else
    result:= false;
end;

function TWinFileSystem.CheckDirectoryIsWriteable(path: string): Boolean;
begin
  path:= RemoveQuotes(path, '"');
  if DirectoryIsWritable(path) then
    result:= true
  else
    result:= false;
end;

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

