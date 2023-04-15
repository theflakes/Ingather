UNIT WinFileSystem;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils, Dos, Misc, INIFiles, DOM, XMLRead, FileUtil, LazFileUtils;
TYPE
  TWinFileSystem = CLASS
     PUBLIC
       PROCEDURE GetPathList(pathList: TStrings);
       FUNCTION ReadINI(
                  iniFile: string;
                  section:string; value: string;
                  default: string
                ): AnsiString;
       FUNCTION CheckFileIsWriteable(path: string): Boolean;
       FUNCTION CheckDirectoryIsWriteable(path: string): Boolean;
       FUNCTION RemoveQuotes(CONST S: string; CONST QuoteChar: Char): string;
       FUNCTION ReadXML(xmlFile: string; node: string): AnsiString;
     PRIVATE
       FUNCTION GetPath: AnsiString;
  END;

IMPLEMENTATION
FUNCTION TWinFileSystem.RemoveQuotes(
                          CONST S: string;
                          CONST QuoteChar: Char
                        ): string;
VAR
  Len: Integer;
BEGIN
  Result := S;
  Len := Length(Result);
  IF (Len < 2) THEN Exit;                    //Quoted text must have at least 2 chars
  IF (Result[1] <> QuoteChar) THEN Exit;     //Text is NOT quoted
  IF (Result[Len] <> QuoteChar) THEN Exit;   //Text is NOT quoted
  System.Delete(Result, Len, 1);
  System.Delete(Result, 1, 1);
  Result := StringReplace(
              Result,
              QuoteChar+QuoteChar,
              QuoteChar,
              [rfReplaceAll]
            );
END;

FUNCTION TWinFileSystem.CheckFileIsWriteable(path: string): Boolean;
BEGIN
  path:= RemoveQuotes(path, '"');
  IF FileIsWritable(path) THEN
    result:= true
  ELSE
    result:= false;
END;

FUNCTION TWinFileSystem.CheckDirectoryIsWriteable(path: string): Boolean;
BEGIN
  path:= RemoveQuotes(path, '"');
  path:= ExtractFilePath(path);
  IF DirectoryIsWritable(path) THEN
    result:= true
  ELSE
    result:= false;
END;

FUNCTION TWinFileSystem.GetPath: AnsiString;
BEGIN
  result:= GetEnv('PATH');
END;

PROCEDURE TWinFileSystem.GetPathList(pathList: TStrings);
VAR
  path     : AnsiString;
  strSplit : TMisc;
BEGIN
  strSplit:= TMisc.Create;
  path:= GetPath;
  strSplit.Split(';', path, pathList);
  strSplit.Free;
END;

FUNCTION TWinFileSystem.ReadINI(
                          iniFile: string;
                          section:string;
                          value: string;
                          default: string
                        ): AnsiString;
VAR
 INI: TINIFile;
BEGIN
  INI:= TINIFile.Create(iniFile);
  result:= INI.ReadString(section, value, default);
  Ini.Free;
END;

FUNCTION TWinFileSystem.ReadXML(xmlFile: string; node: string): AnsiString;
VAR
  PassNode: TDOMNode;
  Doc: TXMLDocument;
  output: AnsiString = '';
BEGIN
  IF FileExists(xmlFile) THEN BEGIN
    ReadXMLFile(Doc, xmlFile);
    PassNode := Doc.DocumentElement.FindNode(node);
    IF PassNode.TextContent = '' THEN
      result:= concat(output, '[!!]' + PassNode.TextContent)
    ELSE
      result:= concat(output, '[**] '+xmlFile+' file exists but '+node+' NOT found');
    Doc.Free;
  END ELSE
    result:= concat(output, '[**] '+xmlFile+' file NOT found.');
END;

END.

