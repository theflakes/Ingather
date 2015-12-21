unit WinReg;
 {
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, registry;
type
  TWinReg = class
    public
      function ReadKey(HKEY: LongWord; regPath: string; key: string): LongInt;
      function ReadKey(HKEY: LongWord; regPath: string; key: string): string;
      function ReadKey(HKEY: LongWord; regPath: string; key: string): boolean;
      function ReadKey(HKEY: LongWord; regPath: string; key: string): double;
      function ReadKey(HKEY: LongWord; regPath: string; key: string): TDateTime;
      function ReadKey(HKEY: LongWord; regPath: string; key: string): TDate;
      function ReadKey(HKEY: LongWord; regPath: string; key: string): TTime;
      function ReadKey(HKEY: LongWord; regPath: string; key: string; bufSize: integer): LongInt;
    private
  end;

implementation
function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): LongInt;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadInteger(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): string;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadString(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): boolean;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadBool(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): double;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadFloat(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): TDateTime;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadDateTime(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): TDate;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadDate(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string): TTime;
var
  Registry: TRegistry;
begin
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadTime(key);
  finally
    Registry.Free;
  end;
end;

function TWinReg.ReadKey(HKEY: LongWord; regPath: string; key: string; bufSize: integer): LongInt;
var
  Registry: TRegistry;
  Buffer  : array of byte;
begin
  SetLength(Buffer, bufSize);
  Registry:= TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    // Navigate to proper "directory":
    Registry.RootKey:= HKEY;
    if Registry.OpenKeyReadOnly(regPath) then
      result:= Registry.ReadBinaryData(key, Buffer, bufSize);
  finally
    Registry.Free;
  end;
end;

end.

