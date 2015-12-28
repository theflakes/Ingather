unit misc;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;
type
  TMisc = class
     public
       procedure Split(Delimiter: Char; Str: string; ListOfStrings: TStrings);
     private

   end;

implementation
// split string by delimiter
procedure TMisc.Split(Delimiter: Char; Str: string; ListOfStrings: TStrings);
begin
   ListOfStrings.Clear;
   ListOfStrings.Delimiter       := Delimiter;
   ListOfStrings.StrictDelimiter := True;
   ListOfStrings.DelimitedText   := Str;
end;

end.

