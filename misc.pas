UNIT misc;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils;
TYPE
  TMisc = CLASS
     PUBLIC
       PROCEDURE Split(Delimiter: Char; Str: string; ListOfStrings: TStrings);
     PRIVATE

   END;

IMPLEMENTATION
// split string by delimiter
PROCEDURE TMisc.Split(Delimiter: Char; Str: string; ListOfStrings: TStrings);
BEGIN
   ListOfStrings.Clear;
   ListOfStrings.Delimiter       := Delimiter;
   ListOfStrings.StrictDelimiter := True;
   ListOfStrings.DelimitedText   := Str;
END;

END.

