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
       PROCEDURE Split(Delimiter: Char; Str: STRING; ListOfStrings: TStrings);
     PRIVATE

   END;

IMPLEMENTATION
// split STRING by delimiter
PROCEDURE TMisc.Split(Delimiter: Char; Str: STRING; ListOfStrings: TStrings);
BEGIN
   ListOfStrings.Clear;
   ListOfStrings.Delimiter       := Delimiter;
   ListOfStrings.StrictDelimiter := True;
   ListOfStrings.DelimitedText   := Str;
END;

END.

