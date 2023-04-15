UNIT WinUsers;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils;
TYPE
  TWinUsers = CLASS
    PUBLIC
    PRIVATE
  END;

TYPE
  Tgroup = RECORD
    Name: STRING;
    Domain: STRING;
    SID: STRING;
  END;

  Tuser = RECORD
    Name: STRING;
    Domain: STRING;
    SID: STRING;
    Groups: Tgroup;
  END;

  TWinUser = CLASS
    PUBLIC
    PRIVATE
  END;

IMPLEMENTATION

END.

