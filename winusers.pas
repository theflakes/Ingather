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
    Name: String;
    Domain: String;
    SID: String;
  END;

  Tuser = RECORD
    Name: String;
    Domain: String;
    SID: String;
    Groups: Tgroup;
  END;

  TWinUser = CLASS
    PUBLIC
    PRIVATE
  END;

IMPLEMENTATION

END.

