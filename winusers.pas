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
    Name: string;
    Domain: string;
    SID: string;
  END;

  Tuser = RECORD
    Name: string;
    Domain: string;
    SID: string;
    Groups: Tgroup;
  END;

  TWinUser = CLASS
    PUBLIC
    PRIVATE
  END;

IMPLEMENTATION

END.

