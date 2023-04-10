unit WinUsers;
{
 AUTHOR:  Brian Kellogg

 MIT licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;
type
  TWinUsers = class
    public
    private
  end;

type
  Tgroup = record
    Name: string;
    Domain: string;
    SID: string;
  end;

  Tuser = record
    Name: string;
    Domain: string;
    SID: string;
    Groups: Tgroup;
  end;

  TWinUser = class
    public
    private
  end;

implementation

end.

