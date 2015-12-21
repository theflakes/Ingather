unit WinUsers;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

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

