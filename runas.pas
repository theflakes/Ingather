unit RunAs;
{
 AUTHOR:  Brian Kellogg

 GPL v.2 licensed

 code from:
 http://stackoverflow.com/questions/16835673/handling-uac-administrative-token
}

{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils, Windows, ShellAPI;
type
  TRunAs = class
    public
      function IsUserAdmin: Boolean;
      function RunAsAdmin(hWnd: HWND; filename: string; Parameters: string): Boolean;
    private
  end;


implementation
// external Windows function for checking group membership
function CheckTokenMembership(TokenHandle: THandle; SidToCheck: PSID; var IsMember: BOOL): BOOL; stdcall; external advapi32;

// This function tells us if we're running with administrative permissions.
function TRunAs.IsUserAdmin: Boolean;
const
  SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
var
    b                  : BOOL;
    AdministratorsGroup: PSID;
begin
    {
        This function returns true if you are currently running with admin privelages.
        In Vista and later, if you are non-elevated, this function will return false (you are not running with administrative privelages).
        If you *are* running elevated, then IsUserAdmin will return true, as you are running with admin privelages.
    }
    b := AllocateAndInitializeSid(
            SECURITY_NT_AUTHORITY,
            2, //2 sub-authorities
            SECURITY_BUILTIN_DOMAIN_RID,    //sub-authority 0
            DOMAIN_ALIAS_RID_ADMINS,        //sub-authority 1
            0, 0, 0, 0, 0, 0,               //sub-authorities 2-7 not passed
            AdministratorsGroup);
    if (b) then
    begin
        if not CheckTokenMembership(0, AdministratorsGroup, b) then
            b := False;
        FreeSid(AdministratorsGroup);
    end;

    Result := b;
end;

function TRunAs.RunAsAdmin(hWnd: HWND; filename: string; Parameters: string): Boolean;
{
    See Step 3: Redesign for UAC Compatibility (UAC)
    http://msdn.microsoft.com/en-us/library/bb756922.aspx
}
var
    sei: TShellExecuteInfo;
begin
    ZeroMemory(@sei, SizeOf(sei));
    sei.cbSize := SizeOf(TShellExecuteInfo);
    sei.Wnd := hwnd;
    sei.fMask := SEE_MASK_FLAG_DDEWAIT or SEE_MASK_FLAG_NO_UI;
    sei.lpVerb := PChar('runas');
    sei.lpFile := PChar(Filename); // PAnsiChar;
    if parameters <> '' then
        sei.lpParameters := PChar(parameters); // PAnsiChar;
    sei.nShow := SW_SHOWNORMAL; //Integer;

    Result := ShellExecuteExA(@sei);
end;

end.

