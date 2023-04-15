UNIT RunAs;
{
 AUTHOR:  Brian Kellogg

 MIT licensed

 code from:
      http://stackoverflow.com/questions/16835673/handling-uac-administrative-token
}

{$mode objfpc}{$H+}

INTERFACE
USES
  Classes, SysUtils, Windows, ShellAPI;
TYPE
  TRunAs = CLASS
    PUBLIC
      FUNCTION IsUserAdmin: Boolean;
      FUNCTION RunAsAdmin(
                  hWnd: HWND;
                  filename: string;
                  Parameters: string
                ): Boolean;
    PRIVATE
  END;


IMPLEMENTATION
// external Windows FUNCTION FOR checking group membership
FUNCTION CheckTokenMembership(
            TokenHandle: THandle;
            SidToCheck: PSID;
            VAR IsMember: BOOL
          ): BOOL; stdcall; external advapi32;

// This FUNCTION tells us IF we're running with administrative permissions.
FUNCTION TRunAs.IsUserAdmin: Boolean;
CONST
  SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
VAR
    b                  : BOOL;
    AdministratorsGroup: PSID;
BEGIN
    {
        This FUNCTION returns true IF you are currently running with admin privelages.
        In Vista AND later, IF you are non-elevated, this FUNCTION will return false
        (you are NOT running with administrative privelages).
        If you *are* running elevated, THEN IsUserAdmin will return true,
        as you are running with admin privelages.
    }
    b := AllocateAndInitializeSid(
            SECURITY_NT_AUTHORITY,
            2, //2 sub-authorities
            SECURITY_BUILTIN_DOMAIN_RID,    //sub-authority 0
            DOMAIN_ALIAS_RID_ADMINS,        //sub-authority 1
            0, 0, 0, 0, 0, 0,               //sub-authorities 2-7 NOT passed
            AdministratorsGroup);
    IF (b) THEN
    BEGIN
        IF NOT CheckTokenMembership(0, AdministratorsGroup, b) THEN
            b := False;
        FreeSid(AdministratorsGroup);
    END;

    Result := b;
END;

FUNCTION TRunAs.RunAsAdmin(
            hWnd: HWND;
            filename: string;
            Parameters: string
          ): Boolean;
{
    See Step 3: Redesign FOR UAC Compatibility (UAC)
    http://msdn.microsoft.com/en-us/library/bb756922.aspx
}
VAR
    sei: TShellExecuteInfo;
BEGIN
    ZeroMemory(@sei, SizeOf(sei));
    sei.cbSize := SizeOf(TShellExecuteInfo);
    sei.Wnd := hwnd;
    sei.fMask := SEE_MASK_FLAG_DDEWAIT OR SEE_MASK_FLAG_NO_UI;
    sei.lpVerb := PChar('runas');
    sei.lpFile := PChar(Filename); // PAnsiChar;
    IF parameters <> '' THEN
        sei.lpParameters := PChar(parameters); // PAnsiChar;
    sei.nShow := SW_SHOWNORMAL; //Integer;

    Result := ShellExecuteExA(@sei);
END;

END.

