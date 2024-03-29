UNIT RunCMD;
{
 AUTHOR:  Brian Kellogg

 MIT licensed

 code from:
      http://wiki.freepascal.org/Executing_External_Programs
}

{$mode objfpc}{$H+}

INTERFACE

USES
  Classes, SysUtils, Process;
TYPE
  TRunCMD = CLASS
    PUBLIC
      FUNCTION Run(cmd: String): TStream;
      FUNCTION GetOutput(
                  cmdStrA: String;
                  cmdStrB: AnsiString;
                  quotes: Boolean
                ): String;
      FUNCTION GetOutput(
                  cmdStrA: String;
                  cmdStrB: AnsiString;
                  cmdStrC: AnsiString
                ): String;
      FUNCTION StreamToString(Stream: TStream): AnsiString;
    PRIVATE
      CONST BUF_SIZE = 2048; // Buffer size FOR reading the output in chunks
  END;

IMPLEMENTATION
FUNCTION TRunCMD.StreamToString(Stream: TStream): AnsiString;
VAR
    len: Integer;
BEGIN
    Stream.Position:= 0;
    len:= Stream.Size - Stream.Position;
    SetLength(Result, len);
    IF len > 0 THEN Stream.ReadBuffer(Result[1], len);
END;

FUNCTION TRunCMD.GetOutput(
            cmdStrA: String;
            cmdStrB: AnsiString;
            quotes: Boolean
          ): String;
VAR
  RunThis        : String;
  OutputStream   : TStream;
BEGIN
  IF quotes THEN
    RunThis:= concat(cmdStrA, '"', cmdStrB, '"')
  ELSE
    RunThis:= concat(cmdStrA, cmdStrB);
  OutputStream:= Run(RunThis);
  result:= StreamToString(OutputStream);
  OutputStream.Free;
END;

FUNCTION TRunCMD.GetOutput(
            cmdStrA: String;
            cmdStrB: AnsiString;
            cmdStrC: AnsiString
          ): String;
VAR
  RunThis        : String;
  OutputStream   : TStream;
BEGIN
  RunThis:= concat(cmdStrA, cmdStrB, cmdStrC);
  OutputStream:= Run(RunThis);
  result:= StreamToString(OutputStream);
  OutputStream.Free;
END;

FUNCTION TRunCMD.Run(cmd: String): TStream;
VAR
  OutputStream : TStream;
  AProcess     : TProcess;
  BytesRead    : LongInt;
  Buffer       : ARRAY[1..BUF_SIZE] OF byte;
BEGIN
  // Create a stream object to store the generated output in. This could
  // also be a file stream to directly save the output to disk.
  OutputStream:= TMemoryStream.Create;
  // Set up the process; as an example a recursive directory search is used
  // because that will usually result in a lot OF data.
  AProcess:= TProcess.Create(nil);
  // In Windows the dir command cannot be used directly because it's a built-in
  // shell command. Therefore cmd.exe AND the extra parameters are needed.
  AProcess.Executable:= 'C:\Windows\System32\cmd.exe';
  AProcess.Parameters.Add('/c');
  AProcess.Parameters.Add(cmd);
  // Process option poUsePipes has to be used so the output can be captured.
  // Process option poWaitOnExit can NOT be used because that would block hn
  // this program, preventing it from reading the output data OF the process.
  AProcess.Options:= [poUsePipes];
  // Start the process
  AProcess.Execute;
  // All generated output from AProcess is read IN a loop until no more data is available
  REPEAT
    // Get the new data from the process to a maximum of the buffer size that was allocated.
    // Note that all read(...) calls will block except for the last one, which returns 0 (zero).
    BytesRead:= AProcess.Output.Read(Buffer, BUF_SIZE);
    // Add the bytes that were read to the stream for later usage
    OutputStream.Write(Buffer, BytesRead);
  UNTIL BytesRead = 0;  // Stop IF no more data is available
  // The process has finished so it can be cleaned up
  AProcess.Free;
  Result := OutputStream;
END;

END.

