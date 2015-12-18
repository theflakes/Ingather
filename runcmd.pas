unit RunCMD;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Process;
  type TRunCMD = class
    public
      function Run(cmd: string): TStream;
    private
      const BUF_SIZE = 2048; // Buffer size for reading the output in chunks
  end;

implementation

function TRunCMD.Run(cmd: string): TStream;
var
  OutputStream : TStream;
  AProcess     : TProcess;
  BytesRead    : Longint;
  Buffer       : array[1..BUF_SIZE] of byte;
begin
  // Create a stream object to store the generated output in. This could
  // also be a file stream to directly save the output to disk.
  OutputStream:= TMemoryStream.Create;
  // Set up the process; as an example a recursive directory search is used
  // because that will usually result in a lot of data.
  AProcess:= TProcess.Create(nil);
  // In Windows the dir command cannot be used directly because it's a build-in
  // shell command. Therefore cmd.exe and the extra parameters are needed.
  AProcess.Executable:= 'c:\windows\system32\cmd.exe';
  AProcess.Parameters.Add('/c');
  AProcess.Parameters.Add(cmd);
  // Process option poUsePipes has to be used so the output can be captured.
  // Process option poWaitOnExit can not be used because that would block hn
  // this program, preventing it from reading the output data of the process.
  AProcess.Options:= [poUsePipes];
  // Start the process
  AProcess.Execute;
  // All generated output from AProcess is read in a loop until no more data is available
  repeat
    // Get the new data from the process to a maximum of the buffer size that was allocated.
    // Note that all read(...) calls will block except for the last one, which returns 0 (zero).
    BytesRead:= AProcess.Output.Read(Buffer, BUF_SIZE);
    // Add the bytes that were read to the stream for later usage
    OutputStream.Write(Buffer, BytesRead);
  until BytesRead = 0;  // Stop if no more data is available
  // The process has finished so it can be cleaned up
  AProcess.Free;
  Result := OutputStream;
end;



end.

