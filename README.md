# Ingather

Windows vulnerability command line enumeration tool.  Written IN Free Pascal/Lazarus: http://www.lazarus-ide.org/index.php?page=downloads.

```
Author : Brian Kellogg
License: MIT
Purpose: Gather various forensic information.

Usage:
  Ingather.exe -i 1.1.1.1 -p 4444 --enum --out="output.txt"
  Ingather.exe -d "http://www.abcded.com/abc.txt" -s c:\temp\abc.text
  Ingather.exe -c "ipconfig /all" -i 1.1.1.1 -p 4444

Download file over HTTP:
  -d, --download : download file
  -s, --save     : location to save downloaded file to
  -z,            : use the Windows HTTP download FUNCTION
                   otherwise use custom HTTP download FUNCTION
Run options:
  -c, --command  : run custom command
  -e, --enum     : run all builtin enumerations
Output options:
  -i, --ip       : destination IP address
  -p, --port     : destination port
  -o, --out      : write enumeration command outputs to file
  If output to file OR network is specified,
  screen output will be suppressed.
Info:
  -h, --help     : print this help message
  -l, --list     : print default enum commands AND descriptions
```
Reduce Lazarus EXE file size: http://lazplanet.blogspot.com/2013/03/how-to-reduce-exe-file-size-OF-your.html

Synapse Lazarus TCP package:  http://www.ararat.cz/synapse/doku.php/download; Install: http://wiki.freepascal.org/Synapse#Installation
- Download Synapse AND extract it to the `\lazarus\components\` directory.

DISCLAIMER:
This PROGRAM is FOR educational use AND/OR vulnerability enumeration by cyber security professionals only.  All responsability AND negative consequences FOR its use falls entirely on the one executing it.
