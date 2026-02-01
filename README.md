# Ingather

Windows vulnerability command line enumeration tool.  Written in Free Pascal/Lazarus: http://www.lazarus-ide.org/index.php?page=downloads.

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
  -z,            : use the Windows HTTP download function
                   otherwise use custom HTTP download function
Run options:
  -c, --command  : run custom command
  -e, --enum     : run all builtin enumerations
Output options:
  -i, --ip       : destination IP address
  -p, --port     : destination port
  -o, --out      : write enumeration command outputs to file
  If output to file or network is specified,
  screen output will be suppressed.
Info:
  -h, --help     : print this help message
  -l, --list     : print default enum commands and descriptions
```
Reduce Lazarus EXE file size: http://lazplanet.blogspot.com/2013/03/how-to-reduce-exe-file-size-OF-your.html

Synapse Lazarus TCP package:  http://www.ararat.cz/synapse/doku.php/download; Install: http://wiki.freepascal.org/Synapse#Installation
- Download Synapse and extract it to the `\lazarus\components\` directory.

### Compile for Windows on Linux
```
# See: https://wiki.freepascal.org/Cross_compiling_for_Windows_under_Linux
sudo -i 
export FPCVER="3.2.2"
cd "/usr/share/fpcsrc/${FPCVER}"
make clean all OS_TARGET=win64 CPU_TARGET=x86_64
make clean all OS_TARGET=win32 CPU_TARGET=i386
make crossinstall OS_TARGET=win64 CPU_TARGET=x86_64 INSTALL_PREFIX=/usr
make crossinstall OS_TARGET=win32 CPU_TARGET=i386 INSTALL_PREFIX=/usr
ln -sf "/usr/lib/fpc/${FPCVER}/ppcrossx64" /usr/bin/ppcrossx64
ln -sf "/usr/lib/fpc/${FPCVER}/ppcross386" /usr/bin/ppcross386

# Check config file for the existence of this search path
# Add it if not present
grep 'Fu' /etc/fpc.cfg
# searchpath for units and other system dependent things
-Fu/usr/lib/fpc/${fpcversion}/units/${fpctarget}/*
```

DISCLAIMER:
This program is for educational use and/or vulnerability enumeration by cyber security professionals only.  All responsability and negative consequences for its use falls entirely on the one executing it.
