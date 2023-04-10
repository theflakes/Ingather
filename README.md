# Ingather

Windows vulnerability command line enumeration tool.  Written in Free Pascal/Lazarus: http://www.lazarus-ide.org/index.php?page=downloads.

```
Usage: Ingather.exe -i 1.1.1.1 -p 4444 -o output.txt
       Ingather.exe -d http://www.abcded.com/abc.txt -s c:\temp\abc.text
       Ingather.exe -c "ipconfig /all" -i 1.1.1.1 -p 4444

Download file over HTTP:
       -d, --download    : download file
       -s, --save        : location to save downloaded file to
       -z,               : use the Windows HTTP download function
                           otherwise use custom HTTP download function
Run options:
       -c, --command     : run command and send output across network
       -e, --enum        : run all builtin enumerations
Output options:
       -i, --ip          : destination IP address
       -p, --port        : destination port
       -o, --out         : write enumeration command outputs to file
NOTE: If output to file or network is specified,
      screen output will be suppressed.
Info:
       -h, --help        : print this help message
       -l, --list        : print enumeration commands use by Ingather
```

Reduce Lazarus EXE file size: http://lazplanet.blogspot.com/2013/03/how-to-reduce-exe-file-size-of-your.html

Synapse Lazarus TCP package:  http://www.ararat.cz/synapse/doku.php/download; Install: http://wiki.freepascal.org/Synapse#Installation
- Download Synapse and extract it to the `\lazarus\components\` directory.

DISCLAIMER:
This program is for educational use and/or vulnerability enumeration by cyber security professionals only.  All responsability and negative consequences for its use falls entirely on the one executing it.
