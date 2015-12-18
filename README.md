# Ingather

Windows vulnerability command line enumeration tool.  Written in Free Pascal/Lazarus: http://www.lazarus-ide.org/index.php?page=downloads.

Presently it only lists services and their path to the console which it parses from the output of Windows' built-in commands.  If directed, it will write all of the information it gathers from the Windows' command output it captures to a file and/or to an IP on the specified port.

```
Usage: Ingather.exe --enum -i 1.1.1.1 -p 4444 -o output.txt
       Ingather.exe --download http://www.abcded.com/abc.txt --save c:\temp\abc.text

Download file over HTTP:
       -d --download    : download file
       -s --save        : location to save downloaded file to
       -z               : use the Windows HTTP download function
                          otherwise use custom HTTP download function
Enumerate vulnerabilities:
       -e --enum        : enumerate host vulnerabilities
Output options:
       -h --help        : print this help message
       -i --ip          : destination IP address
       -p --port        : destination port
       -o --out         : write enumeration command outputs to file
```

Reduce Lazarus EXE file size: http://lazplanet.blogspot.com/2013/03/how-to-reduce-exe-file-size-of-your.html

Synapse Lazarus TCP package:  http://www.ararat.cz/synapse/doku.php/download; Install: http://wiki.freepascal.org/Synapse#Installation
