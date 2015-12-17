# Ingather

Windows vulnerability enumeration program.  Written in Free Pascal/Lazarus: http://www.lazarus-ide.org/index.php?page=downloads.

Presently it only lists services and their path to the console which it parses from the output of Windows built-in commands.  If directed, it will write all of the information it gather before parsing it to a file and/or to an IP on the specified port.

Usage: Ingather.exe -i 1.1.1.1 -p 4444 -o output.txt
-h --help  : print this help message
-i --ip    : destination IP address
-p --port  : destination port
-o --out   : write to file
