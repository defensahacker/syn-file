#
# Makefile
#
# Exfiltrate data from a compromised target using covert channels.
#
# (c) spinfoo <spinfoo.vuln@gmail.com>

all: syn-file.c syn-daemon.c
	gcc syn-file.c -o syn-file -lnet -Wall
	@strip syn-file
	@du -h syn-file
	gcc syn-daemon.c -o syn-daemon -lpcap -Wall
	@strip syn-daemon
	@du -h syn-daemon

clean:
	rm -f syn-file syn-daemon
