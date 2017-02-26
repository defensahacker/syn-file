#
# Makefile
#
# Exfiltrate data from a compromised target using covert channels.
#
# (c) spinfoo <spinfoo.vuln@gmail.com>

CFLAGS=-Wall

all: syn-file syn-daemon

syn-file: syn-file.c
	gcc $< -o $@ -lnet $(CFLAGS)
	@strip $@
	@du -h $@
 
syn-daemon: syn-daemon.c
	gcc $< -o $@ -lpcap $(CFLAGS)
	@strip $@
	@du -h $@

clean:
	rm -f syn-file syn-daemon
