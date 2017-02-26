#
#
# (c) spinfoo

all:
	gcc syn-file.c -o syn-file -lnet -Wall
	@strip syn-file
	@du -h syn-file
	gcc syn-daemon.c -o syn-daemon -lpcap -Wall
