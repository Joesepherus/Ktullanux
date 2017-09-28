/* Demonstration program of reading packet trace files recorded by pcap
* (used by tshark and tcpdump) and dumping out some corresponding information
* in a human-readable form.
*
* Note, this program is limited to processing trace files that contains
* UDP packets.  It prints the timestamp, source port, destination port,
* and length of each such packet.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"


/* We've included the UDP header struct for your ease of customization.
* For your protocol, you might want to look at netinet/tcp.h for hints
* on how to deal with single bits or fields that are smaller than a byte
* in length.
*
* Per RFC 768, September, 1981.
*/
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};


/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/* dump_UDP_packet()
*
* This routine parses a packet, expecting Ethernet, IP, and UDP headers.
* It extracts the UDP source and destination port numbers along with the UDP
* packet length by casting structs over a pointer that we move through
* the packet.  We can do this sort of casting safely because libpcap
* guarantees that the pointer will be aligned.
*
* The "ts" argument is the timestamp associated with the packet.
*
* Note that "capture_len" is the length of the packet *as captured by the
* tracing program*, and thus might be less than the full length of the
* packet.  However, the packet pointer only holds that much data, so
* we have to be careful not to read beyond it.
*/

void hexDump(void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;


	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		if (i % 8 == 0) {
			printf(" ");
		}


		// Now the hex code for the specific character.
			printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}


// ================================================================================================================================================================
#define GET_SIZE(p) ((sizeof(p)/sizeof(p[0]))

typedef struct icmp {
	int icmp_type[2];
} ICMP;

typedef struct tcp {
	int source_port[2];
	int dest_port[2];
} TCP;

typedef struct ip {
	int source_ip[4];
	int dest_ip[4];
	int protocol_ip;
	char ip_type[2];
	struct tcp next;
	//struct arp arp;
	struct icmp icmp;
} IP;

typedef struct ether {
	unsigned short id;
	unsigned short frame_length_pcap;
	unsigned short frame_length_cable;
	int source_MA[6];
	int dest_MA[6];
	char ether_type[4];
	struct ip next;
	int hexDump[250];
} ETHER;

typedef struct arp {
	int operation[4];
	int arp_req_ip[8];
	int arp_reply_ip[8];
} ARP;

void printHexa(int *ptr, int size) {
	for (int i = 0; i < size; i++) {
		if (ptr[i] == '9999') return;
		printf("%02x ", ptr[i]);
	}
	putchar('\n');
}

void printEther(struct ether ethernet) {
	printf("id=%d\nlength=%d\nlength2=%d\n", ethernet.id, ethernet.frame_length_pcap, ethernet.frame_length_cable);
	// TO DO vypis typu ramca(ethernet or llc)
	printHexa(ethernet.source_MA, GET_SIZE(ethernet.source_MA)));
	printHexa(ethernet.dest_MA, GET_SIZE(ethernet.dest_MA)));
	printf("%s\n", ethernet.ether_type);

	if (strcmp(ethernet.ether_type, "IP") == 0) {
		printHexa(ethernet.next.dest_ip, GET_SIZE(ethernet.next.dest_ip)));
		printHexa(ethernet.next.source_ip, GET_SIZE(ethernet.next.source_ip)));
	}

	printf("%s\n", ethernet.next.ip_type);

	if (strcmp(ethernet.next.ip_type, "TCP") == 0) {
		printHexa(ethernet.next.next.dest_port, GET_SIZE(ethernet.next.next.dest_port)));
		printHexa(ethernet.next.next.source_port, GET_SIZE(ethernet.next.next.source_port)));
	}

	if (strcmp(ethernet.next.ip_type, "ICMP") == 0) {
		printHexa(ethernet.next.icmp.icmp_type, GET_SIZE(ethernet.next.icmp.icmp_type)));
	}

	// TO DO
	if (strcmp(ethernet.next.ip_type, "ARP") == 0) {

	}
}

void printAllEthers(struct ether *all, int size) {
	int i;
	for (i = 0; i < size; i++) {
		printEther(all[i]);
	}
}

struct ether ether_dump(void *addr, int len, struct ether ethernet) {
	int i;
	unsigned char *pc = (unsigned char*)addr;

	if (len <= 0) {
		printf("frames length can't be lower than 1");
	}

	// Process every byte in the data.
	for (i = 0; i < 14; i++) {
		if (i >= 0 && i < 6) {
			ethernet.dest_MA[i] = pc[i];
		}
		else if (i >= 6 && i < 12)
			ethernet.source_MA[i - 6] = pc[i];
		else if (i >= 12 && i < 14)
			if (pc[12] == 8 && pc[13] == 0) {
				strcpy(ethernet.ether_type, "IP");
			}
		ethernet.hexDump[i] = pc[i];
	}
	return ethernet;
}

struct ether ip_dump(void *addr, struct ether ethernet) {
	int i;
	unsigned char *pc = (unsigned char*)addr;
	// ip protocol

	for (i = 14; i < 34; i++) {
		if (i == 23) {
			if (pc[i] == 6) {
				strcpy(ethernet.next.ip_type, "TCP");
			}
			if (pc[i] == 1) {
				strcpy(ethernet.next.ip_type, "ICMP");
			}
		}

		// ip addresses
		if (i >= 26 && i < 30)
			ethernet.next.source_ip[i - 26] = pc[i];
		if (i >= 30 && i < 34)
			ethernet.next.dest_ip[i - 30] = pc[i];

		ethernet.hexDump[i] = pc[i];
		ethernet.hexDump[34] = '9999';
	}
	return ethernet;
}

struct tcp tcp_dump(void *addr) {
	int i;
	unsigned char *p = (unsigned char*)addr;
	struct tcp tcp;

	// tcp protocol port
	for (i = 34; i < 38; i++) {
		if (i >= 34 && i < 36)
			tcp.source_port[i - 34] = p[i];

		else if (i >= 36 && i < 38)
			tcp.dest_port[i - 36] = p[i];

	}
	return tcp;
}

struct icmp icmp_dump(void *addr) {
	int i;
	unsigned char *p = (unsigned char*)addr;
	struct icmp icmp;

	for (i = 34; i < 36; i++) {
		// icpm protocol port
		if (i >= 34 && 36) {
			icmp.icmp_type[i - 34] = p[i];
		}
	}

	return icmp;
}


struct ether *dump(void *addr, struct pcap_pkthdr packet_header, int id) {
	int i;
	unsigned char *pc = (unsigned char*)addr;
	struct ether ethernet;
	struct ip ip;
	struct tcp tcp;
	struct icmp icmp;
	struct ether all_eths[50];

	ethernet.id = id;
	ethernet.frame_length_pcap = packet_header.len;
	ethernet.frame_length_cable = packet_header.caplen;

	ethernet = ether_dump(pc, packet_header.len, ethernet);
	if (strcmp(ethernet.ether_type, "IP") == 0) {
		ethernet = ip_dump(pc, ethernet);
	}
	if (strcmp(ethernet.next.ip_type, "TCP") == 0) {
		tcp = tcp_dump(pc);
		ethernet.next.next = tcp;
	}
	if (strcmp(ethernet.next.ip_type, "ICMP") == 0) {
		icmp = icmp_dump(pc);
		ethernet.next.icmp = icmp;
	}
	printEther(ethernet);
	printf("\nhexdump\n");
	printHexa(ethernet.hexDump, GET_SIZE(ethernet.hexDump)));
	all_eths[id] = ethernet;
	putchar('\n');
	return all_eths;
}

void ipDump(void *addr, int len) {
	int i, ip_protocol;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;


	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}

	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}

	









		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	/*while ((i % 16) != 0) {
		printf("   ");
		i++;
	}*/

	// And print the final ASCII bit.
	//printf("  %s\n", buff);


void dumpHex(void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int packet_number = 1;

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
	//printf("Packet Number: %d\n", packet_number++);
	printf("Packet capture length: %d\n", packet_header.caplen);
	printf("Packet total length %d\n", packet_header.len);
	printf("\n");
}

void packet_handler(
	u_char *args,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_body,
	int counter
	)
{

	/*ipDump(packet_body, packet_header);
	print_packet_info(packet_body, *packet_header);*/
	dump(packet_body, *packet_header, counter++);

	return;
}

int main(int argc, char *argv[]) {
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char * data[2560];

	char c;

	/* Skip over the program name. */
	//++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	char filename[50] = "files/trace-1.pcap";

	pcap = pcap_open_offline(filename, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	/* Now just loop through extracting packets as long as we have
	* some to read.
	*/
	int counter = 1;
	unsigned char buffer[2560], my_str[2560];
	// hexDump(pcap, sizeof(pcap) + 7500);
	// printf("%d\n==========================================\n", sizeof(pcap));

	while ((packet = pcap_next(pcap, &header)) != NULL) {	
		//dump_UDP_packet(packet, header.ts, header.caplen);
		//dump_UDP_packet(packet, header.ts, header.caplen);
		//hexDump("my_str", &header, sizeof(header));
		dumpHex(packet, sizeof(packet) + 150);
		counter++;
	}
	//ipDump(pcap, sizeof(pcap) + 7500);

	pcap_close(pcap);

	pcap = pcap_open_offline(filename, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}
	int counter2 = 0;
	pcap_loop(pcap, 0, packet_handler, NULL, counter2++);



	// terminate
	getchar();
	return 0;
}




/* Note, this routine returns a pointer into a static buffer, and
* so each call overwrites the value returned by the previous call.
*/
const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int)ts.tv_sec, (int)ts.tv_usec);

	return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
}
