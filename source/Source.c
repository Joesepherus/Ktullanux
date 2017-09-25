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

void ipDump(void *addr, int len) {
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

		/*if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				//printf("  %s\n", buff);

			// Output the offset.
			//printf("  %04x \n", i);
		}*/

		/*if (i % 8 == 0) {
			printf(" ");
		}*/
		if (i >= 12 && i < 14) {
			// Now the hex code for the specific character.
			if (i != 13) {
				printf("\n");
			}
			else {
				printf(" ");
			}
			printf("%02x", pc[i]);
		}
		if (i == 14) {
			printf("\n");
		}
		if (i >= 0 && i < 12 ) {
			if (i == 8) {
				printf("\n");
			}
			printf("%02x ", pc[i]);
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
}

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
	printf("Packet Number: %d\n", packet_number++);
	printf("Packet capture length: %d\n", packet_header.caplen);
	printf("Packet total length %d\n", packet_header.len);
	printf("\n");
}

void packet_handler(
	u_char *args,
		const struct pcap_pkthdr *packet_header,
		const u_char *packet_body
	)
{
	ipDump(packet_body, packet_header->len);
	print_packet_info(packet_body, *packet_header);
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

	//while ((packet = pcap_next(pcap, &header)) != NULL && counter <= 10) {	
		//dump_UDP_packet(packet, header.ts, header.caplen);
		//dump_UDP_packet(packet, header.ts, header.caplen);
		//hexDump("my_str", &header, sizeof(header));
		/*dumpHex(packet, sizeof(packet) + 150);
		printf("udp packet number: %d\nsizeof(data): %d\nsizeof(header): %d\n", counter, sizeof(data), sizeof(packet));
		counter++;*/
	//}
	//ipDump(pcap, sizeof(pcap) + 7500);

	pcap_loop(pcap, 0, packet_handler, NULL);



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
