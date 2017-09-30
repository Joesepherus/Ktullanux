#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap.h"

// ================================================================================================================================================================
#define GET_SIZE(p) ((sizeof(p)/sizeof(p[0]))

typedef struct icmp {
	unsigned char icmp_type[2];
} ICMP;

typedef struct tcp {
	unsigned char source_port[2];
	unsigned char dest_port[2];
} TCP;

typedef struct ip {
	unsigned char source_ip[4];
	unsigned char dest_ip[4];
	unsigned char protocol_ip;
	unsigned char ip_type[3];
	struct tcp next;
	//struct arp arp;
	struct icmp icmp;
} IP;

typedef struct ether {
	unsigned short id;
	unsigned short frame_length_pcap;
	unsigned short frame_length_cable;
	unsigned char source_MA[6];
	unsigned char dest_MA[6];
	unsigned char ether_type[4];
	struct ip next;
	unsigned char hexDump[1500];
} ETHER;

typedef struct arp {
	unsigned char operation[4];
	unsigned char arp_req_ip[8];
	unsigned char arp_reply_ip[8];
} ARP;

struct ether ethernets[250];
int main_counter = 0;

void printHexa(unsigned char *ptr, int size) {
	for (int i = 0; i < size; i++) {
		if (i % 8 == 0 && i != 0) putchar(' ');
		if (i % 16 == 0 && i != 0) putchar('\n');
		printf("%02x ", ptr[i]);
	}
	putchar('\n');
}

void printEther(struct ether ethernet) {
	printf("id=%d\nlength=%d\nlength2=%d\n", ethernet.id, ethernet.frame_length_pcap, ethernet.frame_length_cable);
	printHexa(ethernet.source_MA, GET_SIZE(ethernet.source_MA)));
	printHexa(ethernet.dest_MA, GET_SIZE(ethernet.dest_MA)));

	if (strcmp(ethernet.ether_type, "IP") == 0) {
		printf("%s\n", ethernet.ether_type);
		printHexa(ethernet.next.dest_ip, GET_SIZE(ethernet.next.dest_ip)));
		printHexa(ethernet.next.source_ip, GET_SIZE(ethernet.next.source_ip)));
	}


	if (strcmp(ethernet.next.ip_type, "TCP") == 0) {
		printf("%s\n", ethernet.next.ip_type);
		printHexa(ethernet.next.next.dest_port, GET_SIZE(ethernet.next.next.dest_port)));
		printHexa(ethernet.next.next.source_port, GET_SIZE(ethernet.next.next.source_port)));
	}
	else if (strcmp(ethernet.next.ip_type, "ICMP") == 0) {
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
			if (pc[12] > 6 && pc[13] == 0) {
				strcpy(ethernet.ether_type, "Ethernet");
			}
			else {
				strcpy(ethernet.ether_type, "802.2");
			}
		ethernet.hexDump[i] = pc[i];
	}
	return ethernet;
}

struct ether getHexDump(void *addr, struct ether ethernet) {
	unsigned char *pc = (unsigned char*)addr;
	int i;
	for (i = 0; i < ethernet.frame_length_cable; i++) {
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
			else if (pc[i] == 1) {
				strcpy(ethernet.next.ip_type, "ICMP");
			}
			else {
				strcpy(ethernet.next.ip_type, NULL);
			}
		}

		// ip addresses
		if (i >= 26 && i < 30)
			ethernet.next.source_ip[i - 26] = pc[i];
		if (i >= 30 && i < 34)
			ethernet.next.dest_ip[i - 30] = pc[i];

	}
	return ethernet;
}

struct tcp tcp_dump(void *addr) {
	int i;
	unsigned char *p = (unsigned char*)addr;
	struct tcp tcp;

	// tcp protocol port
	for (i = 34; i < 38; i++) {
		if (i >= 34 && i < 36) {
			tcp.source_port[i - 34] = p[i];
		}
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


struct ether dump(void *addr, struct pcap_pkthdr packet_header) {
	int i;
	unsigned char *pc = (unsigned char*)addr;
	struct ether ethernet;
	struct ip ip;
	struct tcp tcp;
	struct icmp icmp;
	struct ether all_eths[50];

	ethernet.id = main_counter;
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
	/*printEther(ethernet);
	printf("\nhexdump\n");
	printHexa(ethernet.hexDump, GET_SIZE(ethernet.hexDump)));
	putchar('\n');*/
	ethernet = getHexDump(addr, ethernet);
	ethernets[main_counter] = ethernet;
	return ethernet;
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
	int *counter,
	struct ether ethernets
	)
{

	/*ipDump(packet_body, packet_header);
	print_packet_info(packet_body, *packet_header);*/
	dump(packet_body, *packet_header);
	main_counter++;
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

void displayTCP(int type) {
	int counter = 0;
	while (counter < main_counter) {
		if (type == 20 && ethernets[counter].next.next.source_port == type) {
			printf("id = %d\n", counter);
		}
		if (type == 22 && (int)ethernets[counter].next.next.source_port == type) {
			printf("id = %d\n", counter);
		}
		if (strcmp(ethernets[counter].next.ip_type, "TCP") == 0 && type == 80 && ethernets[counter].next.next.source_port[0] == 0 && ethernets[counter].next.next.source_port[1] == 80) {
			printf("id = %d\n", counter);
		}
		counter++;
	}
}

void displayAll() {
	int counter = 0;
	while (counter < main_counter) {
		printf("Ramec %d\n", ethernets[counter].id);
		printf("Dlzka ramca poskytnuta pcap API - %d\n", ethernets[counter].frame_length_pcap);
		printf("Dlzka ramca prenasaneho po mediu - %d\n", ethernets[counter].frame_length_cable);
		printf("%s\n", ethernets[counter].ether_type);
		printf("Zdrojova MAC adresa: ");
		printHexa(ethernets[counter].source_MA, GET_SIZE(ethernets[counter].source_MA)));
		printf("Cielova MAC adresa: ");
		printHexa(ethernets[counter].dest_MA, GET_SIZE(ethernets[counter].dest_MA)));
		printHexa(ethernets[counter].hexDump, ethernets[counter].frame_length_pcap);
		counter++;
		putchar('\n');
	}
}


int main(int argc, char *argv[]) {
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char * data[2560];

	char c;
	char filename[50] = "files/trace-1.pcap";

	pcap = pcap_open_offline(filename, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	/*while ((packet = pcap_next(pcap, &header)) != NULL) {	
		dumpHex(packet, sizeof(packet) + 150);
		counter++;
	}*/

	pcap_close(pcap);

	pcap = pcap_open_offline(filename, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}
	int counter2 = 0;

	pcap_loop(pcap, 0, packet_handler, NULL);
	pcap_close(pcap);

	int counter = 0;
	int choice;
	do {
		printf("Menu\n");
		printf("0. ALL\n");
		printf("1. HTTP\n");
		printf("2. HTTPS\n");
		printf("3. TELNET\n");
		printf("4. SSH\n");
		printf("5. FTP DATA\n");
		printf("6. FTP CONTROL\n");
		printf("7. TFTP\n");
		printf("8. ICMP\n");
		printf("9. ARP\n");
		printf("10. EXIT\n");
		scanf("%d", &choice);

		switch (choice) {
			case 0: displayAll(); break;
			case 1: displayTCP(80); break;
			case 2: displayTCP("HTTPS"); break;
			case 3: displayTCP("TELNET"); break;
			case 4: displayTCP(22); break;
			case 5: displayTCP(20); break;
			case 6: displayTCP("FTP CONTROL"); break;
			case 7: displayTCP("TFTP"); break;
		}

	} while (choice != 10);

	getchar();
	return 0;
}