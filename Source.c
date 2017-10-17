#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap.h"

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
	struct tcp tcp;
	struct icmp icmp;
} IP;

typedef struct arp {
	unsigned char operation[15];
	unsigned char source_mac[6];
	unsigned char source_ip[4];
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];
} ARP;

typedef struct ether {
	unsigned short id;
	unsigned short frame_length_pcap;
	unsigned short frame_length_cable;
	unsigned char source_MA[6];
	unsigned char dest_MA[6];
	unsigned char ether_type[15];
	unsigned char frame_type[15];
	struct ip ip;
	struct arp arp;
	unsigned char hexDump[1500];
} ETHER;

struct ether ethernets[12500];
int main_counter = 0;
int packet_number = 1;

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

	if (strcmp(ethernet.frame_type, "Ethernet") == 0) {
		printf("%s\n", ethernet.frame_type);
		printHexa(ethernet.ip.dest_ip, GET_SIZE(ethernet.ip.dest_ip)));
		printHexa(ethernet.ip.source_ip, GET_SIZE(ethernet.ip.source_ip)));
	}

	if (strcmp(ethernet.ether_type, "ARP") == 0) {
		printf("%s\n", ethernet.frame_type);
		printHexa(ethernet.arp.dest_ip, GET_SIZE(ethernet.arp.dest_ip)));
		printHexa(ethernet.arp.dest_mac, GET_SIZE(ethernet.arp.dest_mac)));
		printHexa(ethernet.arp.source_ip, GET_SIZE(ethernet.arp.source_ip)));
		printHexa(ethernet.arp.dest_ip, GET_SIZE(ethernet.arp.dest_ip)));
	}

	if (strcmp(ethernet.ip.ip_type, "TCP") == 0) {
		printf("%s\n", ethernet.ip.ip_type);
		printHexa(ethernet.ip.tcp.dest_port, GET_SIZE(ethernet.ip.tcp.dest_port)));
		printHexa(ethernet.ip.tcp.source_port, GET_SIZE(ethernet.ip.tcp.source_port)));
	}
	else if (strcmp(ethernet.ip.ip_type, "ICMP") == 0) {
		printHexa(ethernet.ip.icmp.icmp_type, GET_SIZE(ethernet.ip.icmp.icmp_type)));
	}
	/*else if (strcmp(ethernet.next.ip_type, "TFTP") == 0) {
		printHexa(ethernet.next.tftp.tftp, GET_SIZE(ethernet.next.icmp.icmp_type)));
	}*/

}

struct ether ether_dump(void *addr, int len, struct ether ethernet) {
	int i;
	unsigned char *pc = (unsigned char*)addr;

	if (len <= 0) {
		printf("frames length can't be lower than 1");
	}

	for (i = 0; i < 14; i++) {
		if (i >= 0 && i < 6) {
			ethernet.dest_MA[i] = pc[i];
		}
		else if (i >= 6 && i < 12)
			ethernet.source_MA[i - 6] = pc[i];
		else if (i >= 12 && i < 14)
			if (pc[12] > 6) {
				strcpy(ethernet.frame_type, "Ethernet");
				if (pc[12] == 8 && pc[13] == 6) {
					strcpy(ethernet.ether_type, "ARP");
					//printf("OOOO\n");
				}
				else strcpy(ethernet.ether_type, "IP");
			}
			else {
				strcpy(ethernet.frame_type, "802.3");
				if (pc[14] == 255 && pc[15] == 255) {
					strcpy(ethernet.frame_type, "802.3 RAW");
				}
				else if (pc[15] == 170)
					strcpy(ethernet.frame_type, "802.3 - LLC - SNAP");
				else
					strcpy(ethernet.frame_type, "802.3 - LLC");
			}
	}
	return ethernet;
}

struct ether getHexDump(void *addr, struct ether ethernet) {
	unsigned char *pc = (unsigned char*)addr;
	int i;
	for (i = 0; i < ethernet.frame_length_pcap; i++) 
		ethernet.hexDump[i] = pc[i];
	return ethernet;
}

struct ether ip_dump(void *addr, struct ether ethernet) {
	int i;
	unsigned char *pc = (unsigned char*)addr;
	// ip protocol

	for (i = 14; i < 34; i++) {
		if (i == 23) {
			if (pc[i] == 6) {
				strcpy(ethernet.ip.ip_type, "TCP");
			}
			else if (pc[i] == 1) {
				strcpy(ethernet.ip.ip_type, "ICMP");
			}
			else {
				strcpy(ethernet.ip.ip_type, "ine");
			}
		}

		// ip addresses
		if (i >= 26 && i < 30)
			ethernet.ip.source_ip[i - 26] = pc[i];
		if (i >= 30 && i < 34)
			ethernet.ip.dest_ip[i - 30] = pc[i];

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

struct arp arp_dump(void *addr) {
	int i;
	unsigned char *p = (unsigned char*)addr;
	struct arp arp;

	for (i = 14; i < 42; i++) {
		if (i >= 20 && i < 22)
			if (p[21] == 1)
				strcpy(arp.operation, "Request");
			else
				strcpy(arp.operation, "Reply");
		if (i >= 22 && i < 28)
			arp.source_mac[i - 22] = p[i];
		if (i >= 28 && i < 32)
			arp.source_ip[i - 28] = p[i];
		if (i >= 32 && i < 38)
			arp.dest_mac[i - 32] = p[i];
		if (i >= 38 && i < 42)
			arp.dest_ip[i - 38] = p[i];
	}
	return arp;
}

struct ether dump(void *addr, struct pcap_pkthdr packet_header) {
	int i;
	unsigned char *pc = (unsigned char*)addr;
	struct ether ethernet;
	struct ip ip;
	struct tcp tcp;
	struct icmp icmp;
	struct arp arp;
	struct ether all_eths[50];

	ethernet.id = main_counter;

	ethernet = ether_dump(pc, packet_header.len, ethernet);
	if (packet_header.len + 4 < 64) 
		ethernet.frame_length_pcap= 64;
	else ethernet.frame_length_pcap = packet_header.caplen;

	ethernet.frame_length_cable = ethernet.frame_length_pcap + 4;

	if (strcmp(ethernet.frame_type, "Ethernet") == 0) {
		if(strcmp(ethernet.ether_type, "IP") == 0)
			ethernet = ip_dump(pc, ethernet);
		if (strcmp(ethernet.ether_type, "ARP") == 0) {
			arp = arp_dump(pc);
			ethernet.arp = arp;
		}
	}
	if (strcmp(ethernet.ip.ip_type, "TCP") == 0) {
		tcp = tcp_dump(pc);
		ethernet.ip.tcp = tcp;
	}
	if (strcmp(ethernet.ip.ip_type, "ICMP") == 0) {
		icmp = icmp_dump(pc);
		ethernet.ip.icmp = icmp;
	}

	ethernet = getHexDump(addr, ethernet);
	ethernets[main_counter] = ethernet;
	return ethernet;
}


void packet_handler(
	u_char *args,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_body,
	int *counter,
	struct ether ethernets
	) {
	dump(packet_body, *packet_header);
	main_counter++;
}

void displayTCP(int type) {
	int counter = 0;
	while (counter < main_counter) {
		if (strcmp(ethernets[counter].ip.ip_type, "TCP") == 0) {
			if (ethernets[counter].ip.tcp.source_port[0] == 0 && ethernets[counter].ip.tcp.source_port[1] == type) {
				printf("id = %d\n", counter);
			}
		}
		counter++;
	}
}

void displayARP(int i, int *arp_count) {
	printf("Komunikacia c. %d\n", *arp_count);
	printf("%ARP - %s\n", ethernets[i].arp.operation);
	printf("IP adresa: ");
	printHexa(ethernets[i].arp.dest_ip, GET_SIZE(ethernets[i].arp.dest_ip)));
	printf("MAC adresa: ");
	printHexa(ethernets[i].arp.dest_mac, GET_SIZE(ethernets[i].arp.dest_mac)));
	printf("Zdrojova IP: ");
	printHexa(ethernets[i].arp.source_ip, GET_SIZE(ethernets[i].arp.source_ip)));
	printf("Cielova IP: ");
	printHexa(ethernets[i].arp.dest_ip, GET_SIZE(ethernets[i].arp.dest_ip)));
	*arp_count++;
}

void displayARPAll() {
	int i = 0, arp_count = 0;
	while (i < main_counter) {
		if (strcmp(ethernets[i].ether_type, "ARP") == 0) {
			printf("Komunikacia c. %d\n", arp_count);
			printf("ARP - %s\n", ethernets[i].arp.operation);
			printf("IP adresa: ");
			printHexa(ethernets[i].arp.dest_ip, GET_SIZE(ethernets[i].arp.dest_ip)));
			printf("MAC adresa: ");
			printHexa(ethernets[i].arp.dest_mac, GET_SIZE(ethernets[i].arp.dest_mac)));
			printf("Zdrojova IP: ");
			printHexa(ethernets[i].arp.source_ip, GET_SIZE(ethernets[i].arp.source_ip)));
			printf("Cielova IP: ");
			printHexa(ethernets[i].arp.dest_ip, GET_SIZE(ethernets[i].arp.dest_ip)));
			arp_count++;
		}
		i++;
	}
}

void displayAll() {
	int counter = 0, arp_count = 0, size;
	printf("Zadaj pocet vypisaneho hex dumpu, pre vypis celeho stlac 0\n");
	scanf("%d", &size);
	while (counter < main_counter) {
		if (strcmp(ethernets[counter].ether_type, "ARP") == 0)
			displayARP(counter, &arp_count);
		printf("Ramec %d\n", ethernets[counter].id);
		printf("Dlzka ramca poskytnuta pcap API - %d\n", ethernets[counter].frame_length_pcap);
		printf("Dlzka ramca prenasaneho po mediu - %d\n", ethernets[counter].frame_length_cable);
		printf("%s\n", ethernets[counter].frame_type);
		printf("Zdrojova MAC adresa: ");
		printHexa(ethernets[counter].source_MA, GET_SIZE(ethernets[counter].source_MA)));
		printf("Cielova MAC adresa: ");
		printHexa(ethernets[counter].dest_MA, GET_SIZE(ethernets[counter].dest_MA)));
		if (size == 0) printHexa(ethernets[counter].hexDump, ethernets[counter].frame_length_pcap);
		else printHexa(ethernets[counter].hexDump, size);
		counter++;
		putchar('\n');
	}
}

typedef struct arpCom {
	unsigned short id;
	unsigned short count;
	unsigned char src_ip[4];
	unsigned char dest_ip[4];
} ARPCOM;

void arpCom() {
	struct arpCom arpCom[2000];
	int counter = 0, arpCount = 0, arpComs[2000], anotherCounter;
	char arp_request_source_ip[4][250];
	while (counter < main_counter) {
		anotherCounter = 0; 
		if (strcmp(ethernets[counter].ether_type, "ARP") == 0) {
			if (arpCount == 0) {
				// create a new arpCom
				arpCom[arpCount].id = counter;
				arpCom[arpCount].count = 1;
				strcpy(arpCom[arpCount].src_ip, ethernets[counter].arp.source_ip);
				strcpy(arpCom[arpCount].dest_ip, "");
			}
			while (anotherCounter < arpCount) {
				if (strcmp(arpCom[anotherCounter].src_ip, ethernets[counter].arp.source_ip) == 0 && arpCom[anotherCounter].dest_ip == "") {
					if (strcmp(ethernets[counter].arp.operation, "Request") == 0)
						arpCom[anotherCounter].count++;
					else if (strcmp(ethernets[counter].arp.operation, "Reply") == 0) 
						strcpy(arpCom[anotherCounter].dest_ip, ethernets[counter].arp.dest_ip);
				}
				else {
					// create a new arpCom
					arpCom[arpCount].id = counter;
					arpCom[arpCount].count = 1;
					strcpy(arpCom[arpCount].src_ip, ethernets[counter].arp.source_ip);
					strcpy(arpCom[arpCount].dest_ip, "");
				}
				anotherCounter++;
			}
			arpCount++;
		}
		counter++;
	}	

	anotherCounter = 0;
	while (anotherCounter < arpCount) {
		printf("%d\n%d\n%s\n%s\n", arpCom[anotherCounter].id, arpCom[anotherCounter].count, arpCom[anotherCounter].src_ip, arpCom[anotherCounter].dest_ip);
		anotherCounter++;
	}
}

pcap_t *setFile() {
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filename[50];

	printf("Enter the name of the file\n");
	scanf("%s", filename);
	pcap = pcap_open_offline(filename, errbuf);
	printf("%s", filename);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		return NULL;
	}
	pcap_loop(pcap, 0, packet_handler, NULL);
	pcap_close(pcap);
	return pcap;
}

int main(int argc, char *argv[]) {
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char * data[2560];

	char c;
	char filename[50] = "files/trace-25.pcap";

	pcap = pcap_open_offline(filename, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

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
		printf("11. SET FILE\n");
		printf("12. ARP COM\n");
		scanf("%d", &choice);

		switch (choice) {
			case 0: displayAll(); break;
			case 1: displayTCP(80); break;
			case 2: displayTCP(443); break;
			case 3: displayTCP(23); break;
			case 4: displayTCP(22); break;
			case 5: displayTCP(20); break;
			case 6: displayTCP(21); break;
			case 9: displayARPAll(); break;
			case 11: pcap = setFile(); break;
			case 12: arpCom(); break;
		}

	} while (choice != 10);

	getchar();
	return 0;
}