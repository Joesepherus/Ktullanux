/*
Simple UDP Server
*/

#include<stdio.h>
#include<winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data
#define SERVER "127.0.0.1"  //ip address of udp server

#define HEADER_BASIC 12
#define HEADER_ACK 16
#define HEADER_INIT 20

// basic message
typedef struct message {
	int fragment_id;
	int type;
	int checksum;
	char *data;
} MESSAGE;

// ack, nack
typedef struct ack {
	int fragment_id;
	int type;
	int checksum;
	int checked_fragment_id;
} ACK;

// init basic message, init file message
typedef struct init{
	int fragment_id;
	int type;
	int checksum;
	int number_of_packets;
	int packet_size;
} INIT;


const unsigned char CRC7_POLY = 0x91;

unsigned char getCRC(char message[], unsigned char length)
{
	unsigned char i, j, crc = 0;

	for (i = 0; i < length; i++)
	{
		crc ^= message[i];
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc ^= CRC7_POLY;
			crc >>= 1;
		}
	}
	return crc;
}

MESSAGE* listen_message(int s, int slen, int frag_size) {
	struct sockaddr_in si_other;
	char buf[1000];
	int recv_len;
	printf("Waiting for data...");
	fflush(stdout);

	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', BUFLEN);

	//try to receive some data, this is a blocking call

	if ((recv_len = recvfrom(s, buf, 1000, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
	{
		printf("recvfrom() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//print details of the client/peer and the data received
	printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
	//MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));
	MESSAGE* m = (MESSAGE*)malloc(sizeof(MESSAGE));
	m->fragment_id = (int)(buf[0]);
	m->type = (int)(buf[4]);
	m->data = (char*)(&buf[8]);
	printf("%d", strlen(m->data));
	m->data[strlen(m->data)] = '\0';
	m->checksum = (int)(buf[HEADER_BASIC + frag_size - 4]);
	//char *data = (char*)(&buf[12]);

	// ack initialize
	ACK* m2 = (ACK*)malloc(sizeof(ACK));
	m2->fragment_id = 25156;
	m2->type = 4;
	m2->checksum = (int)(buf[HEADER_BASIC]);

	int *intlocation = (int*)(&m2[0]);
	*intlocation = m->fragment_id; // stores 3632
	intlocation = (int*)(&m2[8]);
	*intlocation = m->type;
	/*intlocation = (int*)(&m2[16]);
	int crc = getCRC(buf, HEADER_ACK - 4);*/
	int crc = getCRC(buf, HEADER_BASIC - 4);

	if (m->checksum != crc)
		*intlocation = -1;
	else *intlocation = m->fragment_id;

	// send ACK OR NACK
	while (1)
		if (sendto(s, (CHAR*)m2, HEADER_ACK, 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d", WSAGetLastError());
		}
		else break;
		return m;
}

INIT* listen_init(int s, int slen) {
	struct sockaddr_in si_other;
	char buf[1000];
	int recv_len;
	printf("Waiting for data...");
	fflush(stdout);

	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', BUFLEN);

	//try to receive some data, this is a blocking call

	if ((recv_len = recvfrom(s, buf, 1000, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
	{
		printf("recvfrom() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//print details of the client/peer and the data received
	printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
	//MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));
	INIT* m = (INIT*)malloc(sizeof(INIT));
	int *intlocation = (int*)(&buf[0]);
	m->fragment_id = *intlocation;
	m->number_of_packets = (int)(buf[4]);
	m->type = (int)(buf[8]);
	m->packet_size = (int)(buf[12]);
	m->checksum = (int)(buf[20]);

	int crc = getCRC(buf, HEADER_INIT - 4);

	// ack initialize
	/*ACK* m2 = (ACK*)malloc(sizeof(ACK));
	m2->fragment_id = 25156;
	m2->type = 4;
	m2->checksum = (int)(buf[12]);*/
	char m1[1000];
	intlocation = (int*)(&m1[0]);
	*intlocation = 1458;
	intlocation = (int*)(&m1[8]);
	*intlocation = 7;
	intlocation = (int*)(&m1[16]);
	//crc = getCRC(m1, HEADER_INIT - 4);
	//*intlocation = crc;

	if (m->checksum != crc) 
		*intlocation = -1;
	else *intlocation = m->fragment_id;

	// send ACK OR NACK
	while (1)
		if (sendto(s, (CHAR*)m1, HEADER_INIT, 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d", WSAGetLastError());
		}
		else break;
	return m;
}

char* stradd(const char* a, const char* b) {
	size_t len = strlen(a) + strlen(b);
	char *ret = (char*)malloc(len * sizeof(char) + 1);
	*ret = '\0';
	return strcat(strcat(ret, a), b);
}

void server() {
	SOCKET s, s1;
	struct sockaddr_in server, si_other;
	int slen, recv_len;
	char buf[1000];
	WSADATA wsa;

	slen = sizeof(si_other);

	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}
	printf("Socket created.\n");

	s1 = s;

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(PORT);

	//Bind
	if (bind(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	puts("Bind done");

	int counter, packets;
	char *message = (char*)malloc(sizeof(char)*1000);
	memset(message, '\0', BUFLEN);
	INIT* m = (INIT*)malloc(sizeof(INIT));
	MESSAGE* m1 = (MESSAGE*)malloc(sizeof(MESSAGE));
	//keep listening for data
	while (1)
	{
		
		m = listen_init(s, slen);

		// if the first message was a init message then start accepting/receiveing the number of messages specified by the init message
		if (m->type == 9) break;
		else if (m->type == 7) {
			packets = m->number_of_packets;
			counter = 0;
			memset(message, '\0', 1000);
			while (counter < packets) {
				m1 = listen_message(s, slen, m->packet_size);
				strcpy(message, stradd(message, m1->data));
				counter++;
			}
			printf("%s", message);
		}
		//else printf("frag. id = %d | frag. size = %d | message type = %d | data = %s\n", *fragment_id, *size, *type, data);
	}

	closesocket(s);
	WSACleanup();
	getchar();
}

int change_conn(int s, struct sockaddr_in si_other, int slen) {
	MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));

	m->fragment_id = 6518;
	m->type = 9;
	char buf[1000];
	char m1[1000];
	int *intlocation = (int*)(&m1[0]);
	*intlocation = m->fragment_id; // stores 3632
	intlocation = (int*)(&m1[8]);
	*intlocation = m->type;
	
	if (sendto(s, (CHAR*)m1, 1000, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//receive a reply and print it
	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', 1000);
	//try to receive some data, this is a blocking call
	while (1)
		if (recvfrom(s, buf, 1000, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
		{
			// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
		}
		else return 0;
}

unsigned int round_closest(unsigned int dividend, unsigned int divisor) {
	return (dividend + (divisor / 2)) / divisor;
}

void send_text(int s, struct sockaddr_in si_other, int slen) {
	int frag_size, count, i = 0;
	char m1[1000];
	char message[1000], buf[1000];

	printf("Enter message : ");
	getchar();
	fgets(message, 1000, stdin);

	printf("Set the size of fragments");
	scanf("%d", &frag_size);
	count = strlen(message);

	MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));
	m->fragment_id = 1457;

	int *intlocation = (int*)(&m1[0]);
	*intlocation = 1457;
	intlocation = (int*)(&m1[8]);
	*intlocation = 7;
	intlocation = (int*)(&m1[4]);
	*intlocation = round_closest(count, frag_size);
	intlocation = (int*)(&m1[12]);
	*intlocation = frag_size;
	intlocation = (int*)(&m1[20]);
	int crc = getCRC(m1, HEADER_INIT - 4);
	*intlocation = crc;
	if (sendto(s, (CHAR*)m1, frag_size + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	// receive an ACK from server
	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', 1000);
	//try to receive some data, this is a blocking call
	while (1) {
		if (recvfrom(s, buf, 1000, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
		{
			continue;
			// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
		}
		printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
		//MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));
		ACK*m2 = (ACK*)malloc(sizeof(ACK));
		int *intlocation = (int*)(&buf[16]);
		m2->checked_fragment_id = *intlocation;
		if (m2->checked_fragment_id == m->fragment_id) { 
			break; 
		}
		else {
			printf("faulty packet, need to send it again");
			if (sendto(s, (CHAR*)m1, frag_size + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d", WSAGetLastError());
				exit(EXIT_FAILURE);
			}
		}
	}
	
	while (count >= 0) {
		memset(m1, '\0', 1000);
		count -= frag_size;
		m->fragment_id = 6514;
		m->type = 2;
		m->data = message;
		intlocation = (int*)(&m1[0]);
		*intlocation = m->fragment_id; // stores 3632
		intlocation = (int*)(&m1[4]);
		*intlocation = m->type;
		//char** data_location = (char**)(&m1[12]);
		strncpy((char*)&m1[8], m->data + i * frag_size, frag_size);
		unsigned char message[3] = { 0x83, 0x01, 0x00 };
		crc = getCRC(m1, HEADER_BASIC + frag_size - 4);
		intlocation = (int*)(&m1[HEADER_BASIC + frag_size - 4]);
		*intlocation = crc;
		i++;
		//*data_location = m->data;
		//printf("%s %d %s", m1, strlen((CHAR*)m1));
		//send the message
		if (sendto(s, (CHAR*)m1, frag_size + HEADER_BASIC, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}

		//receive a reply and print it
		//clear the buffer by filling null, it might have previously received data
		memset(buf, '\0', 1000);
		//try to receive some data, this is a blocking call
		while (1)
			if (recvfrom(s, buf, 1000, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
			{
				// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
			}
			else break;
	}
		//puts(buf);
}

int client() {
	/*
    Simple udp client
*/
    struct sockaddr_in si_other;
    int s, slen=sizeof(si_other);
    char buf[1000];
    char message[BUFLEN];
    WSADATA wsa;
	char ip_address[20];
 
	printf("input the IP address, for default press d\n");
	scanf("%s", ip_address);
	if (strcmp(ip_address, "d") == 0)
		strcpy(ip_address, SERVER);


    //Initialise winsock
    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("Failed. Error Code : %d",WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    printf("Initialised.\n");
     
    //create socket
    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
    {
        printf("socket() failed with error code : %d" , WSAGetLastError());
        exit(EXIT_FAILURE);
    }
     
    //setup address structure
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
    si_other.sin_addr.S_un.S_addr = inet_addr(ip_address);
    
	char c;

	getchar();

	do {
		// menu
		printf("CLIENT MENU:\n");
		printf("t - text message:\n");
		printf("c - change connection:\n");
		printf("e - exit program:\n");
		c = getchar();
		getchar();
		switch (c) {
		case 't':
			send_text(s, si_other, slen);
			continue;
		case 'c':
			change_conn(s, si_other, slen);
			break;
		case 'e':
			return 1;
		}
	} while (c != 'e');
 
    closesocket(s);
    WSACleanup();
	return 0;
}

int main() {
	printf("client or server?");
	char c;
	c = getchar();
		switch (c) {
			case 's': 
				while (1) {
					server(); 
					if (client() == 1) break;
				}
			case 'c' :
				while (1) {
					if (client() == 1) break;
					server();
				}
			default:
				break;
		}
	

	getchar();
	return 0;
}