/*
Simple UDP Server
*/

#include<stdio.h>
#include<winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data
#define SERVER "127.0.0.1"  //ip address of udp server

typedef struct message {
	int fragment_id;
	int number_of_packets;
	int type;
	int checksum;
	char *data;
} MESSAGE;

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


MESSAGE* listen_to_messages(int s, int slen) {
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
	m->number_of_packets = (int)(buf[4]);
	m->type = (int)(buf[8]);
	m->data = (char*)(&buf[12]);
	printf("%d", strlen(m->data));
 	m->data[strlen(m->data)] = '\0';
	//char *data = (char*)(&buf[12]);

	//now reply the client with the same data
	while (1)
		if (sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
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
	MESSAGE* m = (MESSAGE*)malloc(sizeof(MESSAGE));
	//keep listening for data
	while (1)
	{

		m = listen_to_messages(s, slen);

		if (m->type == 9) break;
		else if (m->type == 7) {
			packets = m->number_of_packets;
			counter = 0;
			memset(message, '\0', 1000);
			while (counter < packets) {
				m = listen_to_messages(s, slen);
				strcpy(message, stradd(message, m->data));
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
	int frag_size, header_size = 16, count, i = 0;
	char m1[1000];
	char message[1000], buf[1000];
	printf("Enter message : ");
	getchar();
	fgets(message, 1000, stdin);

	printf("Set the size of fragments");
	scanf("%d", &frag_size);
	count = strlen(message);

	MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));

	int *intlocation = (int*)(&m1[8]);
	*intlocation = 7;
	intlocation = (int*)(&m1[4]);
	*intlocation = round_closest(count, frag_size);
	if (sendto(s, (CHAR*)m1, frag_size + header_size, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//receive a reply and print it
	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', 1000);
	//try to receive some data, this is a blocking call
	while (1) {
		if (recvfrom(s, buf, 1000, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
		{
			// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
		}
		else break;
	}




	while (count >= 0) {
		memset(m1, '\0', 1000);
		count -= frag_size;
		m->fragment_id = 6514;
		m->type = 2;
		m->data = message;
		intlocation = (int*)(&m1[0]);
		*intlocation = m->fragment_id; // stores 3632
		intlocation = (int*)(&m1[8]);
		*intlocation = m->type;
		//char** data_location = (char**)(&m1[12]);
		strncpy((char*)&m1[12], m->data + i * frag_size, frag_size);
		unsigned char message[3] = { 0x83, 0x01, 0x00 };
		int crc = getCRC(m1, header_size + frag_size);
		i++;
		//*data_location = m->data;
		//printf("%s %d %s", m1, strlen((CHAR*)m1));
		//send the message
		if (sendto(s, (CHAR*)m1, frag_size + header_size, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
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