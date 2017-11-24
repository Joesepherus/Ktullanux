/*
Simple UDP Server
*/

#include<stdio.h>
#include<winsock2.h>
#include <windows.h>
#include <iostream>
#include <stdlib.h> 

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
	char *data;
	int checksum;
} MESSAGE;

// ack, nack
typedef struct ack {
	int fragment_id;
	int type;
	int checked_fragment_id;
	int checksum;
} ACK;

// init basic message, init file message
typedef struct init {
	int fragment_id;
	int type;
	int number_of_packets;
	int packet_size;
	int checksum;
} INIT;

typedef struct packet {
	int fragment_id;
	int type;
	int checksum;
	int number_of_packets;
	int checked_fragment_id;
	int packet_size;
	char *data;
} PACKET;


const unsigned char CRC7_POLY = 0x91;

int fragment_id = 1;

void* as_ptr;
typedef struct as_fields {
	int a, b;
	struct sockaddr_in si_other;
}AS_FIELDS;

unsigned char getCRC(char message[], unsigned char length) {
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

CHAR* create_packet(int type, int frag_size) {
	char *m1 = (char*)malloc(sizeof(char) * 1500);
	// basic packet text message

	memset(m1, '\0', 1500);
	int *intlocation = (int*)(&m1[0]);

	// fragment id
	*intlocation = fragment_id; // stores 3632
	fragment_id++;

	// type
	intlocation = (int*)(&m1[4]);
	*intlocation = type;
	return m1;

}

DWORD WINAPI readThread(LPVOID lpParameter)
{
	unsigned int& myCounter = *((unsigned int*)lpParameter);
	AS_FIELDS *asfields = ((AS_FIELDS*)lpParameter);
	int pom = 0;
	char buffer[1500];
	INIT* m = (INIT*)malloc(sizeof(INIT));
	struct sockaddr_in si_other;

	while (1) {
		int length = sizeof(asfields->b);
		if ((recvfrom(asfields->a, buffer, 1500, 0, (struct sockaddr *) &si_other, &asfields->b)) == SOCKET_ERROR) {
			//printf("nothing");
			printf("recvfrom() failed with error code : %d\n", WSAGetLastError());
		}
		if (m->type == 6) {
			printf("got a keep alive packet\n");
		}
		m = (INIT*)buffer;

		if (m->type == 7) {
			printf("got an init message\n");
			return (DWORD)m;
		}

		if (m->type == 9) {
			printf("got an change message\n");
			return (DWORD)m;
		}

	}
	return 0;
}

MESSAGE* listen_message(int s, int slen, int frag_size) {
	struct sockaddr_in si_other;
	char buf[1500];
	int recv_len;
	printf("Waiting for data...");
	fflush(stdout);

	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', 1500);

	//try to receive some data, this is a blocking call

	if ((recv_len = recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
	{
		printf("recvfrom() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	int crc = getCRC(buf, HEADER_BASIC + frag_size - 3);

	AS_FIELDS* asfieldo = (AS_FIELDS*)malloc(sizeof(AS_FIELDS));
	asfieldo->a = s;
	asfieldo->b = slen;

	DWORD myThreadID;

	//print details of the client/peer and the data received
	printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
	MESSAGE* m = (MESSAGE*)malloc(sizeof(MESSAGE));
	m->data = (char*)malloc(sizeof(char) * frag_size + 1);

	char data[1500];
	memset(data, '\0', BUFLEN);

	strncpy(data, &buf[8], frag_size);

	m = (MESSAGE*)buf;
	m->checksum = *(int*)(&buf[HEADER_BASIC + frag_size - 3]);
	m->data = data;
	//strncpy(m->data, buf[8], frag_size);
	
	// ack initialize
	char *m1 = create_packet(1, 0);
	int *intlocation = (int*)(&m1[16]);
	intlocation = (int*)(&m1[12]);
	//crc = getCRC(m1, HEADER_INIT - 4);
	//*intlocation = crc;

	if (m->checksum != crc)
		*intlocation = -1;
	else *intlocation = m->fragment_id;

	// send ACK OR NACK
	while (1)
		if (sendto(s, (CHAR*)m1, HEADER_ACK, 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d\n", WSAGetLastError());
		}
		else break;

		if (*intlocation == -1) {
			MESSAGE *m = listen_message(s, slen, frag_size);
		}
		return m;
}

INIT* listen_init(int s, int slen) {
	struct sockaddr_in si_other;
	char buf[1500];
	int recv_len;
	printf("Waiting for data...");
	fflush(stdout);

	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', BUFLEN);
	INIT* init = (INIT*)malloc(sizeof(INIT));

	int count = 1;
	//try to receive some data, this is a blocking call
	while (count <= 5) {
		if ((recv_len = recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
		{
			printf("recvfrom() failed with error code : %d\n", WSAGetLastError());
			exit(EXIT_FAILURE);
		}

		//print details of the client/peer and the data received
		printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

		init = (INIT*)buf;
		//printf("%d", init->fragment_id);

		if (int(buf[4]) != 7 && int(buf[4]) != 9) {
			printf("received a packet that wasn't an init, throwing it away.\n");
			return init;
		}

		int crc = getCRC(buf, HEADER_INIT - 4);

		// ack initialize
		char *m1 = create_packet(1, 0);
		int *intlocation = (int*)(&m1[16]);
		if (init->checksum != crc) {
			*intlocation = -1;
			printf("received a faulty packet\n");
		}
		else {
			*intlocation = *(int*)(&buf[0]);
			count = 5;
		}


		// send ACK OR NACK
		while (1)
			if (sendto(s, (CHAR*)m1, HEADER_INIT, 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d\n", WSAGetLastError());
			}
			else break;
		count++;
	}
		return init;
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
	int slen, recv_len, rc;
	char buf[1500];
	unsigned int myCounter = 0;
	DWORD myThreadID;
	WSADATA wsa;

	slen = sizeof(si_other);

	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d\n", WSAGetLastError());
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
	char *message = (char*)malloc(sizeof(char) * 1500);
	memset(message, '\0', BUFLEN);
	INIT* m = (INIT*)malloc(sizeof(INIT));
	MESSAGE* m1 = (MESSAGE*)malloc(sizeof(MESSAGE));

	AS_FIELDS* asfieldo = (AS_FIELDS*)malloc(sizeof(AS_FIELDS));
	asfieldo->a = s;
	asfieldo->b = slen;

	//keep listening for data
	while (1)
	{
		HANDLE myHandle = CreateThread(0, 0, readThread, (void*)asfieldo, 0, &myThreadID);
		LPDWORD a = 0;
		while (1) {
			DWORD result = WaitForSingleObject(myHandle, 0);
			if (result == WAIT_OBJECT_0) {
				break;
			}
			else {
				// the thread handle is not signaled - the thread is still alive
			}
		}
		m = listen_init(s, slen);
		if (m->type == 9) break;

		if (m == 0) continue;
		if (m->type == 6) printf("got a keep alive\n");
		// if the first message was a init message then start accepting/receiveing the number of messages specified by the init message
		else if (m->type == 7) {
			int packet_size = m->packet_size;
			packets = m->number_of_packets;
			counter = 0;
			memset(message, '\0', 1500);
			while (counter < packets) {
				m1 = listen_message(s, slen, packet_size);
				strcpy(message, stradd(message, m1->data));
				counter++;
			}
			printf("________________________________________\n");
			printf("number of packets: %d\npacket size: %d\nmessage: %s\n", packets, packet_size, message);
		}
		//else printf("frag. id = %d | frag. size = %d | message type = %d | data = %s\n", *fragment_id, *size, *type, data);
		fragment_id = 0;
	}

	closesocket(s);
	WSACleanup();
	getchar();
}

int change_conn(int s, struct sockaddr_in si_other, int slen) {
	MESSAGE *m = (MESSAGE*)malloc(sizeof(MESSAGE));

	m->fragment_id = 6518;
	m->type = 9;
	char buf[1500];
	char m1[1500];
	int *intlocation = (int*)(&m1[0]);
	*intlocation = m->fragment_id; // stores 3632
	intlocation = (int*)(&m1[4]);
	*intlocation = m->type;
	intlocation = (int*)(&m1[16]);
	int crc = getCRC(m1, HEADER_INIT - 4);
	*intlocation = crc;

	if (sendto(s, (CHAR*)m1, 1500, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	if (sendto(s, (CHAR*)m1, 1500, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//receive a reply and print it
	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', 1500);
	//try to receive some data, this is a blocking call
	while (1)
		if (recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
		{
			// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
		}
		else return 0;
}

unsigned int round_closest(unsigned int dividend, unsigned int divisor) {
	return (dividend + (divisor / 2)) / divisor;
}

DWORD WINAPI sendingThread(LPVOID lpParameter) {
	//printf("ahoj\n");
	unsigned int& myCounter = *((unsigned int*)lpParameter);
	AS_FIELDS *asfields = ((AS_FIELDS*)lpParameter);
	int pom = 0;
	char buffer[1024];
	INIT* m = (INIT*)malloc(sizeof(INIT));
	while (1) {
		int length = sizeof(asfields->b);
		char *m1 = create_packet(6, 0);

		Sleep(5000);

		if (sendto(asfields->a, (CHAR*)m1, 1500, 0, (struct sockaddr *) &asfields->si_other, asfields->b) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d\n", WSAGetLastError());
		}
		else printf("sent a keep alive packet\n");

		if (m->type == 6) {
			printf("well met\n");
			break;
		}
	}
	return 0;
}

char *send_faulty_packet(int s, struct sockaddr_in si_other, int slen) {
	char buf[1500];
	char *m1 = create_packet(7, 0);
	int *intlocation = (int*)(&m1[16]);
	*intlocation = -1;
	int fragment_id = (int)buf[0];
	if (sendto(s, (CHAR*)m1, 0 + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	if (sendto(s, (CHAR*)m1, 0 + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	if (recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
	{}
	printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

	ACK*m2 = (ACK*)malloc(sizeof(ACK));
	intlocation = (int*)(&buf[16]);
	m2->checked_fragment_id = *intlocation;
	if (m2->checked_fragment_id == fragment_id) {
	}
	else {
		printf("faulty packet sent successfuly\n");
	}
	return m1;
}

char *doimplementacia(int s, struct sockaddr_in si_other, int slen) {
	char buf[1500];
	char *m1 = create_packet(7, 0);
	int *intlocation = (int*)(&m1[16]);
	*intlocation = -1;
	int fragment_id = (int)buf[0];
	if (sendto(s, (CHAR*)m1, 0 + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	if (sendto(s, (CHAR*)m1, 0 + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	int count = 1;
	while (count < 6) {
		if (recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
		{
		}
		printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

		ACK*m2 = (ACK*)malloc(sizeof(ACK));
		intlocation = (int*)(&buf[16]);
		m2->checked_fragment_id = *intlocation;
		if (m2->checked_fragment_id == fragment_id) {
		}
		else {
			if (sendto(s, (CHAR*)m1, 0 + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d\n", WSAGetLastError());
				exit(EXIT_FAILURE);
			}
			count++;
			printf("faulty packet sent successfuly\n");
		}
		if (count > 5) {
			printf("sending good packet now\n");
			intlocation = (int*)(&m1[16]);
			int crc = getCRC(m1, HEADER_INIT - 4);
			*intlocation = crc;
		}
	}


	return m1;
}

void send_text(int s, struct sockaddr_in si_other, int slen) {
	int frag_size, count, i = 0;
	char message[1500], buf[1500];
	DWORD myThreadID;

	printf("Enter message : \n");
	//getchar();
	fgets(message, 1500, stdin);

	printf("Set the size of fragments\n");
	scanf("%d", &frag_size);
	count = strlen(message);


	char *m1 = create_packet(7, 0);
	INIT *init = (INIT*)m1;
	int *intlocation = (int*)(&m1[8]);
	*intlocation = round_closest(count, frag_size);
	intlocation = (int*)(&m1[12]);
	*intlocation = frag_size;
	intlocation = (int*)(&m1[16]);
	int crc = getCRC(m1, HEADER_INIT - 4);
	*intlocation = crc;

	if (sendto(s, (CHAR*)m1, frag_size + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	if (sendto(s, (CHAR*)m1, frag_size + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
	{
		printf("sendto() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	AS_FIELDS* asfieldo = (AS_FIELDS*)malloc(sizeof(AS_FIELDS));
	asfieldo->a = s;
	asfieldo->b = slen;
	asfieldo->si_other = si_other;
	//HANDLE myHandle = CreateThread(0, 0, sendingThread, (void*)asfieldo, 0, &myThreadID);


	// receive an ACK from server
	//clear the buffer by filling null, it might have previously received data
	memset(buf, '\0', 1500);
	//try to receive some data, this is a blocking call
	while (1) {
		if (recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
		{
			continue;
			// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
		}
		printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

		ACK*m2 = (ACK*)malloc(sizeof(ACK));
		int *intlocation = (int*)(&buf[16]);
		m2->checked_fragment_id = *intlocation;
		if (m2->checked_fragment_id == init->fragment_id) {
			break;
		}
		else {
			printf("faulty packet, need to send it again\n");
			if (sendto(s, (CHAR*)m1, frag_size + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d\n", WSAGetLastError());
				exit(EXIT_FAILURE);
			}
		}
	}

	while (count > 0) {
		count -= frag_size;
		memset(m1, '\0', 1500);
		char *m1;
		// create a basic fragment
		m1 = create_packet(1, frag_size);
		// copy the text message
		strncpy((char*)&m1[8], message + i * frag_size, frag_size);
		// set crc
		unsigned char message[3] = { 0x83, 0x01, 0x00 };
		int crc = getCRC(m1, HEADER_BASIC + frag_size - 3);
		intlocation = (int*)(&m1[HEADER_BASIC + frag_size - 3]);
		*intlocation = crc;
		i++;

		//send the message
		if (sendto(s, (CHAR*)m1, frag_size + HEADER_BASIC, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d\n", WSAGetLastError());
			exit(EXIT_FAILURE);
		}

		// receive an ACK from server
		//clear the buffer by filling null, it might have previously received data
		memset(buf, '\0', 1500);
		//try to receive some data, this is a blocking call
		while (1) {
			if (recvfrom(s, buf, 1500, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
			{
				continue;
				// printf("recvfrom() failed with error code : %d" , WSAGetLastError());
			}
			printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
			char *m2;
			// create a basic fragment
			m2 = create_packet(1, frag_size);
			//strcpy(m2, create_packet(1, 0));

			int *intlocation = (int*)(&buf[12]);
			int checked_fragment_id = *intlocation;
			if (checked_fragment_id == *(int*)(&m1[0])) {
				printf("packet was received by server successfuly\n");
				break;
			}
			else {
				printf("faulty packet, need to send it again\n");
				if (sendto(s, (CHAR*)m2, frag_size + HEADER_INIT, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
				{
					printf("sendto() failed with error code : %d", WSAGetLastError());
					exit(EXIT_FAILURE);
				}
			}
		}
	}
}

int client() {
	/*
	Simple udp client
	*/
	struct sockaddr_in si_other;
	int s, slen = sizeof(si_other);
	char buf[1500];
	char message[BUFLEN];
	WSADATA wsa;
	char ip_address[20];

	printf("input the IP address, for default press d\n");
	scanf("%s", ip_address);
	if (strcmp(ip_address, "d") == 0)
		strcpy(ip_address, SERVER);

	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	printf("Initialised.\n");

	//create socket
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
	{
		printf("socket() failed with error code : %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//setup address structure
	memset((char *)&si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	si_other.sin_addr.S_un.S_addr = inet_addr(ip_address);

	AS_FIELDS* asfieldo = (AS_FIELDS*)malloc(sizeof(AS_FIELDS));
	asfieldo->a = s;
	asfieldo->b = slen;
	asfieldo->si_other = si_other;
	DWORD myThreadID, dwExit= 0;
	HANDLE myHandle = CreateThread(0, 0, sendingThread, (void*)asfieldo, 0, &myThreadID);

	char c;
	getchar();

	do {
		// menu
		printf("CLIENT MENU:\n");
		printf("t - text message:\n");
		printf("c - change connection:\n");
		printf("f - send faulty packet:\n");
		printf("d - doimplementacia:\n");
		printf("e - exit program:\n");
		c = getchar();
		getchar();
		switch (c) {
		case 't':
			TerminateThread(myHandle, dwExit);
			send_text(s, si_other, slen);
			myHandle = CreateThread(0, 0, sendingThread, (void*)asfieldo, 0, &myThreadID);
			continue;
		case 'c':
			TerminateThread(myHandle, dwExit);
			change_conn(s, si_other, slen);
			c = 'e';
			break;
		case 'f':
			TerminateThread(myHandle, dwExit);
			send_faulty_packet(s, si_other, slen);
			myHandle = CreateThread(0, 0, sendingThread, (void*)asfieldo, 0, &myThreadID);
			continue;
		case 'd':
			TerminateThread(myHandle, dwExit);
			doimplementacia(s, si_other, slen);
			myHandle = CreateThread(0, 0, sendingThread, (void*)asfieldo, 0, &myThreadID);
			continue;
		case 'e':
			return 1;
		}
	} while (c != 'e');
	
	closesocket(s);
	WSACleanup();
	return 0;
}


int main() {
	printf("client or server?\n");
	char c;
	c = getchar();
	switch (c) {
	case 's':
		while (1) {
			server();
			if (client() == 1) break;
		}
	case 'c':
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
