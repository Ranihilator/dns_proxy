#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>

extern volatile uint8_t work;

#define MAXBUF 4096
struct
{
	uint8_t data[MAXBUF];
	uint32_t size;
} buffer;

static void dump(const char *text)
{
	printf("%s", text);

	for (int i = 0; i < buffer.size; ++i)
		printf("0x%x ",buffer.data[i]);

	printf("\n");

	for (int i = 0; i < buffer.size; ++i)
		printf("%c ",buffer.data[i]);

	printf("\n");
}

//char message[23] = {0x4a, 0x49, 0x01, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x02, 0x79, 0x61, 0x02, 0x72, 0x75, 0x0, 0x0, 0x1c, 0x0, 0x01};

static void task(int fd_server, int fd_client)
{
	uint32_t server_len, client_len;
	struct sockaddr_in local;
	struct sockaddr_in remote;

	server_len = sizeof(local);
	client_len = sizeof(remote);

	while (work == 0xFF)
	{
		struct timeval timeout = {1, 0};
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(fd_server, &readSet);

		if (select(fd_server + 1, &readSet, NULL, NULL, &timeout) < 0)
			continue;

		if (!FD_ISSET(fd_server, &readSet))
			continue;

		buffer.size = recvfrom(fd_server, buffer.data, MAXBUF, 0, (struct sockaddr *)&local, &server_len);

		dump("Send to dns server:\n");
		sendto(fd_client, buffer.data, buffer.size, 0, (struct sockaddr*)NULL, sizeof(remote));

		struct timeval c_timeout = {1, 0};
		fd_set c_readSet;
		FD_ZERO(&c_readSet);
		FD_SET(fd_client, &c_readSet);

		if (select(fd_client + 1, &c_readSet, NULL, NULL, &c_timeout) < 0)
			continue;

		if (!FD_ISSET(fd_client, &c_readSet))
			continue;

		buffer.size = recvfrom(fd_client, buffer.data, MAXBUF, 0, (struct sockaddr*)&remote, &client_len);

		dump("Send to dns client:\n");
		sendto(fd_server, buffer.data, buffer.size, 0, (struct sockaddr *)&local, sizeof(local));
	}
}

void* start_proxy_dns(void *param)
{
	int fd_server, fd_client;
	struct sockaddr_in server_address, client_address;
	uint32_t length;

	if ((fd_server = socket( AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		printf("Server creating socket is failed %i\n", fd_server);
		exit(0);
	}

	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(53);

	if (bind(fd_server, (struct sockaddr *) &server_address, sizeof(server_address)) < 0)
	{
		printf("Error binding server port %d\n", ntohs(server_address.sin_port));
		exit(0);
	}

	length = sizeof(server_address);
	if (getsockname(fd_server, (struct sockaddr *) &server_address, &length) < 0)
	{
		printf("Error server getsockname\n");
		exit(1);
	}

	printf("DNS UDP port is %d\n", ntohs(server_address.sin_port));

	client_address.sin_addr.s_addr = inet_addr("8.8.8.8");
	client_address.sin_port = htons(53);
	client_address.sin_family = AF_INET;

	if ((fd_client = socket( AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		printf("Creating client socket is failed %i\n", fd_client);
		exit(0);
	}

	if(connect(fd_client, (struct sockaddr *)&client_address, sizeof(client_address)) < 0)
	{
		printf("\n Error : Connect Failed \n");
		exit(0);
	}

	task(fd_server, fd_client);

	printf("Finish\n");

	return NULL;
}
