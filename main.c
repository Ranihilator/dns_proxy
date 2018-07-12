#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>


#include <getopt.h>

#include "proxy/proxy.h"

void signal_handler(int _signal);

pthread_t proxy_dns;

int main(int argc, char **argv)
{
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);

	pthread_create(&proxy_dns, NULL, start_proxy_dns, NULL);



	/*while ((result = getopt(argc, argv, "P:p:c:")) != -1)
	{
		switch (result)
		{
			int s;
			case 'P':
				proxy_configuration.dns_port = atoi(optarg);
				break;

			case 'c':
				s = getaddrinfo(optarg, "53" , &proxy_configuration.hints, &proxy_configuration.result);
				if (s != 0)
				{
					fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
					exit(EXIT_FAILURE);
				}
				break;

			case '?':
				printf("Usage dns_proxy [ parameters ]/n");
				printf("/n");
				printf("Parameters:/n");
				printf("-P, DNS server port, Default 53/n");
				printf("-c, DNS proxy client connection /n");
				break;
		};
	};
*/

	while(1)
	{
	}

	return 0;
}
