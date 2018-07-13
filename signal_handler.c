#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "proxy/proxy.h"
#include "ini/src/ini.h"

extern pthread_t proxy_dns;
extern struct Proxy_Configuration configuration;

volatile uint8_t work = 0xFF;

void signal_handler(int _signal)
{
	work = 0;
	printf("KILL\n");
	pthread_join(proxy_dns, NULL);

	for (uint32_t i = 0; i < configuration.size; ++i)
		free(configuration.list[i]);

	configuration.size = 0;
	free(configuration.list);

	exit(_signal);
}
