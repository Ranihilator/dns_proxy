#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include "proxy/proxy.h"

extern pthread_t proxy_dns;

volatile uint8_t work = 0xFF;

void signal_handler(int _signal)
{
	work = 0;
	printf("KILL\n");
	pthread_join(proxy_dns, NULL);

	exit(_signal);
}
