#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <arpa/inet.h>

#include <getopt.h>

#include "proxy/proxy.h"
#include "ini/src/ini.h"

void signal_handler(int _signal);

pthread_t proxy_dns;
struct Proxy_Configuration configuration =
{
	.dns_port = 53,
	.local_address = 0x00000000,
	.remote_address = 0x08080808,
	.redirect_address = 0xFFFFFFFF,
	.size = 0,
	.list = NULL
};

ini_t *config;

static uint32_t get_ip_address(const char *section, const char *key)
{
	const char *ip_address = ini_get(config, section, key);
	if (ip_address)
		return inet_addr(ip_address);

	return 0x00;
}

static void get_list()
{
	ini_sget(config, "blacklist", "size", "%u", &configuration.size);

	if (configuration.size == 0)
		return;

	configuration.list = (char **)malloc(configuration.size * sizeof(char *));

	if (configuration.list == NULL)
		return;

	for (uint32_t i = 0; i < configuration.size; ++i)
	{
		char digit[32];
		memset(digit, 0, 32);
		snprintf(digit, 32, "list%u", i);

		const char *node = ini_get(config, "blacklist", digit);
		if (node)
		{
			size_t node_size = strlen(node);
			configuration.list[i] = (char *)malloc((node_size + 1) * sizeof(char));

			if (configuration.list[i] == NULL)
				break;

			strncpy(configuration.list[i], node, node_size);
			configuration.list[i][node_size] = 0x00;
		}
	}
}

int main(int argc, char **argv)
{
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);

	config = ini_load("config.ini");

	ini_sget(config, "dns", "dns_port", "%u", &configuration.dns_port);

	configuration.local_address = get_ip_address("dns", "dns_local");
	configuration.remote_address = get_ip_address("dns", "dns_server");
	configuration.redirect_address = get_ip_address("blacklist", "redirect");
	get_list();

	DNS_Free();

	ini_free(config);

	pthread_create(&proxy_dns, NULL, start_proxy_dns, NULL);

	while(1)
	{}
	return 0;
}
