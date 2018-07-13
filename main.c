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

static uint32_t get_ip_address(const char *section, const char *key, uint32_t _default)
{
	const char *ip_address = ini_get(config, section, key);
	if (ip_address)
		return htonl(inet_addr(ip_address));

	return _default;
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

	if (config != NULL)
	{
		printf("Load config.ini\n");
		ini_sget(config, "dns", "dns_port", "%u", &configuration.dns_port);

		configuration.local_address = get_ip_address("dns", "dns_local", 0x00);
		configuration.remote_address = get_ip_address("dns", "dns_server", 0x08080808);
		configuration.redirect_address = get_ip_address("blacklist", "redirect", 0xFFFFFFFF);
		get_list();

		ini_free(config);
	}
	else
		printf("could not find config.ini, loading default\n");

	printf("dns server local %u.%u.%u.%u:%u \n", (uint8_t)(configuration.local_address >> 24), (uint8_t)(configuration.local_address >> 16), (uint8_t)(configuration.local_address >> 8), (uint8_t)configuration.local_address, configuration.dns_port);
	printf("dns server remote %u.%u.%u.%u \n", (uint8_t)(configuration.remote_address >> 24), (uint8_t)(configuration.remote_address >> 16), (uint8_t)(configuration.remote_address >> 8), (uint8_t)configuration.remote_address);
	printf("redirect ip %u.%u.%u.%u \n", (uint8_t)(configuration.redirect_address >> 24), (uint8_t)(configuration.redirect_address >> 16), (uint8_t)(configuration.redirect_address >> 8), (uint8_t)configuration.redirect_address);

	printf("\n");

	pthread_create(&proxy_dns, NULL, start_proxy_dns, NULL);

	while(1)
	{}

	return 0;
}
