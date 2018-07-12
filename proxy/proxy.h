#pragma once

#include "dns/dns.h"

struct Proxy_Configuration
{
	uint16_t dns_port;
	uint32_t local_address;
	uint32_t remote_address;
	uint32_t redirect_address;

	uint32_t size;
	char **list;
};

void* start_proxy_dns(void *param);
