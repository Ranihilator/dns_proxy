/*!
\file
\brief Header proxy thread
*/
#pragma once

#include "dns/dns.h"

/*!
\brief Application configuration
*/
struct Proxy_Configuration
{
	uint16_t dns_port;					///< current dns port server
	uint32_t local_address;				///< current ip address bind server
	uint32_t remote_address;			///< remote dns server to connect proxy
	uint32_t redirect_address;			///< redirect ip address from black list

	uint32_t size;						///< size of list
	char **list;						///< blacklist
};

/*!
\brief Proxy thread start
*/
void* start_proxy_dns(void *param);
