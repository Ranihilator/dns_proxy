#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct DNS_Format dns;

static uint32_t Get_DNS_Domain_Name_Size(uint8_t *data, uint32_t size, uint32_t pos)
{
	uint32_t dns_size = 0;
	uint32_t dns_pos = 0;
	uint32_t dns_current_size = 0;

	if (data == NULL || size == 0)
		return 0;

	dns_current_size = data[0];

	if (pos == 1)
		return data[0];

	while (dns_current_size != 0)
	{
		dns_size += dns_current_size;
		dns_pos++;
		dns_current_size = data[dns_pos + dns_size];

		if (dns_current_size > size)
			return 0;

		if (pos == 0)
			continue;

		if (pos - 1 == dns_pos)
		{
			if (dns_current_size == 0)
				break;

			return dns_current_size;
		}
	}
	dns_size += dns_pos;

	return dns_size;
}

void DNS_Free(struct DNS_Format* format)
{
	if (format == NULL)
		return;

	for (uint32_t i = 0; i < dns.Request_Size; ++i)
	{
		if (dns.Queries == NULL)
			return;

		free(dns.Queries[i].Request_Name);

		free(dns.Queries);
	}
}

struct DNS_Format* DNS_DeSerialize(uint8_t *data, uint32_t size)
{
	const uint8_t start_data_field = 12;

	if (data == NULL || size == 0)
		return NULL;

	if (size < start_data_field)
		return NULL;

	dns.Identification = data[0] << 8;
	dns.Identification |= data[1];

	dns.Flags.QR = (data[2] & 0x80) >> 7;
	dns.Flags.opcode = (data[2] & 0x78) >> 3;
	dns.Flags.AA = (data[2] & 0x04) >> 2;
	dns.Flags.TC = (data[2] & 0x02) >> 1;
	dns.Flags.RD = (data[2] & 0x01);

	dns.Flags.RA = (data[3] & 0x80) >> 7;
	dns.Flags.NUL = (data[3] & 0x70) >> 4;
	dns.Flags.rcode = (data[3] & 0x0F);

	dns.Request_Size = data[4] << 8;
	dns.Request_Size |= data[5];

	dns.Answer_Size = data[6] << 8;
	dns.Answer_Size |= data[7];

	dns.Access_Size = data[8] << 8;
	dns.Access_Size |= data[9];

	dns.Addons_Size = data[10];
	dns.Addons_Size |= data[11];

	if (dns.Request_Size == 0)
		return NULL;

	dns.Queries = (struct DNS_Request *)malloc(dns.Request_Size * sizeof(struct DNS_Request));

	if (dns.Queries == NULL)
		return NULL;

	uint32_t domain_size = Get_DNS_Domain_Name_Size(&data[start_data_field], size - start_data_field, 0);

	if (domain_size == 0)
		return NULL;

	for (uint32_t i = 0; i < dns.Request_Size; ++i)
	{
		dns.Queries[i].Request_Name = (char *)malloc(domain_size * sizeof(char));

		if (dns.Queries[i].Request_Name == NULL)
			return NULL;

		uint32_t j = 0;
		uint32_t size = 0;
		uint32_t current_domain_size = 0;
		while (current_domain_size != domain_size)
		{
			size = Get_DNS_Domain_Name_Size(&data[start_data_field], size - start_data_field, ++j);

			strncpy((char*)&dns.Queries[i].Request_Name[current_domain_size], (char*)&data[start_data_field + 1 + current_domain_size], size);
			dns.Queries[i].Request_Name[size + current_domain_size++] = '.';

			current_domain_size += size;
		}
		dns.Queries[i].Request_Name[current_domain_size - 1] = 0x00;
		dns.Queries[i].Request_Type = data[start_data_field + current_domain_size + 1] << 8;
		dns.Queries[i].Request_Type |= data[start_data_field + current_domain_size + 2];

		dns.Queries[i].Request_Class = data[start_data_field + current_domain_size + 3] << 8;
		dns.Queries[i].Request_Class |= data[start_data_field + current_domain_size + 4];
	}

	return &dns;
}
