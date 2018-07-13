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

void DNS_Free()
{
	if (dns.Queries != NULL)
	{
		for (uint32_t i = 0; i < dns.Queries_Size; ++i)
			free(dns.Queries[i].Request_Name);

		free(dns.Queries);
	}

	if (dns.Answers != NULL)
	{
		for (uint32_t i = 0; i < dns.Answers_Size; ++i)
			free(dns.Answers[i].Data);

		free(dns.Answers);
	}

	free(dns.Other);
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

	dns.Queries_Size = data[4] << 8;
	dns.Queries_Size |= data[5];

	dns.Answers_Size = data[6] << 8;
	dns.Answers_Size |= data[7];

	dns.Authority_Size = data[8] << 8;
	dns.Authority_Size |= data[9];

	dns.Additionals_Size = data[10];
	dns.Additionals_Size |= data[11];

	if (dns.Queries_Size == 0)
		return NULL;

	dns.Queries = (struct DNS_Request *)malloc(dns.Queries_Size * sizeof(struct DNS_Request));
	dns.Answers = (struct DNS_Answer *)malloc(dns.Answers_Size * sizeof(struct DNS_Answer));

	if (dns.Queries == NULL && dns.Queries_Size != 0)
		return NULL;

	if (dns.Answers == NULL && dns.Answers_Size != 0)
		return NULL;

	uint32_t domain_size = Get_DNS_Domain_Name_Size(&data[start_data_field], size - start_data_field, 0);

	if (domain_size == 0)
		return NULL;

	for (uint32_t i = 0; i < dns.Queries_Size; ++i)
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
		dns.Queries[i].Request_Name[domain_size - 1] = 0x00;
		dns.Queries[i].Request_Type = data[start_data_field + domain_size + 1] << 8;
		dns.Queries[i].Request_Type |= data[start_data_field + domain_size + 2];

		dns.Queries[i].Request_Class = data[start_data_field + domain_size + 3] << 8;
		dns.Queries[i].Request_Class |= data[start_data_field + domain_size + 4];
	}

	uint32_t start_answers_field = start_data_field + domain_size + 5;
	for (uint32_t i = 0; i < dns.Answers_Size; ++i)
	{
		dns.Answers[i].Name_Offset = data[start_answers_field++] << 8;
		dns.Answers[i].Name_Offset |= data[start_answers_field++];

		dns.Answers[i].Type = data[start_answers_field++] << 8;
		dns.Answers[i].Type |= data[start_answers_field++];

		dns.Answers[i].Class = data[start_answers_field++] << 8;
		dns.Answers[i].Class |= data[start_answers_field++];

		dns.Answers[i].TTL = data[start_answers_field++] << 24;
		dns.Answers[i].TTL |= data[start_answers_field++] << 16;
		dns.Answers[i].TTL |= data[start_answers_field++] << 8;
		dns.Answers[i].TTL |= data[start_answers_field++];

		dns.Answers[i].Length = data[start_answers_field++] << 8;
		dns.Answers[i].Length |= data[start_answers_field++];

		if (dns.Answers[i].Length == 0)
			return NULL;

		dns.Answers[i].Data = (uint8_t *)malloc(dns.Answers[i].Length * sizeof(uint8_t));
		memcpy(dns.Answers[i].Data, (char*)&data[start_answers_field++], dns.Answers[i].Length);
		start_answers_field += dns.Answers[i].Length - 1;
	}

	uint32_t start_other_field = start_answers_field;
	dns.Other = (uint8_t *)malloc(start_other_field * sizeof(uint8_t));
	memcpy(dns.Other, (char*)&data[start_other_field], size - start_other_field);

	return &dns;
}

uint32_t DNS_Serialize(uint8_t *data, uint32_t max)
{
	const uint8_t start_data_field = 12;
	uint32_t size = 0;

	if (data == NULL)
		return 0;

	data[size++] = dns.Identification >> 8;
	data[size++] = dns.Identification;

	uint8_t flags = 0;

	flags = dns.Flags.QR << 7;
	flags |= dns.Flags.opcode << 6;
	flags |= dns.Flags.AA << 2;
	flags |= dns.Flags.TC << 1;
	flags |= dns.Flags.RD;
	data[size++] = flags;

	flags = dns.Flags.RA << 7;
	flags |= dns.Flags.NUL << 6;
	flags |= dns.Flags.rcode << 3;
	data[size++] = flags;

	data[size++] = dns.Queries_Size >> 8;
	data[size++] = dns.Queries_Size;

	data[size++] = dns.Answers_Size >> 8;
	data[size++] = dns.Answers_Size;

	data[size++] = dns.Authority_Size >> 8;
	data[size++] = dns.Authority_Size;

	data[size++] = dns.Additionals_Size >> 8;
	data[size++] = dns.Additionals_Size;

	return size;
}
