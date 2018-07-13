/*!
\file
\brief DNS Frame parser
*/

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
		{
			free(dns.Queries[i].Request_Name);
			dns.Queries[i].Request_Name = NULL;
		}

		free(dns.Queries);
		dns.Queries = NULL;
	}

	if (dns.Answers != NULL)
	{
		for (uint32_t i = 0; i < dns.Answers_Size; ++i)
		{
			free(dns.Answers[i].Data);
			dns.Answers[i].Data = NULL;
		}

		free(dns.Answers);
		dns.Answers = NULL;
	}

	free(dns.Other);
	dns.Other = NULL;
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

	if (dns.Queries_Size != 0)
		dns.Queries = (struct DNS_Request *)malloc(dns.Queries_Size * sizeof(struct DNS_Request));

	if (dns.Answers_Size != 0)
		dns.Answers = (struct DNS_Answer *)malloc(dns.Answers_Size * sizeof(struct DNS_Answer));

	uint32_t domain_size = Get_DNS_Domain_Name_Size(&data[start_data_field], size - start_data_field, 0);

	if (domain_size == 0)
		return NULL;

	for (uint32_t i = 0; i < dns.Queries_Size; ++i)
	{
		dns.Queries[i].Request_Name = (char *)malloc(domain_size * sizeof(char));

		if (dns.Queries[i].Request_Name == NULL)
			return NULL;

		uint32_t j = 0;
		uint32_t s = 0;
		uint32_t current_domain_size = 0;
		while (current_domain_size != domain_size)
		{
			s = Get_DNS_Domain_Name_Size(&data[start_data_field], size - start_data_field, ++j);

			strncpy((char*)&dns.Queries[i].Request_Name[current_domain_size], (char*)&data[start_data_field + 1 + current_domain_size], s);
			dns.Queries[i].Request_Name[s + current_domain_size++] = '.';

			current_domain_size += s;
		}
		dns.Queries[i].Request_Name[domain_size - 1] = 0x00;
		dns.Queries[i].Request_Type = data[start_data_field + domain_size + 1] << 8;
		dns.Queries[i].Request_Type |= data[start_data_field + domain_size + 2];

		dns.Queries[i].Request_Class = data[start_data_field + domain_size + 3] << 8;
		dns.Queries[i].Request_Class |= data[start_data_field + domain_size + 4];

		dns.Queries[i].status = 0x00;
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
	dns.Size = size - start_other_field;

	if (dns.Other != 0)
	{
		dns.Other = (uint8_t *)malloc(dns.Size * sizeof(uint8_t));
		memcpy(dns.Other, (char*)&data[start_other_field], dns.Size);
	}

	return &dns;
}

uint32_t DNS_Serialize(uint8_t *data, uint32_t max)
{
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

	uint8_t queries_offset = 0;
	for (uint32_t i = 0; i < dns.Queries_Size; ++i)
	{
		if (dns.Queries[i].status == 0xFF)
		{
			queries_offset++;
			continue;
		}

		char name[4096];
		strcpy(name, dns.Queries[i].Request_Name);

		char* res = strtok(name, ".");

		while (res != NULL)
		{
			uint32_t s = strlen(res);

			data[size++] = s;

			strncpy((char*)&data[size], res, s);
			size += s;

			res = strtok(NULL, ".");
		}
		data[size++] = 0x00;

		data[size++] = dns.Queries[i - queries_offset].Request_Type >> 8;
		data[size++] = dns.Queries[i - queries_offset].Request_Type;

		data[size++] = dns.Queries[i - queries_offset].Request_Class >> 8;
		data[size++] = dns.Queries[i - queries_offset].Request_Class;
	}
	uint32_t quer_size = dns.Queries_Size - queries_offset;
	data[4] = quer_size >> 8;
	data[5] = quer_size;

	for (uint32_t i = 0; i < dns.Answers_Size; ++i)
	{
		data[size++] = dns.Answers[i].Name_Offset >> 8;
		data[size++] = dns.Answers[i].Name_Offset;

		data[size++] = dns.Answers[i].Type >> 8;
		data[size++] = dns.Answers[i].Type;

		data[size++] = dns.Answers[i].Class >> 8;
		data[size++] = dns.Answers[i].Class;

		data[size++] = dns.Answers[i].TTL >> 24;
		data[size++] = dns.Answers[i].TTL >> 16;
		data[size++] = dns.Answers[i].TTL >> 8;
		data[size++] = dns.Answers[i].TTL;

		data[size++] = dns.Answers[i].Length >> 8;
		data[size++] = dns.Answers[i].Length;

		for (uint32_t j = 0; j < dns.Answers[i].Length; ++j)
			data[size++] = dns.Answers[i].Data[j];
	}

	for (uint32_t i = 0; i < dns.Size; ++i)
		data[size++] = dns.Other[i];

	return size;
}

const char* DNS_Find_Queries(const char* name)
{
	if (name == NULL || dns.Queries_Size == 0)
		return NULL;

	for (uint32_t i = 0; i < dns.Queries_Size; ++i)
	{
		const char* path = strstr(dns.Queries[i].Request_Name, name);
		if (path != NULL)
			return dns.Queries[i].Request_Name;
	}

	return NULL;
}

void DNS_Remove_Queries(const char* name)
{
	if (name == NULL || dns.Queries_Size == 0)
		return;

	for (uint32_t i = 0; i < dns.Queries_Size; ++i)
	{
		const char* path = strstr(dns.Queries[i].Request_Name, name);
		if (path != NULL)
			dns.Queries[i].status = 0xFF;
	}
}

void DNS_Redirect_Answers(const char* name, uint32_t ip_address)
{
	if (dns.Queries_Size == 0)
		return;

	uint32_t count = 0;
	for (uint32_t i = 0; i < dns.Queries_Size; ++i)
	{
		const char* path = strstr(dns.Queries[i].Request_Name, name);
		if (path != NULL)
			count++;
	}

	if (count == 0)
		return;

	struct DNS_Answer *Answers = (struct DNS_Answer *)malloc((dns.Answers_Size + count) * sizeof(struct DNS_Answer));

	if (Answers == NULL)
		return;

	for (uint32_t i = 0; i < dns.Answers_Size; ++i)
	{
		Answers[i].Class = dns.Answers[i].Class;
		Answers[i].Type = dns.Answers[i].Type;
		Answers[i].Length = dns.Answers[i].Length;
		Answers[i].Name_Offset = dns.Answers[i].Name_Offset;
		Answers[i].TTL = dns.Answers[i].TTL;
		Answers[i].Data = dns.Answers[i].Data;
	}

	free(dns.Answers);
	dns.Answers = Answers;

	for (uint32_t i = dns.Answers_Size; i < dns.Answers_Size + count; i++)
	{
		Answers[i].Class = 0x01;
		Answers[i].Type = 0x01;
		Answers[i].Length = 0x04;
		Answers[i].Name_Offset = 0xc00c;
		Answers[i].TTL = 300;
		Answers[i].Data = (uint8_t *)malloc(Answers[i].Length * sizeof(uint8_t));
		Answers[i].Data[0] = ip_address >> 24;
		Answers[i].Data[1] = ip_address >> 16;
		Answers[i].Data[2] = ip_address >> 8;
		Answers[i].Data[3] = ip_address;
	}

	dns.Answers_Size += count;
}
