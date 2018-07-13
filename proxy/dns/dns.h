#pragma once

#include "type.h"

enum DNS_STATUS
{
	BLOCK_DNS,
	PASS_DNS,
	REDIRECT_DNS,
};

struct DNS_Format* DNS_DeSerialize(uint8_t *data, uint32_t size);
uint32_t DNS_Serialize(uint8_t *data, uint32_t max);

void DNS_Free();
