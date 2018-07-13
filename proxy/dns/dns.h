#pragma once

#include "type.h"

struct DNS_Format* DNS_DeSerialize(uint8_t *data, uint32_t size);
void DNS_Free(struct DNS_Format* format);
