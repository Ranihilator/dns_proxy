#pragma once

#include "type.h"

struct DNS_Format* DNS_DeSerialize(uint8_t *data, uint32_t size);
uint32_t DNS_Serialize(uint8_t *data, uint32_t max);

const char* DNS_Find_Queries(const char* name);
void DNS_Remove_Queries(const char* name);
void DNS_Redirect_Answers(const char* name, uint32_t ip_address);

void DNS_Free();
