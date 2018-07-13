/*!
\file
\brief DNS Frame Parser Header
*/

#pragma once

#include "type.h"

/*!
\brief Parse dns frame from binary sequency and fill the \see DNS_Format struct
\param[in] data - pointet to the data
\param[in] size - data size
\return DNS_Format pointer, or return NULL if parser failed
*/
struct DNS_Format* DNS_DeSerialize(uint8_t *data, uint32_t size);

/*!
\brief Generate binary sequency from \see DNS_Format struct
\param[out] data - pointer to the data
\param[in] max - max capacity of data from pointer
\return real size
*/
uint32_t DNS_Serialize(uint8_t *data, uint32_t max);

/*!
\brief Find the dns text
\param[in] name - text data
\return finded text
*/
const char* DNS_Find_Queries(const char* name);

/*!
\brief Remove Queries node to domain text \see DNS_Format struct
\param[in] name - domain text in normal mode (example ya.ru)
*/
void DNS_Remove_Queries(const char* name);

/*!
\brief Insert Answer node to redirect dns \see DNS_Format struct
\param[in] name - domain text in normal mode (example ya.ru)
\param[in] ip_address - ip address to redirect
*/
void DNS_Redirect_Answers(const char* name, uint32_t ip_address);

/*!
\brief Finish work with parser and clean \see DNS_Format struct
*/
void DNS_Free();
