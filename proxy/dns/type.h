/*!
\file
\brief DNS Frame Type Header for parser
*/

#pragma once

#include <stdint.h>

/*!
\brief DNS Flags struct

\details One of nodes DNS data \see DNS_Format
*/
struct DNS_Flags
{
	unsigned QR:1;					///< Type message
	unsigned opcode:4;				///< Code operation
	unsigned AA:1;					///< Auth answer
	unsigned TC:1;					///< Shortcut
	unsigned RD:1;					///< Need recursive
	unsigned RA:1;					///< Recursive enable

	unsigned NUL:3;					///< Reserved
	unsigned rcode:4;				///< Return code
};

/*!
\brief DNS Request struct

\details One of nodes DNS data \see DNS_Format
*/
struct DNS_Request
{
	char *Request_Name;				///< DNS format text (example 2ya2ru) -> ya.ru
	uint16_t Request_Type;			///< DNS Type
	uint16_t Request_Class;			///< DNS Class

	uint8_t status;					///< DNS status (0 - using, 0xFF - deleted, parser will be ignored node)
};

/*!
\brief DNS Answer struct

\details One of nodes DNS data \see DNS_Format
*/
struct DNS_Answer
{
	uint16_t Name_Offset;			///< DNS Node pointer offset
	uint16_t Type;					///< DNS Type
	uint16_t Class;					///< DNS Class
	uint32_t TTL;					///< DNS Time to live

	uint16_t Length;				///< DNS Length data
	uint8_t *Data;					///< DNS Data (binary format)
};

/*!
\brief Main DNS struct

\details All DNS working Data from parser
*/
struct DNS_Format
{
	uint16_t Identification;		///< DNS Identification frame
	struct DNS_Flags Flags;			///< DNS Flags

	uint16_t Queries_Size;			///< Queries Size DNS nodes
	uint16_t Answers_Size;			///< Answers Size DNS nodes
	uint16_t Authority_Size;		///< Authority Size DNS nodes (in current version parser not used)
	uint16_t Additionals_Size;		///< Additionals Size DNS nodes (in current version parser not used)

	struct DNS_Request *Queries;	///< Queries Data
	struct DNS_Answer *Answers;		///< Answer Data

	uint8_t *Other;					///< Authority and Additionals Data (Nodes not analyze, just copy to proxy)
	uint8_t Size;					///< Size of Other data
};
