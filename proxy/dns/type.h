#pragma once

#include <stdint.h>

struct DNS_Flags
{
	unsigned QR:1;					///< Тип сообщения
	unsigned opcode:4;				///< Код операции
	unsigned AA:1;					///< Авторитетный ответ
	unsigned TC:1;					///< Обрезано
	unsigned RD:1;					///< Требуется рекурсия
	unsigned RA:1;					///< Рекурсия возможна

	unsigned NUL:3;					///< Резерв
	unsigned rcode:4;				///< Код возврата
};

struct DNS_Request
{
	char *Request_Name;
	uint16_t Request_Type;
	uint16_t Request_Class;
};

struct DNS_Answer
{
	uint16_t Name_Offset;
	uint16_t Type;
	uint16_t Class;
	uint32_t TTL;

	uint16_t Length;
	uint8_t *Data;
};

struct DNS_Format
{
	uint16_t Identification;
	struct DNS_Flags Flags;

	uint16_t Queries_Size;
	uint16_t Answers_Size;
	uint16_t Authority_Size;
	uint16_t Additionals_Size;

	struct DNS_Request *Queries;
	struct DNS_Answer *Answers;

	uint8_t *Other;
};
