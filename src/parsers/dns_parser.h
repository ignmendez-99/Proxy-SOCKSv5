#ifndef PC_2020B_6_DNS_PARSER_H
#define PC_2020B_6_DNS_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

typedef enum {
	DNS_QTYPE_A,
	DNS_QTYPE_AAAA,
	DNS_QTYPE_CNAME,
	DNS_QTYPE_UNSUPPORTED
} dns_qtype;

typedef enum {
	DNS_QCLASS_IN,
	DNS_QCLASS_UNSUPPORTED
} dns_qclass;

typedef struct {
	char * qname;
	dns_qtype qtype;
} dns_question ;

/**
 * Structure for dns header section.
 * Flags attribute is composed by the following bits
 * 	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
typedef struct {
	uint16_t 	id;
	uint16_t 	flags;
	uint16_t 	qdcount;
	uint16_t 	ancount;
	uint16_t 	nscount;
	uint16_t 	arcount;
} dns_header ;

typedef union {
	struct in_addr ipv4;
	struct in6_addr ipv6;
	char * cname;
} dns_rdata;

typedef struct {
	char * 			name;
	dns_qtype 		type;
	dns_qclass 		class;
	dns_rdata rdata;
} dns_rr;

typedef struct {
	dns_header 		header;
	dns_rr *	 	answer;
} dns_response;

typedef uint8_t * dns_query_bytes;
typedef uint8_t * dns_response_bytes;


/** TODO: Accept multiple questions
 * Creates a DNS Query. Uses Heap
 * @param question Query question
 * @param bytes Size of DNS Query
 * @return Returns pointer to memory allocated for DNS Query. Must be freed.
 */
dns_query_bytes create_dns_query(const dns_question question, size_t * bytes);


/**
 * Parses DNS Response. Uses Heap
 * @param dns_data
 * @param bytes
 * @return Returns pointer to response structure. Must be freed.
 */
dns_response * parse_dns_response(dns_response_bytes dns_data, size_t size);

/**
 * Free DNS Response.
 * @param response dns_response
 */
void free_dns_response(dns_response * response);

uint8_t dns_get_reply_code(uint16_t flags);

/**
 * Free DNS Query.
 * @param response dns_query_bytes
 */
void free_dns_query(dns_query_bytes query);

#endif //PC_2020B_6_DNS_PARSER_H
