#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "dns_parser.h"
#include "../utils/buffer.h"

#define QTYPE_SIZE 2
#define QCLASS_SIZE 2
#define QCLASS_IN_CODE 0x0100	// Obs: Uses big endian

struct dns_query{
	dns_header header;
	uint8_t question[];
};

typedef enum {
	DNS_HEADER_STATE,
	DNS_QUESTION_STATE,
	DNS_ANSWER_STATE,
	DNS_FINISHED_STATE,
	DNS_INVALID_STATE
} dns_parse_state;

struct parser_context {
	dns_parse_state state;
	size_t qcount;
	size_t acount;
};

uint8_t dns_get_reply_code(uint16_t flags){
	return flags & 0x000F;
}

uint16_t get_qtype_code(dns_qtype type){
	switch (type) {
		case DNS_QTYPE_A:
			return 0x0100;
		case DNS_QTYPE_AAAA:
			return 0x1c00;
		default:
			return 0;
	}
}

size_t get_next_name(const char * name){
	size_t i = 0;
	while (name[i] != '.' && name[i] != 0) i++;
	return i;
}

dns_query_bytes create_dns_query(dns_question question, size_t *bytes) {
	size_t qname_len = strlen(question.qname);
	struct dns_query * query = malloc(sizeof(dns_header) + qname_len + 2 + QTYPE_SIZE + QCLASS_SIZE);
	if(query == NULL)
		return NULL;
	*bytes = sizeof(dns_header) + qname_len + 2 + QTYPE_SIZE + QCLASS_SIZE;

	// Set Header Section
	query->header.id = 0;
	query->header.flags = 0x2001; //Flags: QR=0; Opcode=0000; AA=0; TC=0; RD=1; RA=0; Z=010; RCODE=0000;
	query->header.qdcount = 0x0100;
	query->header.ancount = 0;
	query->header.nscount = 0;
	query->header.arcount = 0;

	// Set Question Section
	uint8_t * question_position = query->question;
	//	--Set Qname
	size_t currentNameSize = 0;
	while (currentNameSize < qname_len){
		size_t nextName = get_next_name(question.qname + currentNameSize );
		memcpy(question_position + 1, question.qname + currentNameSize, nextName);
		*question_position = (char)nextName;
		currentNameSize += nextName + 1;
		question_position += nextName + 1;
	}
	*question_position = 0; // NULL Ended

	// --Set Qtype
	uint16_t * qtype_ptr = (uint16_t*)(question_position + 1);
	*qtype_ptr = get_qtype_code(question.qtype);

	// --Set Qclass
	uint16_t * qclass_ptr = (uint16_t*)(question_position + 1 + QTYPE_SIZE);
	*qclass_ptr = QCLASS_IN_CODE;

	return (dns_query_bytes) query;
}

// Consumes a 16bit attribute using buffer (which only consumes 8bits)
int consume_attribute(buffer * buf, uint16_t * attribute_ptr){
	uint8_t bytes[2];
	if(!buffer_can_read(buf))
		return -1;
	bytes[0] = buffer_read(buf);
	if(!buffer_can_read(buf))
		return -1;
	bytes[1] = buffer_read(buf);

	*attribute_ptr = bytes[0]<<8 | bytes[1];
	return 0;
}

int parse_dns_header(buffer * buf, dns_header * header){
	int error = 0;
	error += consume_attribute(buf, &header->id);
	error += consume_attribute(buf, &header->flags);
	error += consume_attribute(buf, &header->qdcount);
	error += consume_attribute(buf, &header->ancount);
	error += consume_attribute(buf, &header->nscount);
	error += consume_attribute(buf, &header->arcount);
	return error;
}

int ignore_name_label(buffer* buf){
	uint8_t byte = buffer_read(buf);

	if(byte >> 6 == 3){		// Ignore label pointers to other names
		buffer_read(buf);
		return 0;
	}
	while(byte != 0){
		if(buffer_can_read(buf))
			byte = buffer_read(buf);
		else
			return -1;
	}

	return 0;
}

int parse_name_label(buffer* buf, char ** name){
	char temp_name[256];
	size_t size = 0;
	uint8_t byte = buffer_read(buf);

	if(byte >> 6 == 3){		// Ignore label pointers to other names
		buffer_read(buf);
		return 0;
	}

	size_t len = byte;
	size += len;
	for(int i = 0; byte != 0 && buffer_can_read(buf); i++){
		byte = buffer_read(buf);
		if(byte != 0) {
			if (len == 0) {
				if(byte >> 6 == 3){		// Ignore label pointers to other names
					buffer_read(buf);
					temp_name[i] = byte;
					break;
				}
				len = byte;
				temp_name[i] = '.';
				size += len + 1;
			} else {
				temp_name[i] = byte;
				len--;
			}
		} else{
			temp_name[i] = byte;
		}

	}

	if(len != 0)
		return -1;

	*name = malloc(strlen(temp_name) + 1);
	if(*name != NULL)
		strcpy(*name, temp_name);

	return 0;
}

int parse_answer_type(buffer * buf, dns_qtype * type){
	uint16_t value;
	int error = consume_attribute(buf, &value);
	switch (value) {
		case 1:
			*type = DNS_QTYPE_A;
			break;
		case 5:
			*type = DNS_QTYPE_CNAME;
			break;
		case 28:
			*type = DNS_QTYPE_AAAA;
			break;
		default:
			*type = DNS_QTYPE_UNSUPPORTED;
			break;
	}
	return error;
}

int parse_answer_class(buffer * buf, dns_qclass * class){
	uint16_t value;
	int error = consume_attribute(buf, &value);
	switch (value) {
		case 1:
			*class = DNS_QCLASS_IN;
			break;
		default:
			*class = DNS_QCLASS_UNSUPPORTED;
			break;
	}
	return error;
}

int parse_ip(buffer * buf, dns_rdata *out, dns_qtype type)
{
	size_t ip_bytes_len;
	switch (type) {

		case DNS_QTYPE_A:
			ip_bytes_len = 4;
			break;
		case DNS_QTYPE_AAAA:
			ip_bytes_len = 16;
			break;
		default:
			return -1;
	}

	uint8_t ip[ip_bytes_len];
	for(size_t i = 0; i < ip_bytes_len && buffer_can_read(buf); i++){
		ip[i] = buffer_read(buf);
	}

	memcpy(out, &ip, ip_bytes_len);
	return 0;
}

int parse_answer_rdata(buffer * buf, dns_rdata * rdata, dns_qtype type){
	switch (type) {
		case DNS_QTYPE_A:
		case DNS_QTYPE_AAAA:
			parse_ip(buf, rdata, type);
			break;
		case DNS_QTYPE_CNAME:
			parse_name_label(buf, &rdata->cname);
			break;
		case DNS_QTYPE_UNSUPPORTED:
			break;
		default:
			return -1;
	}
	return 0;
}

int ignore_dns_question(buffer * buf){
	if(ignore_name_label(buf) < 0)
		return -1;
	buffer_read_adv(buf, QTYPE_SIZE + QCLASS_SIZE); // Ignore QClass & QType
	return 0;
}

int parse_dns_answer(buffer * buf, dns_rr * answer){
	int error = 0;
	error += parse_name_label(buf, &answer->name);
	if(error < 0)
		return error;
	error += parse_answer_type(buf, &answer->type);
	if(error < 0)
		return error;
	error += parse_answer_class(buf, &answer->class);
	if(error < 0)
		return error;
	buffer_read_adv(buf, 6); 	// Ignore TTL & rdlength
	error += parse_answer_rdata(buf, &answer->rdata, answer->type);
	return error;
}

dns_parse_state consume_dns_section(buffer * buf, dns_response * response, struct parser_context * pc){
	switch (pc->state) {

		case DNS_HEADER_STATE:
			if(parse_dns_header(buf, &response->header) < 0)
				return DNS_INVALID_STATE;
			if( dns_get_reply_code(response->header.flags) == 3)
				return DNS_FINISHED_STATE;
			pc->qcount = 0;
			pc->acount = 0;
			response->answer = calloc(sizeof (dns_rr), response->header.ancount);
			return DNS_QUESTION_STATE;
		case DNS_QUESTION_STATE:
			if(response->header.qdcount > pc->qcount){
				if(ignore_dns_question(buf) < 0)
					return DNS_INVALID_STATE;
				pc->qcount--;
			}
			return response->header.qdcount > pc->qcount ? DNS_QUESTION_STATE : DNS_ANSWER_STATE;
		case DNS_ANSWER_STATE:
			if(response->header.ancount > pc->acount){
				if(parse_dns_answer(buf, response->answer + pc->acount) < 0)
					return DNS_INVALID_STATE;
				pc->acount++;
			}
			return response->header.ancount > pc->acount ? DNS_ANSWER_STATE : DNS_FINISHED_STATE;
		case DNS_FINISHED_STATE:
			return DNS_FINISHED_STATE;
		case DNS_INVALID_STATE:
		default:
			return DNS_INVALID_STATE;
	}
}

dns_response * parse_dns_response(dns_response_bytes response_packet, size_t size) {
	buffer buf;
	buffer_init(&buf, size, (uint8_t *) response_packet);
	buffer_write_adv(&buf, size);

	dns_response * response = calloc(1, sizeof (dns_response));
	if(response == NULL) {
	    return NULL;
	}

	struct parser_context pc = {DNS_HEADER_STATE, 0, 0};

	while (pc.state != DNS_INVALID_STATE && pc.state != DNS_FINISHED_STATE)
		pc.state = consume_dns_section(&buf, response, &pc);

	if(pc.state == DNS_INVALID_STATE) {
	    free(response);
	    response = NULL;
        return NULL;
    }

	return response;
}

void free_dns_response(dns_response* response) {
	if(response != NULL) {
	    if(response->answer != NULL) {
            for (int i = 0; i < response->header.ancount; i++) {
                if (response->answer[i].name != NULL)
                    free(response->answer[i].name);
                if (response->answer[i].type == DNS_QTYPE_CNAME && response->answer->rdata.cname != NULL)
                    free(response->answer[i].rdata.cname);
            }
            free(response->answer);
	    }
        free(response);
        response = NULL;
	}
}

void free_dns_query(dns_query_bytes query) {
	if(query != NULL)
		free(query);
}
