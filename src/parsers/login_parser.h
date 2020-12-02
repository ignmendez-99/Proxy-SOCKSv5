#ifndef PC_2020B_6_LOGIN_PARSER_H
#define PC_2020B_6_LOGIN_PARSER_H

#include "login_def.h"

#include <stddef.h>
#include "http_parser.h"
#include "pop3_parser.h"

enum protocols{
	PROTOCOL_UNIDENTIFIED,
	PROTOCOL_POP3,
	PROTOCOL_HTTP,
	PROTOCOL_UNKNOWN
};

union login_parse_state {
	http_login_parse_state http;
	pop3_login_parse_state pop3;
};

typedef struct {
	bool finished;
	uint8_t protocol;
	login_data data;
	union login_parse_state parse_state;
} login_state ;

void steal_passwords(const char * buf, size_t size, login_data * data, login_state * state, communication_actor actor);

const char * get_protocol_name(login_state * state);

void free_login_state(login_state * state);

void free_login_data(login_data *login);


#endif //PC_2020B_6_LOGIN_PARSER_H
