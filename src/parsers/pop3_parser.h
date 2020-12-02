#ifndef PC_2020B_6_POP3_PARSER_H
#define PC_2020B_6_POP3_PARSER_H

#include "login_def.h"

typedef struct {
	uint8_t state;
	bool ignore_line;
	bool validate;
	size_t command_i;
	char command[8];
} pop3_login_parse_state;

/**
 * Parse POP3 Protocol. Implementation only retrieves username and password.
 * @param buf Read Buffer
 * @param login	Struct with parsed information
 * @param state Parsing State
 * @param actor Is server or client
 *
 */
int pop3_login_parser_consume_buffer(const char *buf, size_t size, login_data *login, pop3_login_parse_state * state, communication_actor actor);

void pop3_login_init_state(pop3_login_parse_state * state);

#endif //PC_2020B_6_POP3_PARSER_H
