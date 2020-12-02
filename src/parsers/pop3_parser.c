//
// Created by ignac on 13/11/2020.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <strings.h>
#include "pop3_parser.h"

#define USER_PASS_INIT_SIZE 16
#define COMMAND_BUF_SIZE 8
#define USER_PASS_CMD_SIZE 4 // user & pass have the same size

typedef enum {
	POP3_INIT_STATE = 0,
	POP3_COMMAND_STATE,
	POP3_SETUSERNAME_STATE,
	POP3_SETPASSWORD_STATE,
	POP3_PASSWORD_STATE,
	POP3_FINISHED_STATE
} parse_state;



void parse_server_line(const char c, login_data* login, pop3_login_parse_state * state){

	if(c == '-'){
		// -ERR
		switch (state->state) {
			case POP3_INIT_STATE:
				state->state = POP3_INIT_STATE;
				state->ignore_line = true;
				break;
			case POP3_PASSWORD_STATE:
				break;
			case POP3_COMMAND_STATE:
				state->state = POP3_COMMAND_STATE;
				state->ignore_line = true;
				break;
			case POP3_FINISHED_STATE:
				state->state = POP3_FINISHED_STATE;
				state->ignore_line = true;
				break;
			default:
				break;
		}
	}
	else if(c == '+'){
		// +OK
		switch (state->state) {
			case POP3_INIT_STATE:
			case POP3_COMMAND_STATE:
				state->state = POP3_COMMAND_STATE;
				state->ignore_line = true;
				break;
			case POP3_PASSWORD_STATE:
				break;
			case POP3_FINISHED_STATE:
				state->state = POP3_FINISHED_STATE;
				state->ignore_line = true;
				break;
			default:
				break;
		}
	}
}

void pop3_append_value(const char val, char ** dst){
	int i;
	int buf_count = 0;
	for(i = 0; (*dst) != NULL && (*dst)[i] != 0; i++){
		if(i % (USER_PASS_INIT_SIZE - 1) == 0)
			buf_count++;
	};
	if(i % (USER_PASS_INIT_SIZE - 1) == 0)
		*dst = realloc(*dst, USER_PASS_INIT_SIZE * (buf_count + 1));

	(*dst)[i] = val;
	(*dst)[i+1] = 0;
}

void reset_command_state(pop3_login_parse_state * state){
	for(int i = 0; i < COMMAND_BUF_SIZE; i++){
		state->command[i] = 0;
	}
	state->command_i = 0;
}

void parse_client_line(const char c, login_data* login, pop3_login_parse_state * state){
	if(state->state == POP3_COMMAND_STATE) {
		if (state->command_i < USER_PASS_CMD_SIZE && c != ' ') {
			state->command[state->command_i] = c;
			state->command_i++;
		} else {
			state->command[USER_PASS_CMD_SIZE] = 0;
			if (c == ' ') {
				if (strcasecmp(state->command, "user") == 0) {
					state->state = POP3_SETUSERNAME_STATE;
					if(login->user != NULL)
						login->user[0] = 0;
				} else if (strcasecmp(state->command, "pass") == 0) {
					state->state = POP3_SETPASSWORD_STATE;
					if(login->pass != NULL)
						login->pass[0] = 0;
				} else {
					state->state = POP3_COMMAND_STATE;
					state->ignore_line = true;
				}
			} else {
				state->state = POP3_COMMAND_STATE;
				state->ignore_line = c != '\n';

			}
			reset_command_state(state);
		}
	} else if(state->state == POP3_SETUSERNAME_STATE){
		if(c != '\r' && c != '\n')
			pop3_append_value(c, &login->user);
		else {
			state->state = POP3_COMMAND_STATE;
			state->ignore_line = c == '\r';
		}
	}
	else if(state->state == POP3_SETPASSWORD_STATE){
		if(c != '\r' && c != '\n')
			pop3_append_value(c, &login->pass);
		else {
			state->state = POP3_PASSWORD_STATE;
			state->ignore_line = c == '\r';
			state->validate = true;
		}
	}
}

void pop3_ignore_line(char c, pop3_login_parse_state * state){
	if(c == '\n')
		state->ignore_line = false;
}

size_t get_line(const char * buf, char * line, size_t size){
	for(size_t i = 0; i < size && i < 63; i++){
		if(buf[i] == '\r' || buf[i] == '\n'){
			line[i] = 0;
			return i+1;
		}
		line[i] = buf[i];
	}
	return 0;
}

void validate_auth(const char* buf, size_t size, pop3_login_parse_state * state, login_data * login){
	size_t i = 0;
	char line[64];
	while (i < size){
		i += get_line(buf + i, line, size);

		if(strcmp(line, "+OK Logged in.") == 0){
			login->valid = true;
			state->state = POP3_FINISHED_STATE;
		} else if(strcmp(line, "-ERR [AUTH] Authentication failed.") == 0){
			state->validate = false;
			state->state = POP3_COMMAND_STATE;
		}
	}

}

int pop3_login_parser_consume_buffer(const char *buf, size_t size, login_data *login, pop3_login_parse_state * state, communication_actor actor) {
	if(size <= 0)
		return 0;

	for(size_t i = 0; i < size; i++) {
		char c = buf[i];
		if(state->ignore_line)
			pop3_ignore_line(c, state);
		else {
			if (actor == COMMUNICATION_SERVER_SIDE) {
				parse_server_line(c, login, state);
				if(state->validate){
					validate_auth(buf + i, size - i, state, login);
				}
			}
			else if (actor == COMMUNICATION_CLIENT_SIDE) {
				parse_client_line(c, login, state);
			}
		}
	}

	return state->state == POP3_FINISHED_STATE;
}

void pop3_login_init_state(pop3_login_parse_state * state){
	state->state = POP3_INIT_STATE;
	state->ignore_line = false;
	state->validate = false;
	for (int i = 0; i < COMMAND_BUF_SIZE; i++){
		state->command[i] = 0;
	}
	state->command_i = 0;
}
