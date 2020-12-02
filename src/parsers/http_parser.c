#include "http_parser.h"
#include "../utils/base64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>


#define MIN_BUFFER_SIZE 2
#define AUTHORIZATION_HEADER_LEN 13
#define BASIC_AUTH_LEN 5
#define HEADER_BUF_SIZE 16
#define AUTH_BUF_INIT_SIZE 32


typedef enum {
	HTTP_INIT_STATE,
	HTTP_HEADER_STATE,
	HTTP_BODY_STATE,
	HTTP_NEWLINE_STATE,
	HTTP_FINISHED_STATE,
	HTTP_INVALID_STATE,
} response_parser_state;

typedef enum {
	HTTP_LOGIN_INIT_STATE,
	HTTP_LOGIN_HEADER_NAME_STATE,
	HTTP_LOGIN_AUTH_TYPE_STATE,
	HTTP_LOGIN_AUTH_VALUE_STATE,
	HTTP_LOGIN_FINISHED_STATE
} request_login_parser_state;

const char* get_http_version(const http_version http_version){
	switch (http_version) {
		case HTTP1:
			return "HTTP/1.0";
		case HTTP1_1:
			return "HTTP/1.1";
		case HTTP2:
			return "HTTP/2";
		default:
			return NULL;
	}
}

http_version parse_http_version(const char * version){

	const char * version_number = version + 5;
	if(strlen(version) == 6 && version_number[0] == '2' && version_number[1] ==  0)
		return HTTP2;
	if(strlen(version) == 8 && version_number[0] == '1' && version_number[1] ==  '.' && version_number[2] == '0')
		return HTTP1;
	if(strlen(version) == 8 && version_number[0] == '1' && version_number[1] ==  '.' && version_number[2] == '1')
		return HTTP1_1;

	return -1;
}

const char* get_http_method(const http_method http_method){
	switch (http_method) {
		case HTTP_GET:
			return "GET";
		case HTTP_POST:
			return "POST";
		default:
			return NULL;
	}
}

int
create_http_request(const http_request* hr, buffer * buf) {
	size_t  bytes_added = 0;
	size_t buffer_available;
	char * buffer_ptr = (char *) buffer_write_ptr(buf, &buffer_available);

	size_t buffer_initial_size = buffer_available;

	// Creates HTTP Request Base
	bytes_added = snprintf(buffer_ptr, buffer_available - 1, "%s %s %s\r\nHost: %s\r\n", get_http_method(hr->method), hr->path, get_http_version(hr->version), hr->host);
	if(bytes_added > buffer_available)
		return -1;
	buffer_write_adv(buf, bytes_added);

	// Creates all HTTP Request Headers
	http_header * current_header = hr->headers;
	while(current_header != NULL){
		buffer_ptr = (char *) buffer_write_ptr(buf, &buffer_available);
		bytes_added = snprintf(buffer_ptr, buffer_available - 1, "%s: %s\r\n", current_header->name, current_header->value);
		if(bytes_added > buffer_available)
			return -1;
		buffer_write_adv(buf, bytes_added);

		current_header = current_header->next_header;
	}

	buffer_write(buf, '\r');
	buffer_write(buf, '\n');
	// Update buffer
	buffer_ptr = (char *) buffer_write_ptr(buf, &buffer_available);
	if(hr->bode_size > buffer_available)
		return -1;
	// Adds body to HTTP Request
	memcpy(buffer_ptr, hr->body, hr->bode_size);
	buffer_write_adv(buf, hr->bode_size);

	buffer_write_ptr(buf, &buffer_available);	// Update buffer_available
	return (int)buffer_initial_size - (int)buffer_available;
}

int consume_response_line(char ** line, buffer * buf) {
	bool has_newline = false;
	size_t line_size = 0;
	size_t available_bytes;
	*line = (char *) buffer_read_ptr(buf, &available_bytes);
	for(size_t i = 0; !has_newline && i < available_bytes; i++){
		char c = (*line)[i];
		if(c == '\r' && (i+1) < available_bytes)
			c = (*line)[i + 1];
		if(c == '\n')
			has_newline = true;
		line_size++;
	}

	if(!has_newline)
		return -2;

	buffer_read_adv(buf, line_size + 1); // Doesn't advance read ptr unless new line found
	return (int)line_size;
}

response_parser_state parse_http_line(http_response *hr, char * line, struct http_parse_state * parse_state) {
	switch (parse_state->state) {
		case HTTP_INIT_STATE: {

			hr->body = NULL;
			hr->headers = NULL;
			hr->headers_size = 0;
			parse_state->current = &hr->headers;

			char version_str[10];
			int matches = sscanf(line, "%9s %d", version_str, &hr->status_code);
			hr->version = parse_http_version(version_str);
			if ((int) hr->version == -1 || matches != 2 || hr->status_code < 100 || hr->status_code >= 600)
				return HTTP_INVALID_STATE;
			return HTTP_HEADER_STATE;
		}

		case HTTP_HEADER_STATE: {
			if(line[0] == '\n' || (line[0] == '\r' && line[1] == '\n'))
				return HTTP_NEWLINE_STATE;

			(*parse_state->current) = malloc(sizeof(struct http_header));
			if((*parse_state->current) == NULL)
				return HTTP_INVALID_STATE;
			(*parse_state->current)->name = NULL;
			(*parse_state->current)->value = NULL;
			(*parse_state->current)->next_header = NULL;

			int matches = sscanf(line, "%m[^:\r\n\t]%*[:] %m[^\r\n\t]", &(*parse_state->current)->name, &(*parse_state->current)->value);
			if(matches != 2)
				return HTTP_INVALID_STATE;
			hr->headers_size++;

			if(strcasecmp((*parse_state->current)->name, "content-length") == 0)
				parse_state->content_length = atoi((*parse_state->current)->value);
			parse_state->current = &(*parse_state->current)->next_header;
			return HTTP_HEADER_STATE;
		}
		case HTTP_NEWLINE_STATE:
			return HTTP_NEWLINE_STATE;
		case HTTP_BODY_STATE:
			return HTTP_BODY_STATE;
		case HTTP_FINISHED_STATE:
			return HTTP_FINISHED_STATE;
		default:
		case HTTP_INVALID_STATE:
			return HTTP_INVALID_STATE;
	}
}

int
http_parser_consume_buffer(http_response *hr, buffer *buf, http_parse_state * parse_state) {
	char * line;
	int line_size;
	do {
		line_size = consume_response_line(&line, buf);
		parse_state->state = parse_http_line(hr, line, parse_state);
	}
	while (line_size > 0 && (parse_state->state == HTTP_INIT_STATE || parse_state->state == HTTP_HEADER_STATE) );

	if(parse_state->state == HTTP_INVALID_STATE)
		return -1;		// INVALID REQUEST

	if(line_size == -1)
		return -2; 	// LINE BUFFER INSUFFICIENT

	if(line_size == -2){
		return 1;	// PARSE UNFINISHED
	}

	if(parse_state->state == HTTP_NEWLINE_STATE){
		if(parse_state->content_length > 0){
			hr->body = malloc(parse_state->content_length);
			parse_state->body_buf = malloc(sizeof (buffer));
			buffer_init(parse_state->body_buf, parse_state->content_length, (uint8_t*)hr->body);
			parse_state->state = HTTP_BODY_STATE;
		} else{
			parse_state->state = HTTP_FINISHED_STATE;
		}
	}

	if(parse_state->state == HTTP_BODY_STATE){
		size_t read_available;
		char * read_buf = (char *)buffer_read_ptr(buf, &read_available);
		size_t write_available;
		char * write_buf = (char *)buffer_write_ptr(parse_state->body_buf, &write_available);

		size_t smallest = read_available < write_available ? read_available : write_available;
		memcpy(write_buf, read_buf, smallest);
		buffer_read_adv(buf, smallest);
		buffer_write_adv(parse_state->body_buf, smallest);

		if(!buffer_can_write(parse_state->body_buf))
			parse_state->state = HTTP_FINISHED_STATE;
	}

	if(parse_state->state == HTTP_INVALID_STATE)
		return -1;		// INVALID REQUEST
	if(parse_state->state == HTTP_FINISHED_STATE)
		return 0;

	return 1;	// PARSE UNFINISHED
}

void http_ignore_line(char c, http_login_parse_state * state){
	if(c == '\n')
		state->ignore_line = false;
}

void clear_header_buf(http_login_parse_state * state){
	for(int i = 0; i < HEADER_BUF_SIZE; i++){
		state->header_buf[i] = 0;
	}
	state->header_buf_i = 0;
}

void append_value(const char val, char ** dst){
	int i;
	int buf_count = 0;
	for(i = 0; (*dst) != NULL && (*dst)[i] != 0; i++){
		if(i % (AUTH_BUF_INIT_SIZE - 1) == 0)
			buf_count++;
	};
	if(i % (AUTH_BUF_INIT_SIZE - 1) == 0)
		*dst = realloc(*dst, AUTH_BUF_INIT_SIZE * (buf_count + 1));

	(*dst)[i] = val;
	(*dst)[i+1] = 0;
}

void http_login_consume_byte(const char c, http_login_parse_state * state){
	switch (state->state) {
		case HTTP_LOGIN_INIT_STATE:
			state->state = HTTP_LOGIN_HEADER_NAME_STATE;
			state->ignore_line = true;
			break;
		case HTTP_LOGIN_HEADER_NAME_STATE:
			if(c != ':' && state->header_buf_i < AUTHORIZATION_HEADER_LEN){
				state->header_buf[state->header_buf_i] = c;
				state->header_buf[state->header_buf_i + 1] = 0;
				state->header_buf_i++;
			} else {
				if(c == ':'){
					if(strcasecmp(state->header_buf, "authorization") == 0){
						state->state = HTTP_LOGIN_AUTH_TYPE_STATE;
					} else{
						state->state = HTTP_HEADER_STATE;
						state->ignore_line = true;
					}
				} else {
					state->state = HTTP_HEADER_STATE;
					state->ignore_line = true;
				}
				clear_header_buf(state);
			}
			break;
		case HTTP_LOGIN_AUTH_TYPE_STATE:
			if(c != '\n' && state->header_buf_i < BASIC_AUTH_LEN){
				if(c != ' '){
					state->header_buf[state->header_buf_i] = c;
					state->header_buf[state->header_buf_i + 1] = 0;
					state->header_buf_i++;
				}
			} else {
				if(state->header_buf_i == BASIC_AUTH_LEN){
					if(strcasecmp(state->header_buf, "basic") == 0){
						state->state = HTTP_LOGIN_AUTH_VALUE_STATE;
					} else{
						state->state = HTTP_HEADER_STATE;
						state->ignore_line = true;
					}
				} else {
					state->state = HTTP_HEADER_STATE;
					state->ignore_line = true;
				}
			}
			break;
		case HTTP_LOGIN_AUTH_VALUE_STATE:
			if(c != '\r' && c != '\n'){
				append_value(c, &state->header_value);
			} else{
				state->state = HTTP_LOGIN_FINISHED_STATE;
			}
	}
}

int http_login_consume_buffer(const char * buf, size_t size, login_data *login, http_login_parse_state * state, communication_actor actor){

	if(actor == COMMUNICATION_CLIENT_SIDE) {
		for (size_t i = 0; i < size && state->state != HTTP_LOGIN_FINISHED_STATE; i++) {
			char c = buf[i];
			if (state->ignore_line)
				http_ignore_line(c, state);
			else {
				http_login_consume_byte(c, state);
			}
		}

		if (state->state == HTTP_LOGIN_FINISHED_STATE && login->valid == false) {
			size_t out_size = b64_decoded_size(state->header_value);
			unsigned char user_pass[out_size];
			b64_decode(state->header_value, user_pass, out_size);
			int match = sscanf((char*)user_pass, "%m[^:\n\r\t ]%*[:]%ms", &login->user, &login->pass);
			if(match == 2) {
				login->valid = true;
				return 1;
			}
		}
	}
	return 0;
}

void http_free_login_state(http_login_parse_state * state){
	if(state->header_value != NULL)
		free(state->header_value);
}

void http_login_init_state(http_login_parse_state * state){
	state->state = HTTP_LOGIN_INIT_STATE;
	state->header_value = NULL;
	state->ignore_line = false;
	clear_header_buf(state);
}

void
free_http_parse_state(http_parse_state * parse_state){
	if(parse_state != NULL) {
		if(parse_state->body_buf != NULL){
			free(parse_state->body_buf);
		}
		parse_state = NULL;
	}
}

void free_http_response(http_response *hr) {
	if (hr != NULL) {
		if(hr->headers != NULL) {
			http_header *current_header = hr->headers;
			while (current_header != NULL) {
				if (current_header->name != NULL)
					free(current_header->name);
				if (current_header->value != NULL)
					free(current_header->value);
				http_header *aux = current_header->next_header;
				free(current_header);
				current_header = aux;
			}
		}
		if(hr->body != NULL)
			free(hr->body);
		hr = NULL;
	}
}

void init_parse_state(http_parse_state *parse_state) {
	parse_state->state = HTTP_INIT_STATE;
	parse_state->body_buf = NULL;
	parse_state->content_length = 0;
	parse_state->current = NULL;
}

