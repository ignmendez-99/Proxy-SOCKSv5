#ifndef PC_2020B_6_HTTP_PARSER_H
#define PC_2020B_6_HTTP_PARSER_H

#include "../utils/buffer.h"
#include "login_def.h"

typedef enum {
    HTTP1,
    HTTP1_1,
    HTTP2
}http_version;

typedef enum {
    HTTP_GET,
    HTTP_POST
} http_method;

typedef struct http_header{
    char *  name;
    char *  value;
    struct http_header * next_header;
} http_header;


typedef struct {
    http_method 	method;
    http_version 	version;
    const char 	* 	path;
    const char 	* 	host;
    size_t 			headers_size;
    http_header	* 	headers;
    size_t			bode_size;
    const unsigned char * 	body;
} http_request;

typedef struct {
	http_version		version;
    int					status_code;
	size_t 				headers_size;
    http_header	*		headers;
    char *				body;
} http_response;

typedef struct http_parse_state {
	unsigned state;
	http_header ** current;
	int content_length;
	buffer * body_buf;
} 	http_parse_state;

typedef struct {
	uint8_t state;
	bool ignore_line;
	size_t header_buf_i;
	char header_buf[16];
	char * header_value;
} http_login_parse_state;

void
init_parse_state(http_parse_state * parse_state);

/**
 * Crea un HTTP request apartir del struct pasado y lo deja en el buffer. No utiliza el heap.
 * @returns La cantidad de bytes a ser leidos. Retorna -1 en caso de no haber suficiente espacio.
 */
int
create_http_request(const http_request* hr, buffer * buf);

/**
 * Parsea un HTTP response guardado en el buffer. Utiliza heap, por ende, requiere de liberar la memoria del http_response.
 * @returns Retorna 1 en caso de estar incompleto; 0 en caso de estar completo; -1 en caso de ser una respuesta invalida; -2 en caso de tener excepcion de tamaño del buffer;
 */
int
http_parser_consume_buffer(http_response *hr, buffer *buf, http_parse_state * parse_state);


int http_login_consume_buffer(const char * buf, size_t size, login_data *login, http_login_parse_state * state, communication_actor actor);

void http_login_init_state(http_login_parse_state * state);

void http_free_login_state(http_login_parse_state * state);

void
free_http_parse_state(http_parse_state * parse_state);

void
free_http_response(http_response * hr);

#endif //PC_2020B_6_HTTP_PARSER_H
