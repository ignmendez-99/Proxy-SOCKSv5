#include "stm_doh.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "../socks5_server.h"
#include "socks5_stm.h"
#include "../config.h"

int
doh_init_query(struct doh_stm *doh_state){
	struct socks5args * socks5_global_args = get_global_args();
	if(doh_state->http_buf != NULL){
		buffer_reset(doh_state->http_buf);
		free_http_response(&doh_state->http_response);
		doh_state->http_response.headers_size = 0;
		doh_state->http_response.headers = NULL;
		doh_state->http_response.body = NULL;
	}
	if(doh_state->query_bytes != NULL){
		free_dns_query(doh_state->query_bytes);
		doh_state->query_bytes = NULL;
	}

	http_request request;
	request.version = HTTP1;
	request.method = HTTP_POST;
	request.host = socks5_global_args->doh.host;
	request.path = socks5_global_args->doh.path;

	doh_state->query_bytes = create_dns_query(doh_state->dns_query_question, &request.bode_size);
	if(doh_state->query_bytes == NULL) {
	    return -1;
	}

	request.body = doh_state->query_bytes;

	char body_size_str[16];
	snprintf(body_size_str, sizeof body_size_str, "%zu", request.bode_size);

	http_header request_headers[] = {
			{"content-type", "application/dns-message", request_headers + 1},
			{"accept","application/dns-message", request_headers + 2},
			{"content-length", body_size_str, NULL}
	};
	request.headers = request_headers;

	if(doh_state->http_buf == NULL) {
		doh_state->http_buf = malloc(sizeof(buffer));
		if (doh_state->http_buf == NULL) {
			return -1;
		}
		buffer_init(doh_state->http_buf, socks5_global_args->doh.http_buffer_size, malloc(socks5_global_args->doh.http_buffer_size));
	}

	int status = create_http_request(&request, doh_state->http_buf);

	return status;
}

unsigned
doh_init_connection(const unsigned int state, struct selector_key *key) {
	struct socks5args * socks5_global_args = get_global_args();
	struct socks5 *s5 = ATTACHMENT(key);
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
	struct request_stm *request_stm = &ATTACHMENT(key)->request_state;
	if(s5->doh_fd == -1) {	// IF CONNECTION WASN'T INITIALIZED

		s5->doh_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s5->doh_fd < 0) {
			s5->err.state = state;
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
		}

		if (selector_fd_set_nio(s5->doh_fd) < 0) {
			s5->err.state = state;
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
		}

		struct sockaddr_in serv_addr;

		serv_addr.sin_port = htons(socks5_global_args->doh.port);
		serv_addr.sin_family = AF_INET;
		if (inet_pton(AF_INET, socks5_global_args->doh.ip, &serv_addr.sin_addr) <= 0) {
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
		}

		if (connect(s5->doh_fd, (const struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
			if(errno == EINPROGRESS) {
				/* man connect: EINPROGRESS. Aparece cuando nos intentamos conectar a un socket que se ha marcado con
				 * operaciones no bloqueantes. Debemos registrar el socket para escritura.*/
				if (selector_register(key->s, s5->doh_fd, &socks5_active_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                    request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
                    goto finally;
				}
			} else {
                // Any other error --> ERROR
                request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
                goto finally;
            }
		}

		if(doh_init_query(doh_state) < 0) {
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
        }
	}

	return state;

finally:
	if(s5->doh_fd >= 0) {
		close(s5->doh_fd);
		s5->doh_fd = -1;
	}
	if(selector_set_interest(key->s, s5->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
	    // No nos podemos recuperar de este error
	    return ERROR_GLOBAL_STATE;
	}
	return WRITING_REQUEST;
}

unsigned
doh_query(struct selector_key *key) {
	struct socks5 *s5 = ATTACHMENT(key);
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;
	unsigned int optval = 1, optlen = sizeof(optval);
	if (getsockopt(s5->doh_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0 || optval != 0) {
		if(optval == ECONNREFUSED) {
            request_stm->request_parser.reply = CONNECTION_REFUSED;
            goto finally;
        } else if(optval == ENETUNREACH) {
            request_stm->request_parser.reply = NETWORK_UNREACHABLE;
            goto finally;
        } else if(optval == EHOSTUNREACH) {
            request_stm->request_parser.reply = HOST_UNREACHABLE;
        } else {
            // Any other error --> ERROR
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
		}
    }

	size_t bytes_to_write;
	uint8_t * read_ptr = buffer_read_ptr(doh_state->http_buf, &bytes_to_write);
	size_t bytes_sent = send(s5->doh_fd, read_ptr, bytes_to_write, MSG_NOSIGNAL);

	if(bytes_sent > 0){
		buffer_read_adv(doh_state->http_buf, bytes_sent);
		if(!buffer_can_read(doh_state->http_buf)){

			if(selector_set_interest(key->s, s5->doh_fd, OP_READ) != SELECTOR_SUCCESS) {
                request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
				goto finally;
			}

			return DNS_RESPONSE;
		} else {	// THERE'S MORE TO SEND
			return DNS_QUERY;
		}

	} else {
        request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
		s5->err.state = s5->stm.current->state;
		s5->err.msg = "Exception sending doh query";
		goto finally;
	}

finally:
	if(s5->doh_fd > 0) {
		selector_unregister_fd(key->s, s5->doh_fd);
		close(s5->doh_fd);
		s5->doh_fd = -1;
	}
    if(selector_set_interest(key->s, s5->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        // No nos podemos recuperar de este error
        return ERROR_GLOBAL_STATE;
    }
	return WRITING_REQUEST;
}

void doh_query_close(const unsigned int state, struct selector_key *key) {
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
	free_dns_query(doh_state->query_bytes);
	doh_state->query_bytes = NULL;
}

unsigned
doh_init_response(const unsigned int state, struct selector_key *key){
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;

	buffer_reset(doh_state->http_buf);
	if(doh_state->response != NULL){
		free_dns_response(doh_state->response);
		doh_state->response = NULL;
	}

	doh_state->parser_http_state.state = 0;
	doh_state->parser_http_state.current = NULL;
	doh_state->parser_http_state.content_length = 0;
	doh_state->parser_http_state.body_buf = NULL;

	return state;
}

unsigned
doh_response(struct selector_key *key) {
	struct socks5 *s5 = ATTACHMENT(key);
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

	size_t available_size;
	char* write_ptr = (char*)buffer_write_ptr(doh_state->http_buf, &available_size);
	size_t bytes_read = recv(s5->doh_fd, write_ptr, available_size, 0);
	buffer_write_adv(doh_state->http_buf, bytes_read);

	if(bytes_read > 0){
		int ret = http_parser_consume_buffer(&doh_state->http_response, doh_state->http_buf, &doh_state->parser_http_state);

		if(ret < 0) {
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
			s5->err.state = s5->stm.current->state;
			s5->err.msg = "Exception in http_parser_consume_buffer()";
			goto finally;
		} else if (ret == 0) {

			if(doh_state->http_response.status_code < 200 || doh_state->http_response.status_code >= 300){
				request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
				s5->err.state = s5->stm.current->state;
				s5->err.msg = "DoH -> HTTP Status Code: ";
				s5->err.code = doh_state->http_response.status_code;
				goto finally;
			}

			doh_state->response = parse_dns_response((uint8_t*)doh_state->http_response.body, doh_state->parser_http_state.content_length);
			if(doh_state->response == NULL) {
                request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
				s5->err.state = s5->stm.current->state;
				s5->err.msg = "Exception in parse_dns_response()";
                goto finally;
			}
			if(dns_get_reply_code(doh_state->response->header.flags) == 3){
				request_stm->request_parser.reply = NETWORK_UNREACHABLE;
				goto finally;
			}

			s5->conn_origin_state.answers_attempted = 0;
			s5->conn_origin_state.connection_type = doh_state->dns_query_question.qtype;

            selector_unregister_fd(key->s, s5->doh_fd);
            close(s5->doh_fd);
            s5->doh_fd = -1;

			return CONNECT_ORIGIN;
		} else if (ret == 1){
			return DNS_RESPONSE;
		}
	} else {
        request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
		s5->err.state = s5->stm.current->state;
		s5->err.msg = "Exception reading doh response";
        goto finally;
	}

finally:
	if(s5->doh_fd > 0) {
		selector_unregister_fd(key->s, s5->doh_fd);
		close(s5->doh_fd);
		s5->doh_fd = -1;
	}

    if(selector_set_interest(key->s, s5->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        // No nos podemos recuperar de este error
        return ERROR_GLOBAL_STATE;
    }
    return WRITING_REQUEST;
}
