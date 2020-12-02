#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "stm_connect_origin.h"
#include "../socks5_server.h"
#include "socks5_stm.h"

// Prototypes
static enum socks5_global_state connect_to_origin(struct selector_key *key, struct request_stm *request_stm);
static enum socks5_global_state connect_to_origin_through_fqdn(struct selector_key *key, struct request_stm *stm);
static enum socks5_global_state connect_to_origin_through_ipv4(struct selector_key *key, struct request_stm *stm);
static enum socks5_global_state connect_to_origin_through_ipv6(struct selector_key *key, struct request_stm *stm);
static enum socks5_global_state make_preparations_to_ipv4_connect(struct selector_key *key, struct request_stm *stm);
static enum socks5_global_state make_preparations_to_ipv6_connect(struct selector_key *key, struct request_stm *stm);


//TODO: MODULARIZAR MEJOR ESTE CODIGO. MUCHO CODIGO REPETIDO

unsigned
connect_origin_init(const unsigned state, struct selector_key *key) {
	struct socks5 * s5 = ATTACHMENT(key);
	struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

	unsigned ret_state = state;

    if(s5->origin_fd < 0 || request_stm->request_parser.address_type == REQUEST_THROUGH_FQDN) {
		ret_state = connect_to_origin(key, request_stm);
		if(ret_state == WRITING_REQUEST) {
		    // Algo mal sucedio al conectarnos. Debemos devolver un Request negativo al cliente
		    if(selector_set_interest(key->s, s5->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
		        // No nos podemos recuperar de este error
		        return ERROR_GLOBAL_STATE;
		    }
		}
    }

    return ret_state;
}


unsigned
connect_origin_write(struct selector_key *key) {
    struct socks5 * s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
    struct connect_origin_stm *conn_origin_stm = &ATTACHMENT(key)->conn_origin_state;
    bool error = false;


    unsigned int optval = 1, optlen = sizeof(optval);
    if (getsockopt(s5->origin_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0 || optval != 0) {

        if(optval == ECONNREFUSED) {
            request_stm->request_parser.reply = CONNECTION_REFUSED;
        } else if(optval == ENETUNREACH) {
            request_stm->request_parser.reply = NETWORK_UNREACHABLE;
        } else if(optval == EHOSTUNREACH) {
            request_stm->request_parser.reply = HOST_UNREACHABLE;
        } else {
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
			s5->err.state = s5->stm.current->state;
			s5->err.msg = "Exception in connection to dst server";
        }

        if(request_stm->request_parser.address_type == REQUEST_THROUGH_FQDN){
            if(conn_origin_stm->answers_attempted < (size_t)doh_state->response->header.ancount-1){
                conn_origin_stm->answers_attempted++;

				selector_unregister_fd(key->s, s5->origin_fd);
				close(s5->origin_fd);
				s5->origin_fd = -1;

                return CONNECT_ORIGIN;
            } else {
                if(conn_origin_stm->connection_type == DNS_QTYPE_A){	// Volvemos a probar con los IPv6
                    doh_state->dns_query_question.qtype = DNS_QTYPE_AAAA;

                    selector_unregister_fd(key->s, s5->origin_fd);
					close(s5->origin_fd);
					s5->origin_fd = -1;

                    return DNS_QUERY;

                } else {
					selector_unregister_fd(key->s, s5->origin_fd);
					close(s5->origin_fd);
					s5->origin_fd = -1;
                    request_stm->request_parser.reply = NETWORK_UNREACHABLE;
                    goto finally;
                }
            }
        }
    }

finally:
	// Hacemos que el FD del Origin no esté para escribir ni para leer
	if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
	    error = true;
		goto error;
	}
    if(selector_set_interest(key->s, s5->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        error = true;
        goto finally;
    }
error:
    if(error) {
		s5->err.state = s5->stm.current->state;
		s5->err.msg = "Exception in connection to dst server";
		request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
	}
    return WRITING_REQUEST;
}


static enum socks5_global_state
connect_to_origin(struct selector_key *key, struct request_stm *request_stm) {
    switch(request_stm->request_parser.address_type){
        case REQUEST_THROUGH_IPV4:
            return connect_to_origin_through_ipv4(key, request_stm);
        case REQUEST_THROUGH_IPV6:
            return connect_to_origin_through_ipv6(key, request_stm);
        case REQUEST_THROUGH_FQDN:
            return connect_to_origin_through_fqdn(key, request_stm);
        default: // impossible
            exit(EXIT_FAILURE);
    }
}

static enum socks5_global_state
connect_to_origin_through_fqdn(struct selector_key *key, struct request_stm *stm) {
	struct socks5 *s5 = ATTACHMENT(key);
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
	struct connect_origin_stm *conn_origin_stm = &ATTACHMENT(key)->conn_origin_state;
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

	s5->origin_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(s5->origin_fd < 0) {
	    goto finally;
	}

	if(selector_fd_set_nio(s5->origin_fd) < 0) {
		request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
        goto finally;
	}

	size_t answers_count = doh_state->response->header.ancount;
	dns_rr * doh_answer = doh_state->response->answer + conn_origin_stm->answers_attempted;

	while ( conn_origin_stm->answers_attempted < answers_count && doh_answer->type == DNS_QTYPE_CNAME) {		// Ignore Answers of QTYPE == CNAME
		conn_origin_stm->answers_attempted++;
		doh_answer = doh_state->response->answer + conn_origin_stm->answers_attempted;
	}

	if(conn_origin_stm->answers_attempted >= answers_count){
		if(conn_origin_stm->connection_type == DNS_QTYPE_A){	// Volvemos a probar con los IPv6
			doh_state->dns_query_question.qtype = DNS_QTYPE_AAAA;
			return DNS_QUERY;
		} else {
			request_stm->request_parser.reply = HOST_UNREACHABLE;
            goto finally;
		}
	}

	int connection_status = 0;

	if(doh_answer->type == DNS_QTYPE_A){
		const int addr_in_size = sizeof(struct sockaddr_in);
		memset(&stm->origin_addr_ipv4, 0, addr_in_size);
		stm->origin_addr_ipv4.sin_port = htons(stm->request_parser.destination_port);
		stm->origin_addr_ipv4.sin_family = AF_INET;
		memcpy(&stm->origin_addr_ipv4.sin_addr, &doh_answer->rdata.ipv4, IPv4_LENGTH);
		connection_status = connect(s5->origin_fd, (struct sockaddr*)&stm->origin_addr_ipv4, sizeof(stm->origin_addr_ipv4));
	}
	else if(doh_answer->type == DNS_QTYPE_AAAA){
		memset(&stm->origin_addr_ipv6, 0, sizeof(struct sockaddr_in6));
		stm->origin_addr_ipv6.sin6_port = htons(stm->request_parser.destination_port);
		stm->origin_addr_ipv6.sin6_family = AF_INET6;
		memcpy(&stm->origin_addr_ipv6.sin6_addr, &doh_answer->rdata.ipv6, IPv6_LENGTH);
		connection_status = connect(s5->origin_fd, (struct sockaddr*)&stm->origin_addr_ipv6, sizeof(stm->origin_addr_ipv6));
	}


	if(connection_status < 0) {
		if (errno == EINPROGRESS) {
			/* man connect: EINPROGRESS. Aparece cuando nos intentamos conectar a un socket que se ha marcado con
			 * operaciones no bloqueantes. Debemos registrar el socket para escritura.*/
			if (selector_register(key->s, s5->origin_fd, &socks5_active_handler, OP_WRITE, key->data) !=
				SELECTOR_SUCCESS) {
				request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
                goto finally;
			}
			return CONNECT_ORIGIN;
		} else {
            // Any other error --> ERROR
			request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
        }
	}

finally:
	if(s5->origin_fd > 0) {
		selector_unregister_fd(key->s, s5->origin_fd);
		close(s5->origin_fd);
		s5->origin_fd = -1;
	}

    return WRITING_REQUEST;
}

static enum socks5_global_state
connect_to_origin_through_ipv4(struct selector_key *key, struct request_stm *stm) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    enum socks5_global_state ret = make_preparations_to_ipv4_connect(key, stm);
    if(ret != CONNECT_ORIGIN) {
        return ret;
    }

    if(connect(s5->origin_fd, (struct sockaddr*)&stm->origin_addr_ipv4, sizeof(stm->origin_addr_ipv4)) < 0) {
        if(errno == EINPROGRESS) {
            /* man connect: EINPROGRESS. Aparece cuando nos intentamos conectar a un socket que se ha marcado con
             * operaciones no bloqueantes. Debemos registrar el socket para escritura.*/
            if (selector_register(key->s, s5->origin_fd, &socks5_active_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
                goto finally;
            }
            return CONNECT_ORIGIN;
        } else {
            // Any other error --> ERROR
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
        }
    }
    return CONNECT_ORIGIN;   // we are still in this state

finally:
    return WRITING_REQUEST;
}


static enum socks5_global_state
connect_to_origin_through_ipv6(struct selector_key *key, struct request_stm *stm) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    enum socks5_global_state ret = make_preparations_to_ipv6_connect(key, stm);
    if(ret != CONNECT_ORIGIN) {
        return ret;
    }

    if(connect(s5->origin_fd, (struct sockaddr*)&stm->origin_addr_ipv6, sizeof(stm->origin_addr_ipv6)) < 0) {
        if(errno == EINPROGRESS) {
            /* man connect: EINPROGRESS. Aparece cuando nos intentamos conectar a un socket que se ha marcado con
             * operaciones no bloqueantes. Debemos registrar el socket para escritura.*/
            if (selector_register(key->s, s5->origin_fd, &socks5_active_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
                goto finally;
            }
            return CONNECT_ORIGIN;
        } else {
            // Any other error --> ERROR
            request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
            goto finally;
        }
    }
    return CONNECT_ORIGIN;   // we are still in this state

finally:
    return WRITING_REQUEST;
}


static enum socks5_global_state
make_preparations_to_ipv4_connect(struct selector_key *key, struct request_stm *stm) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    s5->origin_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(s5->origin_fd < 0) {
        goto finally;
    }

    if(selector_fd_set_nio(s5->origin_fd) < 0) {
        goto finally;
    }

    const int addr_in_size = sizeof(struct sockaddr_in);
    memset(&stm->origin_addr_ipv4, 0, addr_in_size);
    stm->origin_addr_ipv4.sin_port = htons(stm->request_parser.destination_port);
    stm->origin_addr_ipv4.sin_family = AF_INET;
    memcpy(&stm->origin_addr_ipv4.sin_addr, stm->request_parser.destination_address, stm->request_parser.destination_address_length);

    return CONNECT_ORIGIN; // we are still in this state

finally:
    request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
    return WRITING_REQUEST;
}

static enum socks5_global_state
make_preparations_to_ipv6_connect(struct selector_key *key, struct request_stm *stm) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    s5->origin_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if(s5->origin_fd < 0) {
        goto finally;
    }

    if(selector_fd_set_nio(s5->origin_fd) < 0) {
        goto finally;
    }

    const int addr_in_size = sizeof(struct sockaddr_in6);
    memset(&stm->origin_addr_ipv6, 0, addr_in_size);
    stm->origin_addr_ipv6.sin6_port = htons(stm->request_parser.destination_port);
    stm->origin_addr_ipv6.sin6_family = AF_INET6;
    memcpy(&stm->origin_addr_ipv6.sin6_addr, stm->request_parser.destination_address, stm->request_parser.destination_address_length);

    return CONNECT_ORIGIN; // we are still in this state

finally:
    request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
    return WRITING_REQUEST;
}

unsigned
connect_origin_timeout(struct selector_key *key){
	struct socks5 * s5 = ATTACHMENT(key);
	struct request_stm *request_stm = &ATTACHMENT(key)->request_state;
	struct doh_stm *doh_state = &ATTACHMENT(key)->doh_state;
	struct connect_origin_stm *conn_origin_stm = &ATTACHMENT(key)->conn_origin_state;
	s5->err.state = CONNECT_ORIGIN;

	if(request_stm->request_parser.address_type == REQUEST_THROUGH_FQDN){
		if(conn_origin_stm->answers_attempted < doh_state->response->header.ancount){
			conn_origin_stm->answers_attempted++;
			close(s5->origin_fd);
			s5->origin_fd = -1;

			return CONNECT_ORIGIN;
		} else {
			if(conn_origin_stm->connection_type == DNS_QTYPE_A){	// Volvemos a probar con los IPv6
				doh_state->dns_query_question.qtype = DNS_QTYPE_AAAA;
				close(s5->origin_fd);
				s5->origin_fd = -1;
				return DNS_QUERY;

			} else {
				close(s5->origin_fd);
				s5->origin_fd = -1;
				request_stm->request_parser.reply = NETWORK_UNREACHABLE;
				// Hacemos que el FD del Origin no esté para escribir ni para leer
				if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
					request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
				}
				if(selector_set_interest(key->s, s5->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
					request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
				}
				return WRITING_REQUEST;
			}
		}
	}

	return ERROR_GLOBAL_STATE;
}
