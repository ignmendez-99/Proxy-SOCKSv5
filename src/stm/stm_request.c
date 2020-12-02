#include <unistd.h>
#include <sys/socket.h>  // socket
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include "../utils/selector.h"
#include "../utils/netutils.h"
#include "stm_request.h"
#include "../socks5_server.h"
#include "../stm/socks5_stm.h"
#include "../utils/logger.h"

#define ENOUGH_SPACE_TO_CONNECTION_LOG 200

// Prototypes
//static void free_everything(struct socks5* s5);
static void log_connection(struct selector_key *key, struct socks5 *s5);



unsigned
request_read_init(const unsigned state, struct selector_key *key) {
	struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    // Initialize read buffer
    request_stm->read_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(request_stm->read_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&request_stm->rb, get_buff_size(), request_stm->read_buffer_data);

    // Initialize write buffer
    request_stm->write_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(request_stm->write_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&request_stm->wb, get_buff_size(), request_stm->write_buffer_data);

    request_parser_init(&request_stm->request_parser);

    request_stm->origin_addrinfo = calloc(1, sizeof(struct addrinfo));
    if(request_stm->origin_addrinfo == NULL) {
        goto finally;
    }
    return state;

finally:
    //free_everything(s5);
    return ERROR_GLOBAL_STATE;
}


unsigned
request_read(struct selector_key *key) {
	struct socks5 *s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    size_t nbytes;
    uint8_t *where_to_write = buffer_write_ptr(&request_stm->rb, &nbytes);
    ssize_t ret = recv(key->fd, where_to_write, nbytes, 0);  // Non blocking !

    enum socks5_global_state returned_state = READING_REQUEST; // current state
    if(ret > 0) {
        buffer_write_adv(&request_stm->rb, ret);
        enum request_state state = consume_request_buffer(&request_stm->rb, &request_stm->request_parser);
        if(state == request_finished) {

            // Client should wait until proxy connects to origin
            if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                goto finally;
            }

            if(request_stm->request_parser.address_type == REQUEST_THROUGH_IPV4
            		|| request_stm->request_parser.address_type == REQUEST_THROUGH_IPV6) {
				returned_state = CONNECT_ORIGIN;

			} else if(request_stm->request_parser.address_type == REQUEST_THROUGH_FQDN) {
				s5->doh_state.dns_query_question.qname = (char*)request_stm->request_parser.destination_address;
				s5->doh_state.dns_query_question.qtype = DNS_QTYPE_A;
				returned_state = DNS_QUERY;
            }

        } else if(state == request_has_error) {
            goto finally;
        } else {
            // El Request parser terminó, pero no llegó a un estado final. Tenemos que esperar a que llegue la parte
            // que falta del Request
        }

    } else {
        goto finally;
    }
    return returned_state;

finally:
    /* Si hubo alguno de los 3 errores que esta funcion puede tener, debemos devolverle al cliente un mensaje
       fallido con el error "general socks server error" */
    if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        // No nos podemos recuperar de este error. Vamos a cerrar la conexion
        //free_everything(s5);
        return ERROR_GLOBAL_STATE;
    }
    if(request_stm->request_parser.state == request_reading_version) {
        // Si ni llegamos a parsear, devolvemos error general
        request_stm->request_parser.state = request_has_error;
        getReplyBasedOnState( &(request_stm->request_parser) );
    }
    return WRITING_REQUEST;
}


unsigned
request_write(struct selector_key *key) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;


    // Dejamos la respuesta para ser enviada en el buffer "wb"
    request_marshall(&request_stm->wb, &request_stm->request_parser);

    size_t nbytes;
    uint8_t *where_to_read = buffer_read_ptr(&request_stm->wb, &nbytes);
    ssize_t ret = send(key->fd, where_to_read, nbytes, MSG_NOSIGNAL);

    if(ret > 0) {
        buffer_read_adv(&request_stm->wb, nbytes);
        if(!buffer_can_read(&request_stm->wb)) {
            if(request_stm->request_parser.reply == SUCCEDED) {

                if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                    // Ya le enviamos una Response positiva... pero hay error aca. Lastima. Vamos a cerrar la conexion
                    goto finally;
                }

                if(selector_set_interest(key->s, s5->origin_fd, OP_READ) != SELECTOR_SUCCESS) {
                    // Ya le enviamos una Response positiva... pero hay error aca. Lastima. Vamos a cerrar la conexion
                    goto finally;
                }

                log_connection(key, s5);
                return COPY;

            } else {
                // Se terminó de mandar el Response, pero era un Response de error. Cerramos la conexion
                log_connection(key, s5);
                goto finally;
            }

        } else {
            // Exit here, and keep waiting for future calls to this function to end reading buffer
            return WRITING_REQUEST;
        }
    } else {
        // Hubo un error al enviar el Response. Cerramos la conexion
        request_stm->request_parser.reply = GENERAL_SOCKS_SERVER_FAILURE;
        log_connection(key, s5);
        goto finally;
    }

finally:
    // No hace falta llamar a free_everything(), ya que el cambio de estado se encarga de hacerlo
    return ERROR_GLOBAL_STATE;
}

static void
log_connection(struct selector_key *key, struct socks5 *s5) {
    struct request_stm *request_stm = &ATTACHMENT(key)->request_state;

    // Me guardo los datos en variables mas cortas
    const int address_type      = request_stm->request_parser.address_type;
    const char* address = (char*) request_stm->request_parser.destination_address;
    const int address_length    = request_stm->request_parser.destination_address_length;
    const int origin_port       = request_stm->request_parser.destination_port;

    const char* first_part_logging = "%04d-%02d-%02dT%02d:%02d:%02dZ\t%s\tA\t%s\t%d\t%s\t";
    const char* second_part_logging_known_port   = "%d\t%d\n";
    const char* second_part_logging_unknown_port = "%s\t%d\n";


    const char unknown_ip[] = "X.X.X.X";
    const char unknown_port[] = "XX";
    bool port_unavailable = false;


    if(address_type != -1 && address != NULL) {
        // Se logró leer todos los campos necesarios en el parseo de Request
        if(address_type == REQUEST_THROUGH_IPV4) {
            struct sockaddr_in aux;
            aux.sin_family = AF_INET;
            memcpy(&(aux.sin_addr.s_addr), address, address_length);
            s5->origin_ip = calloc(INET_ADDRSTRLEN, sizeof(char));
            if(s5->origin_ip != NULL)
                get_ip_from_sockaddr(s5->origin_ip, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr*)&aux );

        } else if(address_type == REQUEST_THROUGH_IPV6) {
            struct sockaddr_in6 aux;
            aux.sin6_family = AF_INET6;
            memcpy(&(aux.sin6_addr.s6_addr), address, address_length);
            s5->origin_ip = calloc(INET6_ADDRSTRLEN, sizeof(char));
            if(s5->origin_ip != NULL)
                get_ip_from_sockaddr(s5->origin_ip, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr*)&aux );

        } else if(address_type == REQUEST_THROUGH_FQDN) {
            s5->origin_ip = calloc(request_stm->request_parser.destination_address_length+1, sizeof(char));
            if(s5->origin_ip != NULL)
                memcpy(s5->origin_ip, address, address_length);
        }
        s5->origin_port = origin_port;

        if(s5->origin_ip == NULL)
            return;

    } else {
        // No logramos obtener la IP ni el puerto durante el parseo
        s5->origin_ip = malloc(sizeof(unknown_ip));
        if(s5->origin_ip == NULL)
            return;
        memcpy(s5->origin_ip, unknown_ip, sizeof(unknown_ip));
        port_unavailable = true;
    }

    time_t t = time(NULL);
    struct tm *tm = localtime(&t);

    // Loggeamos
    const char* user_to_log;
    if(s5->connected_user.name == NULL) {
        user_to_log = "anonymous";
    } else {
        user_to_log = s5->connected_user.name;
    }

    char buff[ENOUGH_SPACE_TO_CONNECTION_LOG];
    memcpy(buff, first_part_logging, strlen(first_part_logging) + 1);
    if(port_unavailable) {
        strcat(buff, second_part_logging_unknown_port);
        proxy_log(INFO, key->s, buff, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
                  tm->tm_min, tm->tm_sec, user_to_log, s5->client_ip, s5->client_port, s5->origin_ip,
                  unknown_port, s5->request_state.request_parser.reply);
    } else {
        strcat(buff, second_part_logging_known_port);
        proxy_log(INFO, key->s, buff, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
                  tm->tm_min, tm->tm_sec, user_to_log, s5->client_ip, s5->client_port, s5->origin_ip,
                  s5->origin_port, s5->request_state.request_parser.reply);
    }

    if(s5->request_state.request_parser.reply == GENERAL_SOCKS_SERVER_FAILURE){
    	if(s5->err.code != 0){
			proxy_log(ERROR, key->s, "GENERAL SOCKS ERROR (State: %d): %s %d\n", s5->err.state, s5->err.msg != 0 ? s5->err.msg : "", s5->err.code);
    	} else {
			proxy_log(ERROR, key->s, "GENERAL SOCKS ERROR (State: %d): %s\n", s5->err.state, s5->err.msg != 0 ? s5->err.msg : "");
    	}
    }
}
