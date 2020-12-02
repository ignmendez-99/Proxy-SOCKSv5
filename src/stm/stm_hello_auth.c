
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include "stm_hello_auth.h"
#include "../socks5_server.h"
#include "socks5_stm.h"
#include "../utils/logger.h"
#include "../utils/params.h"

#define ENOUGH_SPACE_TO_HELLO_AUTH_LOG 150

// Prototypes
static void failed_hello_auth_log(fd_selector s, struct socks5 *s5);


unsigned
hello_auth_read_init(const unsigned state, struct selector_key *key){
    struct hello_auth_stm *hello_auth_stm = &ATTACHMENT(key)->hello_auth_state;

    hello_auth_stm->reply = -1;  // Initial value

    // Initialize read buffer
    hello_auth_stm->read_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(hello_auth_stm->read_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&hello_auth_stm->rb, get_buff_size(), hello_auth_stm->read_buffer_data);

    // Initialize write buffer
    hello_auth_stm->write_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(hello_auth_stm->write_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&hello_auth_stm->wb, get_buff_size(), hello_auth_stm->write_buffer_data);

    my_hello_parser_init(&hello_auth_stm->hello_auth_parser);
    hello_auth_stm->reply = HELLO_AUTH_FAIL;
    return state;

finally:
    return ERROR_GLOBAL_STATE;
}


unsigned
hello_auth_read(struct selector_key *key) {
    struct hello_auth_stm *hello_auth_stm = &ATTACHMENT(key)->hello_auth_state;
    struct socks5 *s5 = ATTACHMENT(key);

    size_t nbytes;
    uint8_t *where_to_write = buffer_write_ptr(&hello_auth_stm->rb, &nbytes);
    ssize_t ret = recv(key->fd, where_to_write, nbytes, 0);  // Non blocking !

    uint8_t returned_state = READING_HELLO_AUTH; // current state
    if(ret > 0) {
        buffer_write_adv(&hello_auth_stm->rb, ret);
        enum my_hello_state state = my_consume_hello_buffer(&hello_auth_stm->rb, &hello_auth_stm->hello_auth_parser);
        if(state == my_hello_finished || state == my_hello_server_error || state == my_hello_unsupported_version || state == my_hello_bad_length) {

            if(state == my_hello_finished &&
                    is_valid_user(hello_auth_stm->hello_auth_parser.user, hello_auth_stm->hello_auth_parser.password)) {
                hello_auth_stm->reply = HELLO_AUTH_SUCCESS;
                struct users authenticated_user = {
                        .name = (char*)hello_auth_stm->hello_auth_parser.user,
                        .pass = (char*)hello_auth_stm->hello_auth_parser.password
                };
                memcpy(&s5->connected_user, &authenticated_user, sizeof(authenticated_user));
            }

            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                goto finally;
            }
            // Dejamos la respuesta del hello en el buffer "wb" para enviarlo en el próximo estado
            my_hello_marshall(&hello_auth_stm->wb, hello_auth_stm->reply);

            // Success here
            returned_state = WRITING_HELLO_AUTH;

        } else {
            // El hello parser terminó, pero no llegó a un estado final. Tenemos que esperar a que llegue la parte
            // que falta del Hello
        }
    } else {
        goto finally;
    }
    return returned_state;

finally:
    /* Si hubo alguno de los 2 errores que esta funcion puede tener, debemos devolverle al cliente un mensaje fallido */
    hello_auth_stm->reply = HELLO_AUTH_FAIL;
    my_hello_marshall(&hello_auth_stm->wb, hello_auth_stm->reply);
    return WRITING_HELLO_AUTH;
}


unsigned
hello_auth_write(struct selector_key *key) {
    struct hello_auth_stm *hello_auth_stm = &ATTACHMENT(key)->hello_auth_state;
    struct socks5 *s5 = ATTACHMENT(key);

    size_t nbytes;
    uint8_t *where_to_read = buffer_read_ptr(&hello_auth_stm->wb, &nbytes);
    ssize_t ret = send(key->fd, where_to_read, nbytes, MSG_NOSIGNAL);

    uint8_t returned_state = WRITING_HELLO_AUTH; // current state
    if(ret > 0) {
        buffer_read_adv(&hello_auth_stm->wb, nbytes);
        if(!buffer_can_read(&hello_auth_stm->wb)) {

            if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                /* Si ya le enviamos un Hello-auth exitoso, entonces con este error le cerramos la conexion ya que
                   es un error inesperado (y ademas no tenemos que responderle nada todavia) */
                /* Si ya le enviamos un Hello-auth fallido, entonces con este error le cerramos la conexion ya que
                   de todas formas se la ibamos a cerrar un par de lineas mas abajo */
                goto finally;
            }

            if(hello_auth_stm->reply == HELLO_AUTH_SUCCESS) {
                // Ya estamos listos para leer el Request
                returned_state = READING_REQUEST;
            } else {
                goto finally;
            }

        } else {
            // Exit here, and keep waiting for future calls to this function to end reading buffer
        }
    } else {
        goto finally;
    }
    return returned_state;

finally:
    failed_hello_auth_log(key->s, s5);
    return ERROR_GLOBAL_STATE;
}

static void
failed_hello_auth_log(fd_selector s, struct socks5 *s5) {
    char buff[ENOUGH_SPACE_TO_HELLO_AUTH_LOG];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);

    strcpy(buff, "%04d-%02d-%02dT%02d:%02d:%02dZ\t%s:%d failed to authenticate\n");

    proxy_log(ERROR, s, buff, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
              tm->tm_sec, s5->client_ip, s5->client_port);
}
