#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <string.h>
#include "stm_hello.h"
#include "../socks5_server.h"
#include "../stm/socks5_stm.h"
#include "../utils/logger.h"

#define ENOUGH_SPACE_TO_HELLO_LOG 150

// Prototypes
static int choose_hello_method(uint8_t *methods, uint8_t nmethods);
static void failed_hello_log(fd_selector s, struct socks5* s5);


unsigned
hello_read_init(const unsigned state, struct selector_key *key) {
	struct hello_stm *hello_stm = &ATTACHMENT(key)->hello_state;

    hello_stm->method_selected = -1;  // Initial value

    // Initialize read buffer
    hello_stm->read_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(hello_stm->read_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&hello_stm->rb, get_buff_size(), hello_stm->read_buffer_data);

    // Initialize write buffer
    hello_stm->write_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(hello_stm->write_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&hello_stm->wb, get_buff_size(), hello_stm->write_buffer_data);

    hello_parser_init(&hello_stm->hello_parser);
    return state;

finally:
    return ERROR_GLOBAL_STATE;
}


unsigned
hello_read(struct selector_key *key) {
    struct hello_stm *hello_stm = &ATTACHMENT(key)->hello_state;

	size_t nbytes;
    uint8_t *where_to_write = buffer_write_ptr(&hello_stm->rb, &nbytes);
    ssize_t ret = recv(key->fd, where_to_write, nbytes, 0);  // Non blocking !

    uint8_t returned_state = READING_HELLO; // current state
    if(ret > 0) {
        buffer_write_adv(&hello_stm->rb, ret);
        enum hello_state state = consume_hello_buffer(&hello_stm->rb, &hello_stm->hello_parser);
        if(state == hello_finished || state == hello_server_error || state == hello_unsupported_version) {

            // Dependiendo del estado en que nos quedamos, retorna un método válido o 0xFF
            hello_stm->method_selected = choose_hello_method(hello_stm->hello_parser.methods, hello_stm->hello_parser.methods_remaining);

            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                goto finally;
            }
            // Dejamos la respuesta del hello en el buffer "wb" para enviarlo en el próximo estado
            hello_marshall(&hello_stm->wb, hello_stm->method_selected);

            // Success here
            returned_state = WRITING_HELLO;

        } else {
            // El hello parser terminó, pero no llegó a un estado final. Tenemos que esperar a que llegue la parte
            // que falta del Hello
        }
    } else {
        goto finally;
    }
    return returned_state;

finally:
    /* Si hubo alguno de los 2 errores que esta funcion puede tener, debemos devolverle al cliente un mensaje
       fallido con el metodo de autenticacion "NO_ACCEPTABLE_METHODS" */
    hello_stm->method_selected = NO_ACCEPTABLE_METHODS;
    hello_marshall(&hello_stm->wb, hello_stm->method_selected);
    return WRITING_HELLO;
}

static int
choose_hello_method(uint8_t *methods, uint8_t nmethods) {
    int ret = NO_ACCEPTABLE_METHODS;

    if(methods != NULL) {
        for(uint8_t i = 0; i < nmethods; i++) {
            if(methods[i] == USERNAME_PASSWORD_AUTHENTICATION) {
                return methods[i];  // Si el cliente esta dispuesto a usar usr/pass, entonces vamos por ahi
            } else if(methods[i] == NO_AUTHENTICATION_REQUIRED) {
                ret = methods[i];  // Si el cliente quiere usar NO_AUTH_REQUIRED, esta bien. Esperamos a ver si hay una mejor opción
            }
        }
    }
    return ret;
}


unsigned
hello_write(struct selector_key *key) {
    struct hello_stm *hello_stm = &ATTACHMENT(key)->hello_state;
    struct socks5 *s5 = ATTACHMENT(key);

    size_t nbytes;
    uint8_t *where_to_read = buffer_read_ptr(&hello_stm->wb, &nbytes);
    ssize_t ret = send(key->fd, where_to_read, nbytes, MSG_NOSIGNAL);

    uint8_t returned_state = WRITING_HELLO; // current state
    if(ret > 0) {
        buffer_read_adv(&hello_stm->wb, nbytes);
        if(!buffer_can_read(&hello_stm->wb)) {

            if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                /* Si ya le enviamos un Hello exitoso, entonces con este error le cerramos la conexion ya que
                   es un error inesperado (y ademas no tenemos que responderle nada todavia) */
                /* Si ya le enviamos un Hello fallido, entonces con este error le cerramos la conexion ya que
                   de todas formas se la ibamos a cerrar un par de lineas mas abajo */
                goto finally;
            }

            if(hello_stm->method_selected == NO_AUTHENTICATION_REQUIRED) {
                // Ya estamos listos para leer el Request
                returned_state = READING_REQUEST;
            } else if(hello_stm->method_selected == USERNAME_PASSWORD_AUTHENTICATION) {
                // Hay que leer ahora el user:pass
                returned_state = READING_HELLO_AUTH;
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
    failed_hello_log(key->s, s5);
    return ERROR_GLOBAL_STATE;
}


static void
failed_hello_log(fd_selector s, struct socks5* s5) {
    char buff[ENOUGH_SPACE_TO_HELLO_LOG];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    const char* user_to_log;
    if(s5->connected_user.name == NULL) {
        user_to_log = "anonymous";
    } else {
        user_to_log = s5->connected_user.name;
    }

    strcpy(buff, "%04d-%02d-%02dT%02d:%02d:%02dZ\t%s\t%s:%d failed in Hello state\n");

    proxy_log(ERROR, s, buff, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
              tm->tm_sec, user_to_log, s5->client_ip, s5->client_port);
}

