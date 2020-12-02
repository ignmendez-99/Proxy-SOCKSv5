#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "socks5_server.h"
#include "utils/selector.h"
#include "utils/stm.h"
#include "stm/socks5_stm.h"
#include "utils/netutils.h"
#include "utils/logger.h"
#include "utils/metrics.h"

// prototypes
static struct socks5 * create_new_socks5(int client_fd);
static void destroy_socks5(struct selector_key *key);

#define MAX_CONCURRENT_CONNECTIONS 501

void
socksv5_passive_accept(struct selector_key *key) {

    struct sockaddr_storage new_client_addr;
    struct socks5 *s5 = NULL;
    socklen_t new_client_addr_len = sizeof(new_client_addr);

    int client_sock = accept(key->fd, (struct sockaddr*)&new_client_addr, &new_client_addr_len);
    if(client_sock == -1) {
        goto finally;
    }

    if(selector_fd_set_nio(client_sock) == -1) {
        goto finally;
    }

    s5 = create_new_socks5(client_sock);
    if(s5 == NULL) {
        goto finally;
    }

    metric_add_connection();

    if (metric_get_concurrent_connections() == MAX_CONCURRENT_CONNECTIONS) {
        if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
            goto finally;
    }

    // Registramos el nuevo socket activo en el mismo selector que mira al socket pasivo
    if(selector_register(key->s, client_sock, &socks5_active_handler, OP_READ, s5) != SELECTOR_SUCCESS) {
        metric_remove_connection();
        goto finally;
    }

    // Nos guardamos la info del cliente para loggear datos utiles
    get_ip_from_sockaddr(s5->client_ip, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr*)&new_client_addr);
    if(((struct sockaddr*)&new_client_addr)->sa_family == AF_INET) {
        s5->client_port = ntohs(((struct sockaddr_in*)&new_client_addr)->sin_port);
    } else if(((struct sockaddr*)&new_client_addr)->sa_family == AF_INET6) {
        s5->client_port = ntohs(((struct sockaddr_in6*)&new_client_addr)->sin6_port);
    }

    return;

finally:
    if(client_sock != -1) {
        // destruimos el socket si es que se abrió
        close(client_sock);
    }
    if(s5 != NULL) {
        // destruimos la estructura si es que se creó
        destroy_socks5(key);
    }
}

static struct
socks5 * create_new_socks5(int client_fd) {

    struct socks5 *s5 = calloc(1, sizeof(struct socks5));
    if(s5 == NULL) {
        return NULL;
    }

    // Initialize state machine
    s5->stm.initial = READING_HELLO;  // Global state starts waiting for Hello
    s5->stm.max_state = ERROR_GLOBAL_STATE;  // Es la cantidad maxima de estados
    s5->stm.states = global_states_definition;
    s5->stm.current = NULL;
    stm_init( &(s5->stm) );

    s5->client_ip = calloc(INET6_ADDRSTRLEN, sizeof(char));
    if(s5->client_ip == NULL) {
        goto finally;
    }

    s5->client_fd = client_fd;
    s5->origin_fd = -1;  // Inválido por ahora
    s5->doh_fd = -1;
    time(&s5->last_update);

    return s5;
finally:
    if(s5->client_ip != NULL)
        free(s5->client_ip);
    if(s5->origin_ip != NULL)
        free(s5->origin_ip);
    if(s5 != NULL)
        free(s5);
    return NULL;
}

static void
destroy_socks5(struct selector_key *key) {
    struct socks5 *s5  = ATTACHMENT(key);
    if(s5->origin_fd != -1) {
        if(selector_unregister_fd(key->s, s5->origin_fd) != SELECTOR_SUCCESS)
            exit(EXIT_FAILURE);
        close(s5->origin_fd);
    }

    if(s5->client_fd != -1) {
        if(selector_unregister_fd(key->s, s5->client_fd) != SELECTOR_SUCCESS)
            exit(EXIT_FAILURE);
        close(s5->client_fd);
    }

    if(s5->client_ip != NULL)
        free(s5->client_ip);
    if(s5->origin_ip != NULL)
        free(s5->origin_ip);

    // Libero los recursos del estado HELLO en el caso de que se esté destruyendo la conexión en ese estado
    //free_hello_state(&s5->hello_state);
    if(s5->hello_state.read_buffer_data != NULL)
        free(s5->hello_state.read_buffer_data);
    if(s5->hello_state.write_buffer_data != NULL)
        free(s5->hello_state.write_buffer_data);
    if(s5->hello_state.hello_parser.methods != NULL)
        free(s5->hello_state.hello_parser.methods);

    // Libero los recursos del estado de HELLO-AUTH en caso de que se esté destruyendo la conexión en ese estado
    if(s5->hello_auth_state.hello_auth_parser.user != NULL)
        free(s5->hello_auth_state.hello_auth_parser.user);
    if(s5->hello_auth_state.hello_auth_parser.password != NULL)
        free(s5->hello_auth_state.hello_auth_parser.password);
    if(s5->hello_auth_state.read_buffer_data != NULL)
        free(s5->hello_auth_state.read_buffer_data);
    if(s5->hello_auth_state.write_buffer_data != NULL)
        free(s5->hello_auth_state.write_buffer_data);

    // Libero los recursos del estado REQUEST en el caso de que se esté destruyendo la conexión en ese estado
    if(s5->request_state.read_buffer_data != NULL)
        free(s5->request_state.read_buffer_data);
    if(s5->request_state.write_buffer_data != NULL)
        free(s5->request_state.write_buffer_data);
    if(s5->request_state.origin_addrinfo != NULL)
        free(s5->request_state.origin_addrinfo);
    if(s5->request_state.request_parser.destination_address != NULL)
        free(s5->request_state.request_parser.destination_address);
    if(s5->doh_state.response != NULL)
        free_dns_response(s5->doh_state.response);

    // Libero los recursos del estado COPY en el caso de que se esté destruyendo la conexión en ese estado
    if(s5->copy_state.serv_to_client_buff != NULL)
        free(s5->copy_state.serv_to_client_buff);
    if(s5->copy_state.client_to_serv_buff != NULL)
        free(s5->copy_state.client_to_serv_buff);
    if(s5->copy_state.serv_to_client_buff_data != NULL)
        free(s5->copy_state.serv_to_client_buff_data);
    if(s5->copy_state.client_to_serv_buff_data != NULL)
        free(s5->copy_state.client_to_serv_buff_data);
    free_login_state(&s5->copy_state.login_state);
    free_login_data(&s5->copy_state.login);

    // Libero los recursos del estado DOH en el caso de que se esté destruyendo la conexión en ese estado
    free_http_parse_state(&s5->doh_state.parser_http_state);
    free_http_response(&s5->doh_state.http_response);
	free_dns_query(s5->doh_state.query_bytes);
    if(s5->doh_state.http_buf != NULL){
        if(s5->doh_state.http_buf->data != NULL)
            free(s5->doh_state.http_buf->data);
        free(s5->doh_state.http_buf);
    }

    if (s5->doh_fd >= 0) {
        selector_unregister_fd(key->s, s5->doh_fd);
        close(s5->doh_fd);
        s5->doh_fd = -1;
    }

    metric_remove_connection();
    free(s5);
}


void
socks5_read(struct selector_key *key) {
    struct state_machine *stm  = &ATTACHMENT(key)->stm;
    struct socks5 * s5 = ATTACHMENT(key);

    // Se esta realizando una accion sobre este FD --> reinicio el timeout
	time(&s5->last_update);

    // Dependiendo del estado global en el que estemos, se tratará al Read de forma diferente
    enum socks5_global_state state = stm_handler_read(stm, key);

     if(state == ERROR_GLOBAL_STATE || state == CLOSE_CONNECTION) {
        destroy_socks5(key);
     }
}

void
socks5_write(struct selector_key *key) {
    struct state_machine *stm  = &ATTACHMENT(key)->stm;
    struct socks5 * s5 = ATTACHMENT(key);

    // Se esta realizando una accion sobre este FD --> reinicio el timeout
	time(&s5->last_update);

    // Dependiendo del estado global en el que estemos, se tratará al Write de forma diferente
    enum socks5_global_state state = stm_handler_write(stm, key);

    if(state == ERROR_GLOBAL_STATE || state == CLOSE_CONNECTION) {
        destroy_socks5(key);
    }
}

void
socks5_timeout(struct selector_key *key) {
	struct state_machine *stm  = &ATTACHMENT(key)->stm;
	struct socks5 * s5 = ATTACHMENT(key);

	// Se esta realizando una accion sobre este FD --> reinicio el timeout
	time(&s5->last_update);

	// Dependiendo del estado global en el que estemos, se tratará al Write de forma diferente
	enum socks5_global_state state = stm_handler_timeout(stm, key);

	if(state == ERROR_GLOBAL_STATE || state == CLOSE_CONNECTION || state == (enum socks5_global_state) STM_UNDEFINED_STATE) {
		proxy_log(ERROR, key->s, "Connection with %s:%d reached timeout (stm: %d). Closing...\n", s5->client_ip, s5->client_port, s5->stm.current->state);
		destroy_socks5(key);
	}
}
