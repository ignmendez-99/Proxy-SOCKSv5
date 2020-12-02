#ifndef SOCKS5_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define SOCKS5_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include <stdint.h>
#include "utils/stm.h"
#include "stm/stm_hello.h"
#include "stm/stm_request.h"
#include "stm/stm_copy.h"
#include "utils/args.h"
#include "stm/stm_connect_origin.h"
#include "stm/stm_doh.h"
#include "stm/stm_hello_auth.h"

struct error_state {
	unsigned state;
	char * msg;
	int code;
};

struct socks5 {
    int client_fd;
    int origin_fd;
    int doh_fd;

    // Variables useful when fully connected
    char * client_ip;
    uint16_t client_port;
    char * origin_ip;
    uint16_t origin_port;
    struct users connected_user;

    time_t last_update; // Starts in 0. This connection will be cleaned when timeout reaches STATE_TIMEOUT

    struct hello_stm    hello_state;   // State of the hello for this connection
    struct hello_auth_stm hello_auth_state;
    struct request_stm  request_state; // State of the request for this connection
    struct doh_stm		doh_state; 		// State of the DNS over HTTP for this connection
    struct connect_origin_stm conn_origin_state; // State representing trying to connect to the Origin Server
    struct copy_stm     copy_state;      // State representing client and serv fully connected

    struct state_machine stm; // Gestor de máquinas de estado
    struct error_state err;
};


// Util para obtener la estructura socks5 dado una llave de selector
#define ATTACHMENT(key) ( (struct socks5*)(key)->data)


/**
 * Ejecutada cada vez que el selector detecta que hay algo para leer en el socket pasivo del proxy SOCKSv5
 * Acepta la nueva conexión entrante
 */
void
socksv5_passive_accept(struct selector_key *key);


/**
 * Ejecutada cada vez que algún File Descriptor (de alguna conexión SOCKSv5) esté listo para escribir
 */
void
socks5_read(struct selector_key *key);


/**
 * Ejecutada cada vez que algún File Descriptor (de alguna conexión SOCKSv5) esté listo para leer
 */
void
socks5_write(struct selector_key *key);


/**
 * Ejecutada cuando se llega al máximo tiempo permitido de espera para la conexión SOCKSv5 en cuestión
 */
void
socks5_timeout(struct selector_key *key);


// Handler structure for every new active socket created (for a SOCKSv5 connection)
static const fd_handler socks5_active_handler = {
        .handle_read = socks5_read,
        .handle_write = socks5_write,
        .handle_timeout = socks5_timeout
};

#endif
