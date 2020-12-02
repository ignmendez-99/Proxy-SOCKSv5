/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netinet/sctp.h>
#include <stdlib.h>

#include "socks5_server.h"
#include "utils/selector.h"
#include "utils/args.h"
#include "utils/socket_creation_errors.h"  // Bring enum for socket errors
#include "myProtocol/my_protocol_server.h"
#include "utils/logger.h"
#include "utils/params.h"
#include "config.h"

//#define SINIT_NUM_OSTREAMS 1
//#define SINIT_NUM_INSTREAMS 1
//#define SINIT_MAX_ATTEMPS 1

static bool done = false;
struct socks5args args;

// Prototypes
static enum socket_creation_error create_ipv4_passive_socket(int * ret_socket, struct socks5args args);
static enum socket_creation_error create_ipv6_passive_socket(int * ret_socket, struct socks5args args);
static enum socket_creation_error create_ipv4_myProtocol_passive_socket(int *ret_socket, struct socks5args args);
static enum socket_creation_error create_ipv6_myProtocol_passive_socket(int *ret_socket, struct socks5args args);
static int register_all_fds(int fd1, int fd2, int fd3, int fd4, fd_selector s);
static void manage_stdout_stderr();

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

// Definimos los handlers para el socket pasivo
static const struct fd_handler socksv5_passive_handler = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,  // El socket pasivo solo leerá
        .handle_close      = NULL,  // El socket pasivo solo leerá
};

// Definimos los handlers para el socket pasivo de nuestro protocolo
static const struct fd_handler my_protocol_passive_handler = {
        .handle_read       = my_protocol_passive_accept,
        .handle_write      = NULL,  // El socket pasivo solo leerá
        .handle_close      = NULL,  // El socket pasivo solo leerá
};

int
main(const int argc, const char **argv) {

    parse_args(argc, (char **) argv, &args);
    set_global_args(&args);

    set_args(args.users, &args.admin);

    
    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);
    manage_stdout_stderr();

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    int ipv4_passive_socket = -1, ipv6_passive_socket = -1;
    int ipv4_myProtocol_passive_socket = -1, ipv6_myProtocol_passive_socket = -1;
    bool one_passive_socket_failed = false;
    bool one_myProtocol_passive_socket_failed = false;

    enum socket_creation_error error = create_ipv4_passive_socket( &ipv4_passive_socket , args);
    if(error != socket_no_fail) {
        printf("No se pudo crear el socket pasivo de Socksv5 IPv4. Vamos a intentar crear el socket IPv6\n");
        one_passive_socket_failed = true;
    }
    error = create_ipv6_passive_socket( &ipv6_passive_socket , args);
    if(error != socket_no_fail) {
        if(one_passive_socket_failed) {
            printf("Los 2 sockets pasivos Socksv5 fallaron. Cerrando todo el proxy\n");
            err_msg = socket_error_description[error];
            goto finally;
        } else {
            printf("No se pudo crear el socket pasivo de Socksv5 IPv6. Por lo menos tenemos andando el socket IPv4\n");
        }
    }

    error = create_ipv4_myProtocol_passive_socket( &ipv4_myProtocol_passive_socket, args);
    if(error != socket_no_fail) {
        printf("No se pudo crear el socket pasivo de Mi Protocolo IPv4. Vamos a intentar crear el socket IPv6\n");
        // No abortamos, ya que todavía tiene chance de crearse el socket pasivo IPv6
        one_myProtocol_passive_socket_failed = true;
    }
    error = create_ipv6_myProtocol_passive_socket( &ipv6_myProtocol_passive_socket, args);
    if(error != socket_no_fail) {
        if(one_myProtocol_passive_socket_failed) {
            // Ambos sockets pasivos fallaron
            printf("Los 2 sockets pasivos de Mi Protocolo fallaron. Cerrando todo el proxy\n");
            err_msg = socket_error_description[error];
            goto finally;
        } else {
            printf("No se pudo crear el socket pasivo de Mi Protocolo IPv6. Por lo menos tenemos andando el socket IPv4\n");
        }
    }


    if(logger_init() == -1) {
        printf("No se pudo crear el logger para el proxy. Cerrando proxy\n");
        goto finally;
    }


    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);


    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 2,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    ss = register_all_fds(ipv4_passive_socket, ipv6_passive_socket, ipv4_myProtocol_passive_socket,
                          ipv6_myProtocol_passive_socket, selector);

    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }


    for(;!done;) {   // Si hago un CTRL+C, "done" pasa a true
        err_msg = NULL;
        ss = selector_select(selector); // Hace una llamada a select() esperando por conexion en socket pasivo
        selector_update_all_timeouts(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    if(ipv4_passive_socket >= 0) {
        close(ipv4_passive_socket);
    }
    if(ipv6_passive_socket >= 0) {
        close(ipv6_passive_socket);
    }
    if(ipv4_myProtocol_passive_socket >= 0) {
        close(ipv4_myProtocol_passive_socket);
    }
    if(ipv6_myProtocol_passive_socket >= 0) {
        close(ipv6_myProtocol_passive_socket);
    }

    //liberamos los recursos del logger
    logger_destroy();

    return ret;
}

static void
manage_stdout_stderr() {
    if(selector_fd_set_nio(STDOUT_FILENO) == -1) {
        printf("No se pudo hacer a STDOUT no bloqueante. Cerramos todo el programa\n");
        exit(EXIT_FAILURE);
    }
    if(selector_fd_set_nio(STDERR_FILENO) == -1) {
        printf("No se pudo hacer a STDERR no bloqueante. Cerramos todo el programa\n");
        exit(EXIT_FAILURE);
    }
}

static int
register_all_fds(int fd1, int fd2, int fd3, int fd4, fd_selector s) {

    bool fd1_failed = true, fd2_failed = true;
    bool fd3_failed = true, fd4_failed = true;
    bool stdout_failed = true, stderr_failed = true;
    int ss;

    if(fd1 != -1) {
        ss = selector_register(s, fd1, &socksv5_passive_handler, OP_READ, NULL);
        if(ss == SELECTOR_SUCCESS)
            fd1_failed = false;
    }
    if(fd2 != -1) {
        ss = selector_register(s, fd2, &socksv5_passive_handler, OP_READ, NULL);
        if(ss == SELECTOR_SUCCESS)
            fd2_failed = false;
    }
    if(fd3 != -1) {
        ss = selector_register(s, fd3, &my_protocol_passive_handler, OP_READ, NULL);
        if(ss == SELECTOR_SUCCESS)
            fd3_failed = false;
    }
    if(fd4 != -1) {
        ss = selector_register(s, fd4, &my_protocol_passive_handler, OP_READ, NULL);
        if(ss == SELECTOR_SUCCESS)
            fd4_failed = false;
    }

    ss = selector_register(s, STDOUT_FILENO, &logger_handler, OP_NOOP, NULL);
    if(ss == SELECTOR_SUCCESS)
        stdout_failed = false;

    ss = selector_register(s, STDERR_FILENO, &logger_handler, OP_NOOP, NULL);
    if(ss == SELECTOR_SUCCESS)
        stderr_failed = false;

    if( (fd1_failed && fd2_failed) || (fd3_failed && fd4_failed) || stderr_failed || stdout_failed) {
        return -1;
    }
    return SELECTOR_SUCCESS;
}


static enum socket_creation_error
create_ipv4_passive_socket(int *ret_socket, struct socks5args args) {

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, args.socks_addr_ipv4, &addr.sin_addr) == 0) {
        return socket_inet_pton_error;
    }
    addr.sin_port = htons(args.socks_port);

    *ret_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(*ret_socket < 0) {
        return socket_error;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*ret_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(*ret_socket, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return socket_bind_error;
    }

    if(listen(*ret_socket, 20) < 0) {
        return socket_listen_error;
    }

    if(selector_fd_set_nio(*ret_socket) == -1) {
        return socket_selector_fd_set_nio_error;
    }

    // Success here
    return socket_no_fail;
}

static enum socket_creation_error
create_ipv6_passive_socket(int *ret_socket, struct socks5args args) {

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, args.socks_addr_ipv6, &addr.sin6_addr) == 0) {
        return socket_inet_pton_error;
    }
    addr.sin6_port = htons(args.socks_port);

    *ret_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (*ret_socket < 0) {
        return socket_error;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*ret_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    // Este socket solamente va a esperar por conexiones entrantes en IPv6
    if (setsockopt(*ret_socket, SOL_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) < 0) {
        return socket_setsockopt_error;
    }

    if(bind(*ret_socket, (struct sockaddr*) &addr, (socklen_t)sizeof(addr)) < 0) {
        return socket_bind_error;
    }

    if(listen(*ret_socket, 20) < 0) {
        return socket_listen_error;
    }

    if(selector_fd_set_nio(*ret_socket) == -1) {
        return socket_selector_fd_set_nio_error;
    }

    // Success here
    return socket_no_fail;
}


static enum socket_creation_error
create_ipv4_myProtocol_passive_socket(int *ret_socket, struct socks5args args) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, args.mng_addr, &addr.sin_addr) == 0) {
        return socket_inet_pton_error;
    }
    addr.sin_port = htons(args.mng_port);

    *ret_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if(*ret_socket < 0) {
        return socket_error;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*ret_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

//    struct sctp_initmsg *initmsg = calloc(1, sizeof(struct sctp_initmsg));
//    initmsg->sinit_num_ostreams = SINIT_NUM_OSTREAMS;
//    initmsg->sinit_max_instreams = SINIT_NUM_INSTREAMS;
//    initmsg->sinit_max_attempts = SINIT_MAX_ATTEMPS;
//    if (setsockopt(*ret_socket, IPPROTO_SCTP, SCTP_INITMSG, initmsg, sizeof(*initmsg)) < 0) {
//        free(initmsg);
//        return socket_setsockopt_error;
//    }
//    free(initmsg);

    if(bind(*ret_socket, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return socket_bind_error;
    }

    if(listen(*ret_socket, 20) < 0) {
        return socket_listen_error;
    }

    if(selector_fd_set_nio(*ret_socket) == -1) {
        return socket_selector_fd_set_nio_error;
    }

    // Success here
    return socket_no_fail;
}

static enum socket_creation_error
create_ipv6_myProtocol_passive_socket(int *ret_socket, struct socks5args args) {

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, args.mng_addr_ipv6, &addr.sin6_addr) == 0) {
        return socket_inet_pton_error;
    }
    addr.sin6_port = htons(args.mng_port);

    *ret_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
    if (*ret_socket < 0) {
        return socket_error;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*ret_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    // Este socket solamente va a esperar por conexiones entrantes en IPv6
    if (setsockopt(*ret_socket, SOL_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) < 0) {
        return socket_setsockopt_error;
    }

//    struct sctp_initmsg *initmsg = calloc(1, sizeof(struct sctp_initmsg));
//    initmsg->sinit_num_ostreams = SINIT_NUM_OSTREAMS;
//    initmsg->sinit_max_instreams = SINIT_NUM_INSTREAMS;
//    initmsg->sinit_max_attempts = SINIT_MAX_ATTEMPS;
//    if (setsockopt(*ret_socket, IPPROTO_SCTP, SCTP_INITMSG, initmsg, sizeof(*initmsg)) < 0) {
//        free(initmsg);
//        return socket_setsockopt_error;
//    }
//    free(initmsg);

    if(bind(*ret_socket, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return socket_bind_error;
    }

    if(listen(*ret_socket, 20) < 0) {
        return socket_listen_error;
    }

    if(selector_fd_set_nio(*ret_socket) == -1) {
        return socket_selector_fd_set_nio_error;
    }

    // Success here
    return socket_no_fail;
}
