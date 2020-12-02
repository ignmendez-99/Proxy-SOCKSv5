#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include <stdint.h>

#define MAX_USERS 10
#define MAX_ADMINS 1

struct users {
    char *name;
    char *pass;
};

struct doh {
    char           *host;
    char           *ip;
    unsigned short  port;
    char           *path;
    char           *query;
    uint16_t		http_buffer_size;
};

struct socks5args {
    char           *socks_addr_ipv4;
    char           *socks_addr_ipv6;
    unsigned short  socks_port;

    char *          mng_addr;
    char *          mng_addr_ipv6;
    unsigned short  mng_port;

    bool            disectors_enabled;

    struct doh      doh;
    struct users    users[MAX_USERS];
    struct users    admin;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void 
parse_args(const int argc, char **argv, struct socks5args *args);

#endif
