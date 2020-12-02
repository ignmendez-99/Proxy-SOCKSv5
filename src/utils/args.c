#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "args.h"
#include "../config.h"
#include "params.h"

static unsigned short
port(const char *s) {
     char *end     = 0;
     const long sl = strtol(s, &end, 10);

     if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
         fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
         exit(1);
         return 1;
     }
     return (unsigned short)sl;
}

static void
user(char *s, struct users *user) {
    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }

}

static void
version(void) {
    fprintf(stderr, "socks5v version 0.0\n"
                    "ITBA Protocolos de Comunicación 2020-2C  Grupo 6\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v               Imprime información sobre la versión versión y termina.\n"
        "\n"
        "   --doh-ip    <ip>    Establece la dirección del servidor DoH.\n"
        "   --doh-port  <port>  Establece el puerto del servidor DoH.\n"
        "   --doh-host  <host>  Establece el valor del header Host.\n"
        "   --doh-path  <host>  Establece el path del request doh.\n"
        "   --doh-query <host>  Establece el query string si el request DoH utiliza el método Doh por defecto ?dns=.\n"

        "\n",
        progname);
    exit(1);
}

void 
parse_args(const int argc, char **argv, struct socks5args *args) {
    memset(args, 0, sizeof(*args)); // para setear en null los punteros de users

    args->socks_addr_ipv4 = SOCKS_ADDR_IPV4;
    args->socks_addr_ipv6 = SOCKS_ADDR_IPV6;
    args->socks_port = SOCKS_PORT;

    args->mng_addr      = MANAGER_ADDR_IPV4;
    args->mng_addr_ipv6 = MANAGER_ADDR_IPV6;
    args->mng_port      = MANAGER_PORT;

    args->disectors_enabled = DISECTORS_ENABLED;

    args->doh.host = DOH_SERVER_HOST;
    args->doh.ip   = DOH_SERVER_IP;
    args->doh.port = DOH_SERVER_PORT;
    args->doh.path = DOH_SERVER_PATH;
    args->doh.query = DOH_SERVER_QUERY;
    args->doh.http_buffer_size = DOH_HTTP_BUFFER_SIZE;

    int c;
    int nusers = 0, nadmins = 0;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            { "doh-ip",    required_argument, 0, 0xD001 },
            { "doh-port",  required_argument, 0, 0xD002 },
            { "doh-host",  required_argument, 0, 0xD003 },
            { "doh-path",  required_argument, 0, 0xD004 },
            { "doh-query", required_argument, 0, 0xD005 },
            { 0,           0,                 0, 0 }
        };

        c = getopt_long(argc, argv, "hl:L:Np:P:u:U:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                args->socks_addr_ipv4 = optarg;
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
                break;
            case 'p':
                args->socks_port = port(optarg);
                break;
            case 'P':
                args->mng_port   = port(optarg);
                break;
            case 'U':
                if(nadmins >= MAX_ADMINS) {
                    fprintf(stderr, "maximun number of admins users reached: %d.\n", MAX_ADMINS);
                    exit(1);
                } else {
                    user(optarg, &args->admin);
                    nadmins++;
                }
                break;
            case 'u':
                if(nusers >= MAX_USERS) {
                    fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                    exit(1);
                } else {
                    user(optarg, args->users + nusers);
                    nusers++;
                    get_number_of_users_and_increment();
                }
                break;
            case 'v':
                version();
                exit(0);
                break;
            case 0xD001:
                args->doh.ip = optarg;
                break;
            case 0xD002:
                args->doh.port = port(optarg);
                break;
            case 0xD003:
                args->doh.host = optarg;
                break;
            case 0xD004:
                args->doh.path = optarg;
                break;
            case 0xD005:
                args->doh.query = optarg;
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
