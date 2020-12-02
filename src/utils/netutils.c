#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize, const struct sockaddr *addr) {
    if(addr == 0) {
        strncpy(buff, "null", buffsize);
        return buff;
    }

    // Initialize variables
    in_port_t port;
    struct in_addr *ipv4_addr;
    struct in6_addr *ipv6_addr;
    bool handled = false;

    switch(addr->sa_family) {
        case AF_INET:
            ipv4_addr    = &((struct sockaddr_in *) addr)->sin_addr;
            port =  ((struct sockaddr_in *) addr)->sin_port;
            if (inet_ntop(addr->sa_family, ipv4_addr,  buff, buffsize) == 0) {
                strncpy(buff, "unknown ip", buffsize);
                buff[buffsize - 1] = 0;
            }
            handled = true;
            break;

        case AF_INET6:
            ipv6_addr    = &((struct sockaddr_in6 *) addr)->sin6_addr;
            port =  ((struct sockaddr_in6 *) addr)->sin6_port;
            if (inet_ntop(addr->sa_family, ipv6_addr,  buff, buffsize) == 0) {
                strncpy(buff, "unknown ip", buffsize);
                buff[buffsize - 1] = 0;
            }
            handled = true;
            break;

        default:
            strncpy(buff, "unknown", buffsize);
    }

    strncat(buff, ":", buffsize);
    buff[buffsize - 1] = 0;
    const size_t len = strlen(buff);

    if(handled) {
        snprintf(buff + len, buffsize - len, "%d", ntohs(port));
    }
    buff[buffsize - 1] = 0;

    return buff;
}

extern const char *
get_ip_from_sockaddr(char *buff, const size_t buffsize, const struct sockaddr *addr) {

    if(addr == NULL) {
        strncpy(buff, "null", buffsize);
        return buff;
    }

    struct in_addr *ipv4_addr;
    struct in6_addr *ipv6_addr;

    switch(addr->sa_family) {
        case AF_INET:
            ipv4_addr    = &((struct sockaddr_in *) addr)->sin_addr;
            if (inet_ntop(addr->sa_family, ipv4_addr,  buff, buffsize) == 0) {
                strncpy(buff, "unknown ip", buffsize);
            }
            break;

        case AF_INET6:
            ipv6_addr    = &((struct sockaddr_in6 *) addr)->sin6_addr;
            if (inet_ntop(addr->sa_family, ipv6_addr,  buff, buffsize) == 0) {
                strncpy(buff, "unknown ip", buffsize);
            }
            break;

        default:
            strncpy(buff, "unknown", buffsize);
    }
    return buff;
}

int
sock_blocking_write(const int fd, buffer *b) {
        int  ret = 0;
    ssize_t  nwritten;
	 size_t  n;
	uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);   // se bloquea ya que no hicimos nada para prevenirlo !!
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int
sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char* out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
    error:

    return ret;
}

