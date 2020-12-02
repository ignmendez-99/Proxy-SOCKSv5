#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "stm_copy.h"
#include "../socks5_server.h"
#include "../stm/socks5_stm.h"
#include "../parsers/login_parser.h"
#include "../utils/logger.h"
#include "../utils/metrics.h"

// Prototypes
//static void free_everything(struct copy_stm *stm);
static unsigned check_if_copy_finished(struct selector_key *key);


unsigned
copy_init(const unsigned state, struct selector_key *key) {
    struct copy_stm *copy_stm = &ATTACHMENT(key)->copy_state;

    // Initialize client_to_serv_buff
    copy_stm->client_to_serv_buff_data = calloc(1, get_buff_size());
    if(copy_stm->client_to_serv_buff_data == NULL) {
        goto finally;
    }
    copy_stm->client_to_serv_buff = calloc(1, sizeof(buffer));
    if(copy_stm->client_to_serv_buff == NULL) {
        goto finally;
    }
    buffer_init(copy_stm->client_to_serv_buff, get_buff_size(), copy_stm->client_to_serv_buff_data);

    // Initialize serv_to_client_buff
    copy_stm->serv_to_client_buff_data = calloc(1, get_buff_size());
    if(copy_stm->serv_to_client_buff_data == NULL) {
        goto finally;
    }
    copy_stm->serv_to_client_buff = calloc(1, sizeof(buffer));
    if(copy_stm->serv_to_client_buff == NULL) {
        goto finally;
    }
    buffer_init(copy_stm->serv_to_client_buff, get_buff_size(), copy_stm->serv_to_client_buff_data);

    // All variables start in true, showing that at first, data can come/go from/to every direction
    copy_stm->c_to_p_read = true;
    copy_stm->p_to_c_write = true;
    copy_stm->p_to_o_write = true;
    copy_stm->o_to_p_read = true;

    return state;

finally:
    //free_everything(copy_stm);
    return ERROR_GLOBAL_STATE;
}

void register_passwords(struct selector_key *key, login_data * login_data, login_state * state, char * ip_dst, int port_dst){
    struct socks5 *s5 = ATTACHMENT(key);
	time_t now;
	time(&now);
	struct tm * local = localtime(&now);

	const char* user_to_log;
	if(s5->connected_user.name == NULL) {
	    user_to_log = "anonymous";
	} else {
	    user_to_log = s5->connected_user.name;
	}

	proxy_log(INFO, key->s, "%d-%d-%dT%d:%d:%dZ\t%s\tP\t%s\t%s\t%d\t%s\t%s\n",
		   local->tm_year+1990, local->tm_mon+1, local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec,
              user_to_log, get_protocol_name(state), ip_dst, port_dst, login_data->user, login_data->pass);

	login_data->valid = false;
}

unsigned
copy_read(struct selector_key *key) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct copy_stm *copy_stm = &ATTACHMENT(key)->copy_state;

    buffer *general_buff;
    uint8_t fd_to_write;

    if(key->fd == s5->client_fd) {
        // Estamos leyendo del cliente
        general_buff = copy_stm->client_to_serv_buff;
        fd_to_write = s5->origin_fd;

    } else if(key->fd == s5->origin_fd) {
        // Estamos leyendo del origin
        general_buff = copy_stm->serv_to_client_buff;
        fd_to_write = s5->client_fd;

    } else {
        // impossible
        exit(EXIT_FAILURE);
    }

    size_t nbytes;
    uint8_t *where_to_write = buffer_write_ptr(general_buff, &nbytes);
    ssize_t ret = recv(key->fd, where_to_write, nbytes, 0);  // Non blocking !
    if(ret > 0) {
        buffer_write_adv(general_buff, ret);
        metric_add_bytes_transferred(ret);

        if(!copy_stm->login_state.finished && copy_stm->login_state.protocol != PROTOCOL_UNKNOWN)
        	steal_passwords((char *) where_to_write, ret, &copy_stm->login, &copy_stm->login_state, key->fd == s5->client_fd ? COMMUNICATION_CLIENT_SIDE : COMMUNICATION_SERVER_SIDE);

        if(copy_stm->login.valid) {
			register_passwords(key, &copy_stm->login, &copy_stm->login_state, s5->origin_ip, s5->origin_port);
			metric_add_stolen_password();
		}

        if(!buffer_can_write(general_buff)) {
            // No hay mas espacio en el buffer para escribir
            // Por lo tanto, esperamos a que haya mas espacio. Mientras tanto, sacamos el interés de lectura
            if(selector_set_interest_reduction(key->s, key->fd, OP_READ) != SELECTOR_SUCCESS) {
                goto finally;
            }
        }

        // Lo que sea que hayamos leído, ya lo vamos evacuando hacia la otro punta
        if(selector_set_interest_additive(key->s, fd_to_write, OP_WRITE) != SELECTOR_SUCCESS) {
            goto finally;
        }

    } else if(ret == 0 || errno == ECONNRESET) {
        // El FD del que estaba leyendo me cerró la puerta. No voy a leer más de él
        if(selector_set_interest_reduction(key->s, key->fd, OP_READ) != SELECTOR_SUCCESS) {
            goto finally;
        }
        if(key->fd == s5->origin_fd) {
            copy_stm->o_to_p_read = false;
        } else if(key->fd == s5->client_fd) {
            copy_stm->c_to_p_read = false;
        }

        // Si la otra punta ya terminó de leer el buffer, es seguro hacer que deje de escribir
        if (!buffer_can_read(general_buff)) {
            if (shutdown(fd_to_write, SHUT_WR) < 0 && errno != ENOTCONN) {
                goto finally;
            }
            if(key->fd == s5->origin_fd) {
                copy_stm->p_to_c_write = false;
            } else if(key->fd == s5->client_fd) {
                copy_stm->p_to_o_write = false;
            }
        }
    } else {
        goto finally;
    }
    return check_if_copy_finished(key);

finally:
    //free_everything(copy_stm);
    return ERROR_GLOBAL_STATE;
}

unsigned
copy_write(struct selector_key *key) {
    struct socks5 *s5 = ATTACHMENT(key);
    struct copy_stm *copy_stm = &ATTACHMENT(key)->copy_state;

    buffer *general_buff;
    uint8_t fd_read;

    if(key->fd == s5->client_fd) {
        // Estamos escribiendo al cliente
        general_buff = copy_stm->serv_to_client_buff;
        fd_read = s5->origin_fd;

    } else if(key->fd == s5->origin_fd) {
        // Estamos escribiendo al origin
        general_buff = copy_stm->client_to_serv_buff;
        fd_read = s5->client_fd;

    } else {
        // impossible
        exit(EXIT_FAILURE);
    }

    size_t nbytes;
    uint8_t *where_to_read = buffer_read_ptr(general_buff, &nbytes);
    ssize_t ret = send(key->fd, where_to_read, nbytes, MSG_NOSIGNAL);  // Non blocking !
    if(ret > 0) {
        buffer_read_adv(general_buff, ret);

        if(!buffer_can_read(general_buff)) {
            // No hay mas espacio en el buffer para leer
            // Por lo tanto, esperamos a que haya mas espacio. Mientras tanto, sacamos el interés de escritura
            if(selector_set_interest_reduction(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
                goto finally;
            }

            if(key->fd == s5->client_fd && copy_stm->o_to_p_read == false) {
                copy_stm->p_to_c_write = false;
                if(shutdown(key->fd, SHUT_WR) < 0 && errno != ENOTCONN) {
                    goto finally;
                }
            } else if(key->fd == s5->origin_fd && copy_stm->c_to_p_read == false) {
                copy_stm->p_to_o_write = false;
                if(shutdown(key->fd, SHUT_WR) < 0 && errno != ENOTCONN) {
                    goto finally;
                }
            }
        }

        if((key->fd == s5->client_fd && copy_stm->o_to_p_read == true) ||
            (key->fd == s5->origin_fd && copy_stm->c_to_p_read == true)) {
            // Le devolvemos el interés de lectura al otro FD (si es que lo habia perdido)
            if (selector_set_interest_additive(key->s, fd_read, OP_READ) != SELECTOR_SUCCESS) {
                goto finally;
            }
        }

        return check_if_copy_finished(key);

    } else {
        goto finally;
    }
finally:
    //free_everything(copy_stm);
    return ERROR_GLOBAL_STATE;
}


static unsigned
check_if_copy_finished(struct selector_key *key) {
    struct copy_stm *stm = &ATTACHMENT(key)->copy_state;

    if(stm->c_to_p_read == false && stm->o_to_p_read == false &&
            stm->p_to_o_write == false && stm->p_to_c_write == false) {
        return CLOSE_CONNECTION;
    }
    return COPY;
}
