#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../utils/selector.h"
#include "my_protocol_server.h"
#include "my_proto_stm.h"

// Prototypes
static struct my_protocol_struct * create_new_myProtocol_struct(int client_sock);
static void destroy_my_proto(struct selector_key *key);

void my_protocol_passive_accept(struct selector_key *key) {

    struct sockaddr new_client_addr;
    struct my_protocol_struct *my_protocol_struct = NULL;
    socklen_t new_client_addr_len = sizeof(new_client_addr);

    int client_sock = accept(key->fd, &new_client_addr, &new_client_addr_len);
    if(client_sock == -1) {
        goto finally;
    }

    if(selector_fd_set_nio(client_sock) == -1) {
        goto finally;
    }

    my_protocol_struct = create_new_myProtocol_struct(client_sock);
    if(my_protocol_struct == NULL) {
        goto finally;
    }

    // Registramos el nuevo socket activo en el mismo selector que mira al socket pasivo
    if(selector_register(key->s, client_sock, &my_protocol_active_handler, OP_READ, my_protocol_struct) != SELECTOR_SUCCESS) {
        goto finally;
    }

    return;

finally:
    if(client_sock != -1) {
        // destruimos el socket si es que se abrió
        close(client_sock);
    }
    if(my_protocol_struct != NULL) {
        // destruimos la estructura si es que se creó
        destroy_my_proto(key);
    }
}


struct my_protocol_struct*
create_new_myProtocol_struct(int client_sock) {
    struct my_protocol_struct *my_protocol_struct = calloc(1, sizeof(struct my_protocol_struct));
    if(my_protocol_struct == NULL) {
        return NULL;
    }

    // Initialize state machine
    my_protocol_struct->my_stm.initial = MY_READING_HELLO; // Global state starts waiting for Hello
    my_protocol_struct->my_stm.max_state = MY_ERROR_GLOBAL_STATE;
    my_protocol_struct->my_stm.states = global_states_definition;
    my_protocol_struct->my_stm.current = NULL;
    stm_init(&(my_protocol_struct->my_stm));

    return my_protocol_struct;
}

static void destroy_my_proto(struct selector_key *key){
    struct my_protocol_struct *my_proto_struct = MY_PROTOCOL_ATTACHMENT(key);

    if(selector_unregister_fd(key->s, key->fd) != SELECTOR_SUCCESS) {
        exit(EXIT_FAILURE);
    }
    if(key->fd != -1) {
        close(key->fd);
    }

    // Liberamos los recursos del estado de MY_HELLO
    if(my_proto_struct->my_hello_state.read_buffer_data != NULL)
        free(my_proto_struct->my_hello_state.read_buffer_data);
    if(my_proto_struct->my_hello_state.write_buffer_data != NULL)
        free(my_proto_struct->my_hello_state.write_buffer_data);
    if(my_proto_struct->my_hello_state.my_hello_parser.user != NULL)
        free(my_proto_struct->my_hello_state.my_hello_parser.user);
    if(my_proto_struct->my_hello_state.my_hello_parser.password != NULL)
        free(my_proto_struct->my_hello_state.my_hello_parser.password);

    free(my_proto_struct);
}

void my_protocol_read(struct selector_key *key) {
    struct state_machine *stm  = &MY_PROTOCOL_ATTACHMENT(key)->my_stm;

     // Dependiendo del estado global en el que estemos, se tratará al Read de forma diferente
    enum my_proto_global_state state = stm_handler_read(stm, key);

    if(state == MY_ERROR_GLOBAL_STATE || state == MY_CLOSE_CONNECTION) {
        destroy_my_proto(key);
     }
}

void my_protocol_write(struct selector_key *key) {
    struct state_machine *stm  = &MY_PROTOCOL_ATTACHMENT(key)->my_stm;

    // Dependiendo del estado global en el que estemos, se tratará al Write de forma diferente
    enum my_proto_global_state state = stm_handler_write(stm, key);

    if(state == MY_ERROR_GLOBAL_STATE || state == MY_CLOSE_CONNECTION) {
        destroy_my_proto(key);
    }

}

void my_protocol_timeout(struct selector_key *key) {
    // nada
}
