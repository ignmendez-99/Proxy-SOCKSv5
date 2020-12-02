#include "params.h"
#include <string.h>
#include <stdlib.h>

static uint8_t number_of_users = 0;
static struct users *globalUsers = NULL;
static struct users *global_admin = NULL;

struct users * get_global_users() {
    return globalUsers;
}

int set_args(struct users *usrs, struct users *admin) {
    if(globalUsers == NULL) {
        globalUsers = calloc(MAX_USERS, sizeof(*globalUsers));
        if(globalUsers == NULL) {
            number_of_users = 0;
            return 1;
        }
    }
    for(uint8_t i = 0; i < number_of_users; i++) {

        size_t aux1 = strlen(usrs[i].name) + 1;
        size_t aux2 = strlen(usrs[i].pass) + 1;
        globalUsers[i].name = malloc( aux1 );
        globalUsers[i].pass = malloc( aux2 );
        memcpy(globalUsers[i].name, usrs[i].name, aux1);
        memcpy(globalUsers[i].pass, usrs[i].pass, aux2);
    }

    if(global_admin == NULL) {
        global_admin = malloc(sizeof(*global_admin));
        if(global_admin == NULL) {
            return 1;
        }
    }

    if(admin->name == NULL || admin->pass == NULL) {
        return 1;
    }

    size_t aux1 = strlen(admin->name) + 1;
    size_t aux2 = strlen(admin->pass) + 1;
    global_admin->name = malloc( aux1 );
    global_admin->pass = malloc( aux2 );
    memcpy(global_admin->name, admin->name, aux1);
    memcpy(global_admin->pass, admin->pass, aux2);

    return 0;
}

bool is_valid_user(uint8_t * usr, uint8_t * password){
    for(int i = 0; i < number_of_users; i++) {
        const char* aux_name = globalUsers[i].name;
        const char* aux_pass = globalUsers[i].pass;
        if (strcmp((const char *) usr, aux_name) == 0 && strcmp((const char *) password, aux_pass) == 0)
            return true;
    }
    return false;
}

bool is_valid_admin(uint8_t * usr, uint8_t * password) {
    const char* aux_name = global_admin->name;
    const char* aux_pass = global_admin->pass;
    if (strcmp((const char *) usr, aux_name) == 0 && strcmp((const char *) password, aux_pass) == 0)
        return true;
    return false;
}

uint8_t get_number_of_users_and_increment(){
    const uint8_t aux = number_of_users;
    number_of_users++;
    return aux;
}
