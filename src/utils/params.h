#ifndef _PARAMS_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define _PARAMS_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include <stddef.h>
#include "args.h"

/** obtiene la base de datos de los usuarios del proxy */
struct users * get_global_users();

/** guarda los usuarios y administradores proporcionados por argumentos de linea de comandos */
int set_args(struct users *usrs, struct users *admin);

/** devuelve si el usuario dado pertenece o no a la base de datos del proxy */
bool is_valid_user(uint8_t * usr, uint8_t * password);

/** devuelve si el administrador dado pertenece o no a la base de datos del proxy */
bool is_valid_admin(uint8_t * usr, uint8_t * password);

/** incrementa en 1 la cantidad de usuarios en el proxy, y devuelve el valor viejo */
uint8_t get_number_of_users_and_increment();

#endif
