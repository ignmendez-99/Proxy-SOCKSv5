#ifndef STM_CONNECT_ORIGIN_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define STM_CONNECT_ORIGIN_H_68f9cbe0499150288c6b905552e201fb15e0b420


#include "../utils/selector.h"
#include "../parsers/dns_parser.h"

struct connect_origin_stm {
	dns_qtype connection_type;
	size_t answers_attempted;
};

/** Inicializa las variables para el estado de CONNECT_ORIGIN
 *  Intenta conectarse al Origin Server
 */
unsigned
connect_origin_init(const unsigned state, struct selector_key *key);


/** Verifica si la conexión con el Origin Server fue exitosa o no */
unsigned
connect_origin_write(struct selector_key *key);

/** Si se llegó al máximo tiempo de espera al intentar conectarnos al Origin Server, nos intentamo conectar usando otra IP
 *  En caso de no tener otra IP para seguir probando, se considera que es imposible conectarnos al Servidor
 */
unsigned
connect_origin_timeout(struct selector_key *key);



#endif
