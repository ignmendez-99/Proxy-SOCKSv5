#ifndef STM_COPY_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define STM_COPY_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/selector.h"
#include "../utils/buffer.h"
#include "../parsers/pop3_parser.h"
#include "../parsers/http_parser.h"
#include "../parsers/login_parser.h"

struct copy_stm {
    // Usamos 2 buffers:
    //     . 1 en donde el cliente escribe y el servidor lee
    //     . 1 en donde el servidor escribe y el cliente lee
    buffer *client_to_serv_buff;
    buffer *serv_to_client_buff;
    uint8_t *client_to_serv_buff_data;
    uint8_t *serv_to_client_buff_data;

    ///          c_to_p_read                p_to_o_write
    //////////// -----------> ///////////// -----------> ////////////
    ///client///              ////proxy////              ///origin///
    //////////// <----------- ///////////// <----------- ////////////
    ///          p_to_c_write               o_to_p_read
    bool c_to_p_read, p_to_c_write, p_to_o_write, o_to_p_read;

	login_state login_state;
    login_data login;
};


/** inicializa las variables necesarias para operar en este estado COPY */
unsigned
copy_init(const unsigned state, struct selector_key *key);

/** lee los datos que alguna de las 2 partes le envió al proxy, y las guarda en un buffer para su futura escritura */
unsigned
copy_read(struct selector_key *key);

/** escribe los datos que se guardaron anteriormente hacia la parte que corresponde (cliente o servidor) */
unsigned
copy_write(struct selector_key *key);


#endif
