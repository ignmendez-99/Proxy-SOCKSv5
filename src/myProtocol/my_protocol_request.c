#include <unistd.h>
#include <sys/socket.h>  // socket
#include <stdlib.h>
#include <string.h>
#include "../utils/buffer.h"
#include "../utils/selector.h"
#include "../utils/netutils.h"
#include "../myProtocol/my_protocol_server.h"
#include "../myProtocol/my_proto_stm.h"
#include "../utils/metrics.h"
#include "../parsers/my_request_parser.h"


#define ENOUGH_SPACE_TO_CONNECTION_LOG 200

// Prototypes
static void free_everything(struct my_protocol_struct* my_protocol_struct);


unsigned
my_request_read_init(const unsigned state, struct selector_key *key) {
	struct my_protocol_struct *my_protocol_struct = MY_PROTOCOL_ATTACHMENT(key);
    struct my_request_stm *request_stm = &MY_PROTOCOL_ATTACHMENT(key)->my_request_state;

    // Initialize read buffer
    request_stm->read_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(request_stm->read_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&request_stm->rb, get_buff_size(), request_stm->read_buffer_data);

    // Initialize write buffer
    request_stm->write_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(request_stm->write_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&request_stm->wb, get_buff_size(), request_stm->write_buffer_data);

    my_request_parser_init(&request_stm->my_request_parser);

    return state;
finally:
    free_everything(my_protocol_struct);
    return MY_ERROR_GLOBAL_STATE;
}

char * convertLongToString(long l, int *size) {
    char * aux;
    long l2 = l;
    uint8_t digits = 0;

    while(l2 > 0) {
        digits++;
        l2 = l2 / 10;
    }
    *size = digits;
    if(l == 0)
        *size = 1;

    aux = malloc(*size);

    if(l == 0)
        aux[0] = '0';
    while(l > 0) {
        aux[digits - 1] = (l % 10) + '0';
        l = l / 10;
        digits--;
    }

    return aux;
}

char * convertUnsignedLongLongToString(unsigned long long l, int *size) {
    char * aux;
    unsigned long long l2 = l;
    uint8_t digits = 0;

    while(l2 > 0) {
        digits++;
        l2 = l2 / 10;
    }
    *size = digits;
    if(l == 0)
        *size = 1;

    aux = malloc(*size);

    if(l == 0)
        aux[0] = '0';
    while(l > 0) {
        aux[digits - 1] = (l % 10) + '0';
        l = l / 10;
        digits--;
    }

    return aux;
}

char * convertUint16_tToString(uint16_t num, uint8_t * len){
    char * ret;
    uint16_t num2 = num;
    uint8_t digits = 0;
    
    while(num2 > 0){
        digits++;
        num2 = num2 / 10;
    }

    *len = digits;
    if(num == 0)
        *len = 1;

    ret = malloc(*len);

    if(num == 0)
        ret[0] = '0';
    while(num > 0) {
        ret[digits - 1] = (num % 10) + '0';
        num = num / 10;
        digits--;
    }
    

    return ret;
}

uint64_t convertStringToUint64_t(const uint8_t * str, uint8_t len){
    uint64_t ret = 0;
    int i = 0;
    
    for(; i < len; i++){
        ret = ret * 10;
        ret = ret + str[i] - '0';
    }

    return ret;
}

unsigned
my_request_read(struct selector_key *key) {
	struct my_protocol_struct *my_protocol_struct = MY_PROTOCOL_ATTACHMENT(key);
    struct my_request_stm *request_stm = &MY_PROTOCOL_ATTACHMENT(key)->my_request_state;

    size_t nbytes;
    uint8_t *where_to_write = buffer_write_ptr(&request_stm->rb, &nbytes);
    ssize_t ret = recv(key->fd, where_to_write, nbytes, 0);  // Non blocking !
    int len;
    int buffer_size;

    enum my_proto_global_state returned_state = MY_READING_REQUEST; // current state
    if(ret > 0) {
        buffer_write_adv(&request_stm->rb, ret);
	    enum my_request_state state = my_consume_request_buffer(&request_stm->rb, &request_stm->my_request_parser);
        if(state == my_request_finished) {
            switch(request_stm->my_request_parser.command){

                case get_historical_n_of_connections:
                    request_stm->my_request_parser.reply.data = convertLongToString(metric_get_historical_connections(), &len);
                    request_stm->my_request_parser.reply.len = len;
                    break;

                case get_n_of_concurrent_connections:
                    request_stm->my_request_parser.reply.data = convertLongToString(metric_get_concurrent_connections(), &len);
                    request_stm->my_request_parser.reply.len = len;
                    break;

                case get_n_of_bytes_transferred:
                    request_stm->my_request_parser.reply.data = convertUnsignedLongLongToString(metric_get_bytes_transferred(), &len);
                    request_stm->my_request_parser.reply.len = len;
                    break;

                case set_buffer_size:
                    buffer_size = set_buff_size(convertStringToUint64_t(request_stm->my_request_parser.param1, request_stm->my_request_parser.lparam1));
                    if (buffer_size == 0){
                        request_stm->my_request_parser.reply.data = (char*)request_stm->my_request_parser.param1;
                        request_stm->my_request_parser.reply.len = request_stm->my_request_parser.lparam1;
                    }else{
                        request_stm->my_request_parser.reply.code = INVALID_PARAM;
                        request_stm->my_request_parser.reply.data = "Buffer size too small";
                        request_stm->my_request_parser.reply.len = 21;
                    }
                    break;
                // Imposible state
                default:
                    exit(EXIT_FAILURE);
            }

            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) 
                goto finally;
            
            if(my_request_marshall(&request_stm->wb, &request_stm->my_request_parser) < 0)
                goto finally;
            
            returned_state = MY_WRITING_REQUEST;
        } else if(state == my_request_has_error) {
            if(my_request_marshall(&request_stm->wb, &request_stm->my_request_parser) < 0) {
                goto finally;
            }
            returned_state = MY_WRITING_REQUEST;  // Vamos a escribirle al Cliente un Response de respuesta negativa
        } else {
            // El Request parser terminó, pero no llegó a un estado final. Tenemos que esperar a que llegue la parte
            // que falta del Request
        } 

    } else {
        goto finally;
    }
    return returned_state;

finally:
    free_everything(my_protocol_struct);
    return MY_ERROR_GLOBAL_STATE;
}


unsigned
my_request_write(struct selector_key *key) {
    struct my_protocol_struct *my_protocol_struct = MY_PROTOCOL_ATTACHMENT(key);
    struct my_request_stm *request_stm = &MY_PROTOCOL_ATTACHMENT(key)->my_request_state;

    size_t nbytes;
    uint8_t *where_to_read = buffer_read_ptr(&request_stm->wb, &nbytes);
    ssize_t ret = send(key->fd, where_to_read, nbytes, MSG_NOSIGNAL);

    if(ret > 0) {
        buffer_read_adv(&request_stm->wb, nbytes);
        if(!buffer_can_read(&request_stm->wb)) {
            // if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS)
            //     goto finally;
            
            return MY_CLOSE_CONNECTION;

        } else {
            // Exit here, and keep waiting for future calls to this function to end reading buffer
            return MY_WRITING_REQUEST;
        }
    } else {
        goto finally;
    }

finally:
    free_everything(my_protocol_struct);
    return MY_ERROR_GLOBAL_STATE;
}

void
my_request_write_close(const unsigned state, struct selector_key *key) {
	struct my_protocol_struct *my_protocol_struct = MY_PROTOCOL_ATTACHMENT(key);

    // Clean up all resources used for Request
    free_everything(my_protocol_struct);
}

static void
free_everything(struct my_protocol_struct* my_protocol_struct) {
    struct my_request_stm * request_stm = &my_protocol_struct->my_request_state;


    if(request_stm->my_request_parser.reply.data != NULL && request_stm->my_request_parser.reply.code != INVALID_PARAM && request_stm->my_request_parser.reply.code != INVALID_COMMAND)
        free((void*)request_stm->my_request_parser.reply.data);

    if(request_stm->read_buffer_data != NULL)
        free(request_stm->read_buffer_data);
    
    if(request_stm->write_buffer_data != NULL)
        free(request_stm->write_buffer_data);

    if(request_stm->my_request_parser.param1 != NULL && request_stm->my_request_parser.reply.code == INVALID_PARAM)
        free(request_stm->my_request_parser.param1);
//
//    if(request_stm->my_request_parser.param2 != NULL)
//        free(request_stm->my_request_parser.param2);
}
