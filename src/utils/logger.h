#ifndef LOGGER_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define LOGGER_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "buffer.h"
#include "selector.h"

#define LOGGER_BUFFER_SIZE 4096 * 100

enum logging_level {
    INFO,  // Irá a stdout
    ERROR  // Irá a stderr
};

struct logger {
    buffer  buffer_stdout;   // Buffer exclusivo para imprimir a STDOUT
    buffer  buffer_stderr;   // Buffer exclusivo para imprimir a STDERR
    uint8_t *buffer_data_stdout;
    uint8_t *buffer_data_stderr;
};



/** inicia el logger */
int logger_init();

/** Guarda el string dado en un buffer para luego imprimirlo en pantalla de manera no bloqueante */
int proxy_log(enum logging_level level, fd_selector s, char *format, ...);

/** imprime en pantalla la data que esté en el buffer */
void logger_write(struct selector_key *key);

/** destruye el logger */
void logger_destroy();


static const fd_handler logger_handler = {
    .handle_write      = logger_write,
    .handle_read       = NULL,  // El logger solo escribirá
    .handle_close      = NULL,  // El logger solo escribirá
};

#endif
