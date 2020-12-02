#ifndef BUFFER_H_VelRDAxzvnuFmwEaR0ftrkIinkT
#define BUFFER_H_VelRDAxzvnuFmwEaR0ftrkIinkT

#include <stdbool.h>
#include <unistd.h>  // size_t, ssize_t
#include <stdint.h>


/**
 * buffer.c - buffer con acceso directo (útil para I/O) que mantiene
 *            mantiene puntero de lectura y de escritura.
 *
 *
 * Para esto se mantienen dos punteros, uno de lectura
 * y otro de escritura, y se provee funciones para
 * obtener puntero base y capacidad disponibles.
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * |   |   |   |   |   |   |
 * +---+---+---+---+---+---+
 * ↑                       ↑
 * W=0                     limit=6
 *
 * Invariantes:
 *    R <= W <= limit
 *
 * Se quiere escribir en el bufer cuatro bytes.
 *
 * ptr + 0 <- buffer_write_ptr(b, &wbytes), wbytes=6
 * n = read(fd, ptr, wbytes)
 * buffer_write_adv(b, n = 4)
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   |   |
 * +---+---+---+---+---+---+
 *                 ↑       ↑
 *                W=4      limit=6
 *
 * Quiero leer 3 del buffer
 * ptr + 0 <- buffer_read_ptr, wbytes=4
 * buffer_read_adv(b, 3);
 *
 *            R=3
 *             ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   |   |
 * +---+---+---+---+---+---+
 *                 ↑       ↑
 *                W=4      limit=6
 *
 * Quiero escribir 2 bytes mas
 * ptr + 4 <- buffer_write_ptr(b, &wbytes=2);
 * buffer_write_adv(b, 2)
 *
 *            R=3
 *             ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   | M |
 * +---+---+---+---+---+---+
 *                         ↑
 *                         limit=6
 *                         W=4
 * Compactación a demanda
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * | A |   | M |   |   |   |
 * +---+---+---+---+---+---+
 *             ↑           ↑
 *            W=3          limit=6
 *
 * Leo los tres bytes, como R == W, se auto compacta.
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * |   |   |   |   |   |   |
 * +---+---+---+---+---+---+
 * ↑                       ↑
 * W=0                     limit=6
 */
typedef struct buffer buffer;
struct buffer {
    uint8_t *data;

    /** límite superior del buffer. inmutable */
    uint8_t *limit;

    /** puntero de lectura */
    uint8_t *read;

    /** puntero de escritura */
    uint8_t *write;
};

/**
 * inicializa el buffer sin utilizar el heap
 */
void
buffer_init(buffer *b, const size_t n, uint8_t *data);

/**
 * @param nbyte: es un parametro de salida. Se guardará ahí la cantidad de bytes que se pueden escribir.
 * @returns un puntero hacia donde se pueden escribir `*nbytes` 
 * Se debe notificar mediante la función `buffer_read_adv'
 * 
 * Ejemplo:
 *         R=2
 *         ↓
 * +---+---+---+---+---+---+        buffer_write_ptr(b, &salida);
 * | O | L | A |   |   |   |        devuelve:
 * +---+---+---+---+---+---+                . un puntero a W
 *             ↑           ↑                . en salida, devuelve 3
 *             W=3         limit=6
 */
uint8_t *
buffer_write_ptr(buffer *b, size_t *nbyte);


/** Avanza el puntero de Write en el buffer, "bytes" posiciones */
void
buffer_write_adv(buffer *b, const ssize_t bytes);

/**
 * @param nbyte: es un parametro de salida. Se guardará ahí la cantidad de bytes que se pueden leer.
 * @returns un puntero hacia donde se pueden leer `*nbytes` 
 * Se debe notificar mediante la función `buffer_read_adv'
 * 
 * Ejemplo:
 *         R=2
 *         ↓
 * +---+---+---+---+---+---+        buffer_read_ptr(b, &salida);
 * | O | L | A |   |   |   |        devuelve:
 * +---+---+---+---+---+---+                . un puntero a R
 *             ↑           ↑                . en salida, devuelve 1
 *             W=3         limit=6
 */
uint8_t *
buffer_read_ptr(buffer *b, size_t *nbyte);


/** Avanza el puntero de Read en el buffer, "bytes" posiciones */
void
buffer_read_adv(buffer *b, const ssize_t bytes);


/** obtiene un byte */
uint8_t
buffer_read(buffer *b);

/** escribe un byte */
void
buffer_write(buffer *b, uint8_t c);

/** compacta el buffer */
void
buffer_compact(buffer *b);

/** Reinicia todos los punteros */
void
buffer_reset(buffer *b);

/** retorna true si hay bytes para leer del buffer */
bool
buffer_can_read(buffer *b);

/** retorna true si se pueden escribir bytes en el buffer */
bool
buffer_can_write(buffer *b);

/** devuelve el tamaño actual del buffer */
uint64_t get_buff_size();

/** Setea un nuevo tamaño del buffer
 * @return -1 si el tamaño dado es menor al mínimo tamaño soportado
 * @return 0 si logró setear el nuevo tamaño
 */
int set_buff_size(uint64_t size);

#endif
