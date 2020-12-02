#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "logger.h"

// The one and only logger in the whole proxy
static struct logger global_logger;


int logger_init() {

    // Initialize STDOUT
    global_logger.buffer_data_stdout = calloc(LOGGER_BUFFER_SIZE, sizeof(uint8_t));
    if(global_logger.buffer_data_stdout == NULL) {
        return -1;
    }
    buffer_init(&global_logger.buffer_stdout, LOGGER_BUFFER_SIZE, global_logger.buffer_data_stdout);

    // Initialize STDERR
    global_logger.buffer_data_stderr = calloc(LOGGER_BUFFER_SIZE, sizeof(uint8_t));
    if(global_logger.buffer_data_stderr == NULL) {
        free(global_logger.buffer_data_stdout);
        return -1;
    }
    buffer_init(&global_logger.buffer_stderr, LOGGER_BUFFER_SIZE, global_logger.buffer_data_stderr);

    return 0;
}

struct logger * getLogger() {
    return &global_logger;
}

int proxy_log(enum logging_level level, fd_selector s, char *format, ...) {

    int fd;
    buffer *buff;
    if(level == INFO) {
        fd = STDOUT_FILENO;
        buff = &global_logger.buffer_stdout;
    } else if(level == ERROR) {
        fd = STDERR_FILENO;
        buff = &global_logger.buffer_stderr;
    } else {
        // Bad use of logger
        return -1;
    }

    if(buffer_can_write(buff)) {
        size_t nbytes;
        uint8_t *where_to_write = buffer_write_ptr(buff, &nbytes);
        va_list args;

        va_start(args, format);
        int ret = vsnprintf( (char*)where_to_write, nbytes, (char*)format, args);
        va_end(args);
        if(ret <= 0)
            return -1;

        buffer_write_adv(buff, ret);
        if(selector_set_interest(s, fd, OP_WRITE) != SELECTOR_SUCCESS)
            return -1;
    }

    return 0;
}

void logger_write(struct selector_key *key) {

    buffer *buff;

    if(key->fd == STDOUT_FILENO) {
        buff = &global_logger.buffer_stdout;
    } else if(key->fd == STDERR_FILENO) {
        buff = &global_logger.buffer_stderr;
    } else {
        // IMPOSSIBLE
        exit(EXIT_FAILURE);
    }

    size_t nbytes;
    uint8_t * where_to_read = buffer_read_ptr(buff, &nbytes);
    int ret = write(key->fd, where_to_read, nbytes);
    if (ret <= 0) {
        return;
    }

    buffer_read_adv(buff, ret);
    if (!buffer_can_read(buff)) {
        // Ya evacué lo que había para escribir. Dormimos al FD hasta que haya más cosas para escribir
        selector_set_interest_key(key, OP_NOOP);
    }
}

void logger_destroy() {
    free(global_logger.buffer_data_stdout);
    free(global_logger.buffer_data_stderr);
}
