#ifndef SOCKET_CREATION_ERRORS_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define SOCKET_CREATION_ERRORS_H_68f9cbe0499150288c6b905552e201fb15e0b420

enum socket_creation_error {
    socket_error,
    socket_bind_error,
    socket_listen_error,
    socket_inet_pton_error,
    socket_selector_fd_set_nio_error,
    socket_setsockopt_error,
    /* ADD NEW HERE */
    socket_no_fail,
};

// Error descriptions corresponding to each socket_creation_error
static const char* socket_error_description[] = {
        "Error in socket()",
        "Error in bind()",
        "Error in listen()",
        "Error in inet_pton()",
        "Error in selector_fd_set_nio()",
        "Error in setsockopt()",
        /* ADD NEW HERE */
};


#endif
