#ifndef SOCKS5_STM_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define SOCKS5_STM_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/stm.h"
#include "../parsers/hello_parser.h"
#include "../parsers/request_parser.h"
#include "stm_hello.h"
#include "stm_request.h"
#include "stm_copy.h"
#include "stm_connect_origin.h"
#include "stm_doh.h"
#include "stm_hello_auth.h"


/** Maquina de estados que define cada posible estado de comunicacion entre cliente-proxy-servidor **/
enum socks5_global_state {

    /**
     *  . _Initial state_
     *  .File Descriptor --> only reading from client
     *  .Jump to:
     *      .When finished reading && Hello was well-formed --> WRITING_HELLO (will write a successful hello-reply)
     *      .When error || Hello was malformed  --> WRITING_HELLO (will write an unsuccessful hello-reply)
     */
    READING_HELLO,

    /**
     *  .File Descriptor --> only writing to client
     *  .Jump to:
     *      .When finished writing successful hello-reply && not authentication required --> READING_REQUEST
     *      .When finished writing successful hello-reply && authentication required --> READING_HELLO_AUTH
     *      .When error || when finished writing unsuccessful hello-reply --> ERROR_GLOBAL_STATE
     */
    WRITING_HELLO,

    /**
     *  .File Descriptor --> only reading from client
     *  .Jump to:
     *      .When finished reading auth && authentication was successful --> WRITING_HELLO_AUTH (will write a successful reply)
     *      .When error || authentication was unsuccessful --> WRITING_HELLO_AUTH (will write an unsuccessful reply)
     */
    READING_HELLO_AUTH,

    /**
     *  .File Descriptor --> only writing to client
     *  . Jump to:
     *      .When finished writing successful reply --> READING_REQUEST
     *      .When error || when finished writing unsuccessful reply --> ERROR_GLOBAL_STATE
     */
    WRITING_HELLO_AUTH,

    /**
     *  .File Descriptor --> only reading from client
     *  .Jump to:
     *      .When finished reading Request && Request was well-formed &&
     *          . Request was to connect to an IPv4 --> CONNECT_ORIGIN
     *          . Request was to connect to an IPv6 --> CONNECT_ORIGIN
     *          . Request was to connect to a FQDN  --> DNS_QUERY
     *      .When error || Request was malformed --> WRITING_REQUEST (will write an unsuccessful reply)
     */
    READING_REQUEST,

    /**
     * .File Descriptor --> only writing to DoH server
     * .Jump to:
     * 		. When finished sending query --> DNS_RESPONSE
     * 		. When query sent partially --> DNS_QUERY
     * 		. On error --> WRITING_REQUEST (unsuccessful reply)
     */
    DNS_QUERY,

	/**
 	* .File Descriptor --> only reading from DoH server
 	* .Jump to:
 	* 		. When DoH response received and parsed correctly --> CONNECT_ORIGIN
 	* 		. When response received partially --> DNS_RESPONSE
 	* 		. On error || On HTTP code != 200 || On dns reply code == 3 (invalid domain name) --> WRITING_REQUEST  (unsuccessful reply)
 	*/
    DNS_RESPONSE,

    /**
     *  .File Descriptor --> only writing to origin to check connectivity
     *  .Jump to:
     *      .If connectivity was established --> WRITING_REQUEST
     *      .If connectivity wasn't established && we have been through DNS's states && we have still IPs to try to connect --> DNS_QUERY
     *      .Else --> WRITING_REQUEST (will write a negative reply)
     */
    CONNECT_ORIGIN,

    /**
     *  . File Descriptor --> only writing to client
     *  . Jump to:
     *      . If Reply sent was a successful one --> COPY
     *      . If error || if Reply sent was an unsuccessful one --> ERROR_GLOBAL_STATE
     */
    WRITING_REQUEST,

    /**
     *  .File Descriptor:
     *      . Client: starts only reading. Will gain and lose write interest as required.
     *      . Origin: starts only reading. Will gain and lose write interest as required.
     *  . Jump to:
     *      . If both parts decided to close the connection --> CLOSE_CONNECTION
     *      . If error --> ERROR_GLOBAL_STATE
     */
    COPY,

    /**
     *  Closes the client FD, origin FD, DoH FD (will only close them if they are open).
     *  Unregister all these FDs from the selector.
     *  Frees all resources used for this socks5 connection.
     */
    CLOSE_CONNECTION,

    /**
     *  Closes the client FD, origin FD, DoH FD (will only close them if they are open).
     *  Unregister all these FDs from the selector.
     *  Frees all resources used for this socks5 connection.
     */
    ERROR_GLOBAL_STATE
};


static const struct state_definition global_states_definition[] = {
    {
        .state          = READING_HELLO,		// stm: 0
        .on_arrival     = hello_read_init,
        .on_read_ready  = hello_read
    },{
        .state          = WRITING_HELLO,		// stm: 1
        .on_write_ready = hello_write
    },{
        .state          = READING_HELLO_AUTH,	// stm: 2
        .on_arrival     = hello_auth_read_init,
        .on_read_ready  = hello_auth_read
    },{
        .state          = WRITING_HELLO_AUTH,
        .on_write_ready  = hello_auth_write
    },{
        .state          = READING_REQUEST,		// stm: 4
        .on_arrival     = request_read_init,
        .on_read_ready  = request_read
    },{
		.state          = DNS_QUERY,			// stm: 5
		.on_arrival		= doh_init_connection,
		.on_write_ready = doh_query,
		.on_departure	= doh_query_close,
    },{
		.state          = DNS_RESPONSE,			// stm: 6
		.on_arrival		= doh_init_response,
		.on_read_ready	= doh_response,
    },{
        .state          = CONNECT_ORIGIN,		// stm: 7
        .on_arrival     = connect_origin_init,
        .on_write_ready = connect_origin_write,
        .on_timeout		= connect_origin_timeout
    },{
        .state          = WRITING_REQUEST,		// stm: 8
        .on_write_ready = request_write
    },{
        .state          = COPY,					// stm: 9
        .on_arrival     = copy_init,
        .on_read_ready  = copy_read,
        .on_write_ready = copy_write,
    },{
        .state          = CLOSE_CONNECTION		// stm: 10
    },{
        .state          = ERROR_GLOBAL_STATE	// stm: 11
    }
};


#endif
