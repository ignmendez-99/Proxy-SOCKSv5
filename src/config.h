#ifndef PC_2020B_6_CONFIG_H
#define PC_2020B_6_CONFIG_H

#include <stdint.h>
#include "utils/netutils.h"
#include "utils/selector.h"
#include "utils/stm.h"
#include "utils/buffer.h"
#include "stm/stm_hello.h"
#include "stm/stm_request.h"
#include "parsers/request_parser.h"
#include "stm/stm_copy.h"
#include "utils/args.h"
#include "stm/stm_connect_origin.h"
#include "stm/stm_doh.h"

// DOH Default Values
#define DOH_SERVER_IP "127.0.0.1"
#define DOH_SERVER_PORT 8053
#define DOH_SERVER_HOST "localhost"
#define DOH_SERVER_PATH "/getnsrecord"
#define DOH_SERVER_QUERY "?dns="
#define DOH_HTTP_BUFFER_SIZE 2048

// Proxy SOCKS Default Values
#define SOCKS_ADDR_IPV4 "0.0.0.0"
#define SOCKS_ADDR_IPV6 "::"
#define SOCKS_PORT 1080

// Manager Server Default Values
#define MANAGER_ADDR_IPV4 "127.0.0.1"
#define MANAGER_ADDR_IPV6 "::1"
#define MANAGER_PORT 8080

#define DISECTORS_ENABLED true

// Time in seconds for a state to timeout
#define STATE_TIMEOUT 60

struct socks5args * get_global_args();

void set_global_args(struct socks5args * args);


#endif //PC_2020B_6_CONFIG_H
