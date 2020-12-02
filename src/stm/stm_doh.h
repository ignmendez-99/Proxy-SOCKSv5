#ifndef PC_2020B_6_STM_DOH_H
#define PC_2020B_6_STM_DOH_H

#include <netdb.h>
#include "../utils/selector.h"
#include "../parsers/dns_parser.h"
#include "../utils/buffer.h"
#include "../parsers/http_parser.h"

struct doh_stm {
	buffer * http_buf;

	http_parse_state parser_http_state;
	http_response http_response;

	dns_question dns_query_question;
	dns_query_bytes query_bytes;
	dns_response * response;
};

void
doh_init_state(struct doh_stm * doh_state);

unsigned
doh_init_connection(const unsigned state, struct selector_key *key);

unsigned
doh_query(struct selector_key *key);

void
doh_query_close(const unsigned int state, struct selector_key *key);

unsigned
doh_init_response(const unsigned int state, struct selector_key *key);

unsigned
doh_response(struct selector_key *key);


#endif //PC_2020B_6_STM_DOH_H
