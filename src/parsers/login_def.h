#ifndef PC_2020B_6_LOGIN_DEF_H
#define PC_2020B_6_LOGIN_DEF_H

#include <stdbool.h>


typedef enum {
	COMMUNICATION_SERVER_SIDE,
	COMMUNICATION_CLIENT_SIDE
} communication_actor;

typedef struct {
	char * user;
	char * pass;
	bool valid;
} login_data;

#endif
