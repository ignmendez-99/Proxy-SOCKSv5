#include <stdint.h>
#include "metrics.h"

long historical_connections = 0;
uint16_t concurrent_connections = 0;
unsigned long long bytes_transferred = 0;
long passwords_stolen = 0;

void metric_add_connection() {
	historical_connections ++;
	concurrent_connections ++;
}

void metric_remove_connection() {
	concurrent_connections --;
}

void metric_add_bytes_transferred(unsigned long long bytes) {
	bytes_transferred += bytes;
}

void metric_add_stolen_password() {
	passwords_stolen ++;
}

long metric_get_historical_connections() {
	return historical_connections;
}

uint16_t metric_get_concurrent_connections() {
	return concurrent_connections;
}

unsigned long long metric_get_bytes_transferred() {
	return bytes_transferred;
}

long metric_get_stolen_passwords() {
	return passwords_stolen;
}



