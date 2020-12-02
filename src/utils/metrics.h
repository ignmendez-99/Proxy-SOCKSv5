#ifndef PC_2020B_6_METRICS_H
#define PC_2020B_6_METRICS_H

void metric_add_connection();
void metric_remove_connection();
void metric_add_bytes_transferred(unsigned long long bytes);
void metric_add_stolen_password();


long metric_get_historical_connections();
uint16_t metric_get_concurrent_connections();
unsigned long long metric_get_bytes_transferred();
long metric_get_stolen_passwords();



#endif //PC_2020B_6_METRICS_H
