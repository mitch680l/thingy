#ifndef SHELL_MQTT_H
#define SHELL_MQTT_H

/** Maximum length for string settings (must match your .c) */
#define MQTT_MAX_STR_LEN 128

/* In-RAM copies of each setting, defined in shell_commands.c */
extern char mqtt_client_id[MQTT_MAX_STR_LEN];               
extern char mqtt_publish_topic[MQTT_MAX_STR_LEN];
extern char mqtt_subscribe_topic[MQTT_MAX_STR_LEN];
extern char mqtt_broker_host[MQTT_MAX_STR_LEN];
extern int  mqtt_broker_port;
extern int  mqtt_publish_interval;
extern int  mqtt_keepalive;

/* call this before you read them */
void shell_mqtt_init(void);

#endif /* SHELL_MQTT_H */