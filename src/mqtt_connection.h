#ifndef _MQTTCONNECTION_H_
#define _MQTTCONNECTION_H_
#define LED_CONTROL_OVER_MQTT          DK_LED1 /*The LED to control over MQTT*/
#define IMEI_LEN 15
#define CGSN_RESPONSE_LENGTH (IMEI_LEN + 6 + 1) /* Add 6 for \r\nOK\r\n and 1 for \0 */
#define CLIENT_ID_LEN sizeof("nrf-") + IMEI_LEN
#include <stdbool.h>

extern bool mqtt_connected;

/**@brief Initialize the MQTT client structure
 */
int client_init(struct mqtt_client *client);

/**@brief Initialize the file descriptor structure used by poll.
 */
int fds_init(struct mqtt_client *c, struct pollfd *fds);

/**@brief Function to publish data on the configured topic
 */
int data_publish(struct mqtt_client *c, enum mqtt_qos qos,
	uint8_t *data, size_t len, const char *mqtt_publish_topic);

void provision_cert(void);

void set_user_pass();
void clear_user_pass();

void provision_all_tls_credentials(void);
#endif /* _CONNECTION_H_ */
