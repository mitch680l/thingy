#ifndef _MQTTCONNECTION_H_
#define _MQTTCONNECTION_H_

#define LED_CONTROL_OVER_MQTT          DK_LED1
#define IMEI_LEN 15
#define CGSN_RESPONSE_LENGTH (IMEI_LEN + 6 + 1)
#define CLIENT_ID_LEN sizeof("nrf-") + IMEI_LEN

#include <stdbool.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>

extern bool mqtt_connected;
/**
 * @brief Initialize the MQTT client structure
 */
int client_init(struct mqtt_client *client);

/**
 * @brief Initialize the file descriptor structure used by poll
 */
int fds_init(struct mqtt_client *c, struct pollfd *fds);

/**
 * @brief Function to publish data on the configured topic
 */
int data_publish(struct mqtt_client *c, enum mqtt_qos qos,
                 uint8_t *data, size_t len, const char *mqtt_publish_topic);



static int publish_all(void);

static void mqtt_handle(void);
void provision_cert(void);
void provision_all_tls_credentials(void);

#endif /* _CONNECTION_H_ */
