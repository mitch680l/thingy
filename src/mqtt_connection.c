#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>
#include <nrf_modem_at.h>
#include <dk_buttons_and_leds.h>
#include <modem/modem_key_mgmt.h>
#include "mqtt_connection.h"
#include "shell_commands.h"

#define TLS_SEC_TAG 42

static uint8_t rx_buffer[256];
static uint8_t tx_buffer[516];
static uint8_t payload_buf[256];
static struct sockaddr_storage broker;
static uint16_t packet_id;

LOG_MODULE_REGISTER(mqtt_conn, LOG_LEVEL_INF);

bool mqtt_connected = false;

static struct mqtt_utf8 struct_pass;
static struct mqtt_utf8 struct_user;
static char user_buf[64];
static char pass_buf[64];

void set_user_pass(void)
{
    const char *password = get_config("password");
    if (!password || strcmp(password, "NULL") == 0) {
        LOG_ERR("Failed to get password from config");
        return;
    }
    strncpy(pass_buf, password, sizeof(pass_buf) - 1);
    pass_buf[sizeof(pass_buf) - 1] = '\0';

    const char *username = get_config("username");
    if (!username || strcmp(username, "NULL") == 0) {
        LOG_ERR("Failed to get username from config");
        return;
    }
    strncpy(user_buf, username, sizeof(user_buf) - 1);
    user_buf[sizeof(user_buf) - 1] = '\0';

    LOG_INF("Setting MQTT username: %s", user_buf);
    LOG_INF("Setting MQTT password: %s", pass_buf);

    struct_pass.utf8 = (uint8_t *)pass_buf;
    struct_pass.size = strlen(pass_buf);
    struct_user.utf8 = (uint8_t *)user_buf;
    struct_user.size = strlen(user_buf);
}

void clear_user_pass(void)
{
    struct_pass.utf8 = NULL;
    struct_pass.size = 0;
    struct_user.utf8 = NULL;
    struct_user.size = 0;
    LOG_INF("Cleared MQTT username and password");
}

void provision_all_tls_credentials(void)
{
    int err;
    bool ca_cert_exists = false;
    bool public_cert_exists = false;
    bool private_key_exists = false;

    LOG_INF("PROVISION TLS CRED");

    err = modem_key_mgmt_exists(TLS_SEC_TAG,
                                MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, &ca_cert_exists);
    err = modem_key_mgmt_exists(TLS_SEC_TAG,
                                MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT, &public_cert_exists);
    err = modem_key_mgmt_exists(TLS_SEC_TAG,
                                MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT, &private_key_exists);

    if (ca_cert_exists) {
        LOG_INF("CA cert exists");
    }
    if (public_cert_exists) {
        LOG_INF("Client cert exists");
    }
    if (private_key_exists) {
        LOG_INF("Private key exists");
    }
    if (!ca_cert_exists || !public_cert_exists || !private_key_exists) {
        LOG_INF("YOU NEED TO PROVISION AWS TLS CREDENTIALS");
    }
}

/**
 * @brief Get the payload of received data
 */
static int get_received_payload(struct mqtt_client *c, size_t length)
{
    int ret;
    int err = 0;

    if (length > sizeof(payload_buf)) {
        err = -EMSGSIZE;
    }

    while (length > sizeof(payload_buf)) {
        ret = mqtt_read_publish_payload_blocking(
                c, payload_buf, (length - sizeof(payload_buf)));
        if (ret == 0) {
            return -EIO;
        } else if (ret < 0) {
            return ret;
        }
        length -= ret;
    }

    ret = mqtt_readall_publish_payload(c, payload_buf, length);
    if (ret) {
        return ret;
    }

    return err;
}

/**
 * @brief Generate next packet ID
 */
static uint16_t mqtt_next_packet_id(void)
{
    packet_id++;
    if (packet_id == 0) {
        packet_id = 1;
    }
    return packet_id;
}

/**
 * @brief Print strings without null-termination
 */
static void data_print(uint8_t *prefix, uint8_t *data, size_t len)
{
    char buf[len + 1];

    memcpy(buf, data, len);
    buf[len] = 0;
    LOG_INF("%s%s", (char *)prefix, (char *)buf);
}

/**
 * @brief Publish data on the configured topic
 */
int data_publish(struct mqtt_client *c, enum mqtt_qos qos,
                 uint8_t *data, size_t len, const char *mqtt_publish_topic)
{
    struct mqtt_publish_param param;
    int start, setup_time, publish_start, publish_time;

    if (!mqtt_connected) {
        LOG_ERR("MQTT not connected, cannot publish");
        return -ENOTCONN;
    }

    LOG_DBG("Starting data_publish, payload size: %d", len);
    start = k_uptime_get_32();

    param.message.topic.qos = qos;
    param.message.topic.topic.utf8 = (uint8_t *)mqtt_publish_topic;
    param.message.topic.topic.size = strlen(mqtt_publish_topic);
    param.message.payload.data = data;
    param.message.payload.len = len;
    param.message_id = mqtt_next_packet_id();
    param.dup_flag = 0;
    param.retain_flag = 0;

    setup_time = k_uptime_get_32() - start;
    LOG_DBG("Parameter setup took: %d ms", setup_time);

    publish_start = k_uptime_get_32();
    int result = mqtt_publish(c, &param);
    publish_time = k_uptime_get_32() - publish_start;

    LOG_DBG("mqtt_publish() took: %d ms, result: %d", publish_time, result);
    
    if (result != 0) {
        LOG_ERR("MQTT publish failed: %d", result);
        mqtt_connected = false;
    }
    
    return result;
}

/**
 * @brief MQTT client event handler
 */
void mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
    int err;

    switch (evt->type) {
    case MQTT_EVT_CONNACK:
        if (evt->result != 0) {
            LOG_ERR("MQTT connect failed: %d", evt->result);
            mqtt_connected = false;
            break;
        }
        LOG_INF("MQTT client connected");
        mqtt_connected = true;
        break;

    case MQTT_EVT_DISCONNECT:
        LOG_INF("MQTT client disconnected: %d", evt->result);
        mqtt_connected = false;
        break;

    case MQTT_EVT_PUBLISH:
    {
        const struct mqtt_publish_param *p = &evt->param.publish;
        LOG_INF("MQTT PUBLISH result=%d len=%d", evt->result, p->message.payload.len);

        err = get_received_payload(c, p->message.payload.len);

        if (p->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
            const struct mqtt_puback_param ack = {
                .message_id = p->message_id
            };
            mqtt_publish_qos1_ack(c, &ack);
        }

        if (err >= 0) {
            data_print("Received: ", payload_buf, p->message.payload.len);
            if (strcmp((char*)payload_buf, "reset") == 0) {
                LOG_INF("Received reset — rebooting!");
                sys_reboot(SYS_REBOOT_COLD);
            }
        } else if (err == -EMSGSIZE) {
            LOG_ERR("Received payload (%d bytes) is larger than buffer (%d bytes)",
                    p->message.payload.len, sizeof(payload_buf));
        } else {
            LOG_ERR("get_received_payload failed: %d", err);
            LOG_INF("Disconnecting MQTT client...");
            
            err = mqtt_disconnect(c, NULL);
            if (err) {
                LOG_ERR("Could not disconnect: %d", err);
            }
            mqtt_connected = false;
        }
        break;
    }

    case MQTT_EVT_PUBACK:
        if (evt->result != 0) {
            LOG_ERR("MQTT PUBACK error: %d", evt->result);
            break;
        }
        LOG_INF("PUBACK packet id: %u", evt->param.puback.message_id);
        break;

    case MQTT_EVT_SUBACK:
        if (evt->result != 0) {
            LOG_ERR("MQTT SUBACK error: %d", evt->result);
            break;
        }
        LOG_INF("SUBACK packet id: %u", evt->param.suback.message_id);
        break;

    case MQTT_EVT_PINGRESP:
        if (evt->result != 0) {
            LOG_ERR("MQTT PINGRESP error: %d", evt->result);
            mqtt_connected = false;
        }
        break;

    default:
        LOG_INF("Unhandled MQTT event type: %d", evt->type);
        break;
    }
}

/**
 * @brief Resolves the configured hostname and initializes the MQTT broker structure
 */
static int broker_init(void)
{
    int err;
    struct addrinfo *result;
    struct addrinfo *addr;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    const char *mqtt_broker_host = get_config("mqtt_broker_host");

    err = getaddrinfo(mqtt_broker_host, NULL, &hints, &result);
    if (err) {
        LOG_ERR("getaddrinfo failed: %d", err);
        return -ECHILD;
    }

    addr = result;

    while (addr != NULL) {
        if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
            struct sockaddr_in *broker4 = ((struct sockaddr_in *)&broker);
            char ipv4_addr[NET_IPV4_ADDR_LEN];

            broker4->sin_addr.s_addr = ((struct sockaddr_in *)addr->ai_addr)->sin_addr.s_addr;
            broker4->sin_family = AF_INET;
            broker4->sin_port = htons(mqtt_broker_port);

            inet_ntop(AF_INET, &broker4->sin_addr.s_addr, ipv4_addr, sizeof(ipv4_addr));
            LOG_INF("IPv4 Address found %s", ipv4_addr);
            break;
        } else {
            LOG_ERR("ai_addrlen = %u should be %u or %u",
                    (unsigned int)addr->ai_addrlen,
                    (unsigned int)sizeof(struct sockaddr_in),
                    (unsigned int)sizeof(struct sockaddr_in6));
        }
        addr = addr->ai_next;
    }

    freeaddrinfo(result);
    return err;
}

/**
 * @brief Function to get the client id
 */
static const uint8_t* client_id_get(void)
{
    static uint8_t client_id[MAX(sizeof(mqtt_client_id), CLIENT_ID_LEN)];

    if (strlen(mqtt_client_id) > 0) {
        snprintf(client_id, sizeof(client_id), "%s", mqtt_client_id);
        goto exit;
    }

    char imei_buf[CGSN_RESPONSE_LENGTH + 1];
    int err;

    err = nrf_modem_at_cmd(imei_buf, sizeof(imei_buf), "AT+CGSN");
    if (err) {
        LOG_ERR("Failed to obtain IMEI, error: %d", err);
        goto exit;
    }

    imei_buf[IMEI_LEN] = '\0';
    snprintf(client_id, sizeof(client_id), "nrf-%.*s", IMEI_LEN, imei_buf);

exit:
    LOG_DBG("client_id = %s", (char *)(client_id));
    return client_id;
}


/**
 * @brief Initialize the MQTT client
 */
int client_init(struct mqtt_client *client)
{
    int err;
    struct mqtt_sec_config *tls_cfg;
    static sec_tag_t sec_tag_list[] = { TLS_SEC_TAG };

    mqtt_client_init(client);

    err = broker_init();
    if (err) {
        LOG_ERR("Failed to initialize broker connection");
        return err;
    }

    client->broker = &broker;
    client->evt_cb = mqtt_evt_handler;
    client->client_id.utf8 = client_id_get();
    client->client_id.size = strlen(client->client_id.utf8);
    client->password = &struct_pass;
    client->user_name = &struct_user;
    client->protocol_version = MQTT_VERSION_3_1_1;

    client->rx_buf = rx_buffer;
    client->rx_buf_size = sizeof(rx_buffer);
    client->tx_buf = tx_buffer;
    client->tx_buf_size = sizeof(tx_buffer);

    tls_cfg = &(client->transport).tls.config;
    LOG_INF("TLS enabled");
    client->transport.type = MQTT_TRANSPORT_SECURE;
    tls_cfg->peer_verify = 1;
    tls_cfg->cipher_list = NULL;
    tls_cfg->cipher_count = 0;
    tls_cfg->sec_tag_count = ARRAY_SIZE(sec_tag_list);
    tls_cfg->sec_tag_list = sec_tag_list;
    tls_cfg->hostname = NULL;
    tls_cfg->session_cache = 0;
    
    return err;
}

/**
 * @brief Initialize the file descriptor structure used by poll
 */
int fds_init(struct mqtt_client *c, struct pollfd *fds)
{
    if (c->transport.type == MQTT_TRANSPORT_NON_SECURE) {
        fds->fd = c->transport.tcp.sock;
    } else {
        fds->fd = c->transport.tls.sock;
    }

    fds->events = POLLIN;
    return 0;
}

/**
 * @brief Check if MQTT connection is alive by sending keepalive
 */
bool mqtt_is_connected_robust(struct mqtt_client *client)
{
    int err;

    if (!mqtt_connected) {
        return false;
    }

    err = mqtt_ping(client);
    if (err != 0) {
        LOG_ERR("MQTT ping failed: %d", err);
        mqtt_connected = false;
        return false;
    }

    return true;
}

/**
 * @brief Reconnect to MQTT broker
 */
int mqtt_reconnect(struct mqtt_client *client)
{
    int err;

    LOG_INF("Attempting MQTT reconnection...");
    
    if (mqtt_connected) {
        LOG_WRN("Already connected to MQTT");
        return 0;
    }

    mqtt_disconnect(client, NULL);
    k_sleep(K_SECONDS(2));

    err = mqtt_connect(client);
    if (err) {
        LOG_ERR("MQTT reconnect failed: %d", err);
        mqtt_connected = false;
        return err;
    }

    LOG_INF("MQTT reconnection initiated, waiting for CONNACK...");
    return 0;
}