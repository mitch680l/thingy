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
#include <modem/modem_key_mgmt.h>
#include "mqtt_connection.h"
#include "shell_commands.h"
#include "config.h"
#include "lte_helper.h"
#include "fota.h"
#define TLS_SEC_TAG 42

static struct mqtt_client client;
static struct pollfd fds;

K_THREAD_STACK_DEFINE(mqtt_thread_stack, MQTT_THREAD_STACK_SIZE);
static struct k_thread mqtt_thread_data;
static volatile bool got_connack;

static uint8_t rx_buffer[256];
static uint8_t tx_buffer[516];
static uint8_t payload_buf[256];
static struct sockaddr_storage broker;
static uint16_t packet_id;

LOG_MODULE_REGISTER(mqtt_conn, LOG_LEVEL_INF);

bool mqtt_connected = false;





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
        else {
            got_connack = true;
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

    
    err = getaddrinfo(mqtt_config.broker_addr, NULL, &hints, &result);
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
            broker4->sin_port = htons(mqtt_config.broker_port);

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
    static uint8_t client_id[MAX(sizeof(mqtt_config.client_id), CLIENT_ID_LEN)];

    if (strlen(mqtt_config.client_id) > 0) {
        snprintf(client_id, sizeof(client_id), "%s", mqtt_config.client_id);
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

static int wait_for_connack(struct mqtt_client *client, struct pollfd *fds, int timeout_ms)
{
    int64_t deadline = k_uptime_get() + timeout_ms;

    while (k_uptime_get() < deadline) {
        int kleft = (int)(deadline - k_uptime_get());
        if (kleft < 0) kleft = 0;

        int rc = poll(fds, 1, kleft);
        if (rc < 0) {
            return -errno;
        }
        if (rc > 0 && (fds->revents & POLLIN)) {
            /* This parses incoming packets and invokes mqtt_evt_handler() */
            int irc = mqtt_input(client);
            if (irc && irc != -EAGAIN) {
                return irc;
            }
            if (got_connack) {
                return 0;
            }
        }

        /* Keepalive machinery */
        int lrc = mqtt_live(client);
        if (lrc && lrc != -EAGAIN) {
            return lrc;
        }

        if (got_connack) {
            return 0;
        }
    }

    return -ETIMEDOUT;
}

int mqtt_reconnect(struct mqtt_client *client,
                   struct pollfd *fds,
                   int initial_backoff_ms,
                   int max_backoff_ms)
{
    int err;
    int backoff = initial_backoff_ms;

    LOG_INF("Attempting MQTT reconnection...");

    /* Stop any external poll loop before this point */

    /* Try to disconnect cleanly; if that fails, abort the client */
    err = mqtt_disconnect(client, NULL);
    if (err) {
        LOG_WRN("mqtt_disconnect: %d, aborting", err);
        mqtt_abort(client);
    }

    /* Small pause to ensure socket teardown */
    k_sleep(K_SECONDS(1));

    for (;;) {
        got_connack = false;

        err = mqtt_connect(client);
        if (err) {
            LOG_ERR("mqtt_connect failed: %d (%s)", err, strerror(-err));
            goto retry;
        }

        /* New socket => re-init fds */
        fds->fd = client->transport.type == MQTT_TRANSPORT_NON_SECURE
                  ? client->transport.tcp.sock
                  : client->transport.tls.sock;
        fds->events = POLLIN;
        fds->revents = 0;

        LOG_INF("MQTT reconnection initiated, waiting for CONNACK...");

        err = wait_for_connack(client, fds, 15000); /* 15s timeout */
        if (!err) {
            LOG_INF("MQTT CONNACK received");

            /* If using clean sessions, you must resubscribe here */
            /* mqtt_subscribe(client, &sub); ... */

            /* Success: caller can resume the normal poll loop */
            return 0;
        }

        LOG_ERR("Waiting for CONNACK failed: %d (%s)", err, strerror(-err));
        /* Make sure we’re not half-open before retrying */
        mqtt_abort(client);

    retry:
        LOG_INF("Retrying in %d ms", backoff);
        k_sleep(K_MSEC(backoff));
        backoff = MIN(max_backoff_ms, backoff * 2 + (sys_rand32_get() % 500)); // jitter
    }
}


/**
 * @brief Handle MQTT operations including polling and publishing
 */
void mqtt_handle(void)
{
    static int bad_publish = 0;
    int err, ret;
    int start_time, poll_start, poll_time, input_start, input_time;
    int publish_start, publish_time, error_handling_start, error_handling_time, total_time;

    start_time = k_uptime_get_32();
    k_sleep(K_MSEC(mqtt_config.publish_rate));

    poll_start = k_uptime_get_32();
    ret = poll(&fds, 1, 0);
    poll_time = k_uptime_get_32() - poll_start;
    LOG_DBG("poll() took: %d ms", poll_time);

    if (ret < 0) {
        LOG_ERR("poll() error: %d", errno);
    } else if ((ret > 0) && (fds.revents & POLLIN)) {
        input_start = k_uptime_get_32();
        mqtt_input(&client);
        input_time = k_uptime_get_32() - input_start;
        LOG_DBG("mqtt_input took: %d ms", input_time);
    }

    LOG_DBG("MQTT Publish");

    publish_start = k_uptime_get_32();
    err = publish_all();
    publish_time = k_uptime_get_32() - publish_start;
    LOG_DBG("publish_all() took: %d ms", publish_time);

    error_handling_start = k_uptime_get_32();
    
    if (err) {
    LOG_ERR("data_publish: %d (%s)", err, strerror(-err));

    if (err == -EAGAIN) {
        /* Buffer busy — just skip reconnect and retry later */
        LOG_WRN("Publish busy, will retry later");
    } else {
        LOG_WRN("Bad publish count: %d", bad_publish);
        bad_publish++;

        if (bad_publish >= BAD_PUBLISH_LIMIT) {
            sys_reboot(SYS_REBOOT_COLD);
        }

        /* Attempt full reconnect with backoff and CONNACK wait */
        int rc = mqtt_reconnect(&client, &fds,
                                500,          /* initial_backoff_ms */
                                30000);       /* max_backoff_ms */

        if (rc) {
            LOG_ERR("MQTT reconnect failed: %d (%s)", rc, strerror(-rc));
            mqtt_connected = false;
        } else {
            mqtt_connected = true;
            LOG_INF("MQTT reconnected successfully");

            /* If using clean session, re-subscribe here */
            // mqtt_subscribe(&client, &sub);
        }
    }
    } else {
        bad_publish = 0;
    }
    error_handling_time = k_uptime_get_32() - error_handling_start;
    LOG_DBG("Error handling took: %d ms", error_handling_time);

    total_time = k_uptime_get_32() - start_time;
    LOG_DBG("Total mqtt_handle() took: %d ms", total_time);
}

/**
 * @brief MQTT thread function with improved connectivity handling
 */
void mqtt_thread_fn(void *arg1, void *arg2, void *arg3)
{
    int64_t last_fota_check = k_uptime_get();

    while (1) {
        int64_t start = k_uptime_get();
        enum lte_lc_nw_reg_status reg_status;
        int lte_err = lte_lc_nw_reg_status_get(&reg_status);
        bool lte_connected_ok = (lte_err == 0) && (reg_status == LTE_LC_NW_REG_REGISTERED_HOME ||  reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING);

        
        if (!lte_connected_ok) {
            LOG_WRN("LTE not connected: status=%d, err=%d", reg_status, lte_err);
            mqtt_connected = false;
            k_sem_take(&lte_connected, K_FOREVER);
            continue;
        }

        
        LOG_INF("MQTT and LTE connected: MQTT: %d, LTE: %d", mqtt_connected, lte_connected_ok);
        
        if ((start - last_fota_check) >= ota_config.check_interval) {
            LOG_INF("Suspending MQTT publish to check FOTA...");
            
            if (fota_get_state() == FOTA_CONNECTED) {
                check_fota_server();
            } else {
                LOG_INF("LTE not connected, skipping FOTA check.");
            }
            
            last_fota_check = start;
        }

        if (fota_get_state() == FOTA_DOWNLOADING) {
            LOG_INF("FOTA download in progress, skipping MQTT publish.");
            k_sleep(K_SECONDS(1));
            continue;
        }
        
        mqtt_handle();
        
        int64_t end = k_uptime_get();
        LOG_INF("MQTT Thread Took: %d ms", (int)(end - start));
    }
}

/**
 * @brief Publish all pending data to MQTT broker
 */
int publish_all(void)
{
    static int err = 0;
    static char topic[200];
    static char last_payload[sizeof(json_payload)] = {0};
    static char last_sensor_payload[sizeof(sensor_payload)] = {0};
    enum lte_lc_nw_reg_status status;
    
    k_mutex_lock(&json_mutex, K_FOREVER);
    
    if (strcmp(json_payload, last_payload) == 0) {
        LOG_WRN("No new GNSS fix since last publish!");
        lte_lc_nw_reg_status_get(&status);
       
        if (status != LTE_LC_NW_REG_REGISTERED_HOME || !mqtt_connected) {
            LOG_WRN("Not connected to LTE or MQTT");
            k_mutex_unlock(&json_mutex);
            return -ENOTCONN;
        } else {
            err = 0;
            mqtt_live(&client);
        }
    }
    else {

        if (topic_gps[0] != '\0') {
            snprintf(topic, sizeof(topic), "%s%s", mqtt_config.client_id, topic_gps);
            err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                               (uint8_t *)json_payload, strlen(json_payload), topic);
            if (err == 0) {
                memcpy(last_payload, json_payload, sizeof(json_payload));
            } else {
                LOG_ERR("Failed to publish GPS data: %d", err);
            }
        } else {
            LOG_WRN("GPS topic not configured, skipping GPS publish");
        }
    }


    if (topic_sensor[0] != '\0') {
        if (strcmp(sensor_payload, last_sensor_payload) != 0) {
            snprintf(topic, sizeof(topic), "%s%s", mqtt_config.client_id, topic_sensor);
            int sensor_err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                               (uint8_t *)sensor_payload, strlen(sensor_payload), topic);
            if (sensor_err == 0) {
                memcpy(last_sensor_payload, sensor_payload, sizeof(sensor_payload));
                LOG_INF("Published sensor data");
            } else {
                LOG_ERR("Failed to publish sensor data: %d", sensor_err);
                if (err == 0) {
                    err = sensor_err;
                }
            }
        } else {
            LOG_DBG("No new sensor data since last publish");
        }
    } else {
        LOG_DBG("Sensor topic not configured, skipping sensor publish");
    }
    

    if (publish_lte_info && topic_lte[0] != '\0') {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_config.client_id, topic_lte);
        int lte_err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload_lte, strlen(json_payload_lte), topic);
        if (lte_err == 0) {
            publish_lte_info = false;
            LOG_INF("Published LTE info");
        } else {
            LOG_ERR("Failed to publish LTE info: %d", lte_err);
            if (err == 0) {
                err = lte_err;
            }
        }
    } else if (publish_lte_info) {
        LOG_WRN("LTE topic not configured, skipping LTE publish");
        publish_lte_info = false;
    }
    
    k_mutex_unlock(&json_mutex);
    return err;
}

/**
 * @brief Initialize MQTT connection and start thread
 */
void mqtt_init(void)
{
    int err;

    LOG_INF("Initializing MQTT connection");

    k_sleep(K_SECONDS(1));
    
    err = client_init(&client);
    if (err) {
        LOG_ERR("client_init: %d", err);
        return;
    }
    
    k_sleep(K_SECONDS(1));

    err = mqtt_connect(&client);
    if (err) {
        LOG_ERR("Initial mqtt_connect failed: %d", err);
    }

    k_sleep(K_SECONDS(3));

    err = fds_init(&client, &fds);
    if (err) {
        LOG_ERR("fds_init: %d", err);
        return;
    }

    k_thread_create(&mqtt_thread_data, mqtt_thread_stack,
                    K_THREAD_STACK_SIZEOF(mqtt_thread_stack),
                    mqtt_thread_fn, NULL, NULL, NULL,
                    MQTT_THREAD_PRIORITY, 0, K_NO_WAIT);
    
    LOG_INF("MQTT thread started");
}