#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <modem/modem_info.h>
#include <dk_buttons_and_leds.h>
#include <nrf_modem_gnss.h>
#include <nrf_modem_at.h>
#include <zephyr/sys/heap_listener.h>
#include "mqtt_connection.h"
#include "gnss.h"
#include "heartbeat.h"
#include "lte_helper.h"
#include "shell_commands.h"
#include "fota.h"
#include "additional_shell.h"

#define MQTT_THREAD_STACK_SIZE 2048
#define MQTT_THREAD_PRIORITY 1
#define JSON_BUF_SIZE 516
#define BAD_PUBLISH_LIMIT 5
#define ENCRYPTED_BLOB_ADDR ((const uint8_t *)0xFDF00)
#define ENCRYPTED_BLOB_SIZE 0x2000
#define MQTT_RECONNECT_DELAY_SEC 10

static struct mqtt_client client;
static struct pollfd fds;

K_MUTEX_DEFINE(json_mutex);
K_THREAD_STACK_DEFINE(mqtt_thread_stack, MQTT_THREAD_STACK_SIZE);
static struct k_thread mqtt_thread_data;

LOG_MODULE_REGISTER(loop, LOG_LEVEL_INF);



/**
 * @brief Publish all pending data to MQTT broker
 */
static int publish_all(void)
{
    static int err = 0;
    static char topic[200];
    static char last_payload[sizeof(json_payload)] = {0};
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
        }
    } else {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/gnss_json");
        err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload, strlen(json_payload), topic);
        if (err == 0) {
            memcpy(last_payload, json_payload, sizeof(json_payload));
        }
    }

    if (publish_lte_info) {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/lte_json");
        int lte_err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload_lte, strlen(json_payload_lte), topic);
        if (lte_err == 0) {
            publish_lte_info = false;
        } else if (err == 0) {
            err = lte_err;
        }
    }

    k_mutex_unlock(&json_mutex);
    return err;
}

/**
 * @brief Handle MQTT operations including polling and publishing
 */
static void mqtt_handle(void)
{
    static int bad_publish = 0;
    int err, ret;
    int start_time, poll_start, poll_time, input_start, input_time;
    int publish_start, publish_time, error_handling_start, error_handling_time, total_time;

    start_time = k_uptime_get_32();
    k_sleep(K_MSEC(interval_mqtt));

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
        LOG_ERR("data_publish: %d", err);
        LOG_WRN("Bad publish count: %d", bad_publish);
        bad_publish++;
        if (bad_publish >= BAD_PUBLISH_LIMIT) {
            sys_reboot(SYS_REBOOT_COLD);
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
    static int64_t last_reconnect_attempt = 0;
    static int reconnect_failures = 0;

    while (1) {
        int64_t start = k_uptime_get();
        enum lte_lc_nw_reg_status reg_status;
        int lte_err = lte_lc_nw_reg_status_get(&reg_status);
        bool lte_connected_ok = (lte_err == 0) &&
                                (reg_status == LTE_LC_NW_REG_REGISTERED_HOME ||
                                 reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING);

        if (!lte_connected_ok) {
            LOG_WRN("LTE not connected: status=%d, err=%d", reg_status, lte_err);
            mqtt_connected = false;
            k_sleep(K_SECONDS(5));
            continue;
        }

        if (!mqtt_connected) {
            int64_t time_since_last_attempt = start - last_reconnect_attempt;
            
            if (time_since_last_attempt >= (MQTT_RECONNECT_DELAY_SEC * 1000)) {
                LOG_INF("Attempting MQTT reconnection (attempt %d)...", reconnect_failures + 1);
                
                int reconnect_err = mqtt_reconnect(&client);
                last_reconnect_attempt = start;
                
                if (reconnect_err != 0) {
                    reconnect_failures++;
                    LOG_ERR("MQTT reconnection failed: %d (failures: %d)", 
                            reconnect_err, reconnect_failures);
                    
                    if (reconnect_failures >= 5) {
                        LOG_ERR("Too many reconnection failures, rebooting...");
                        sys_reboot(SYS_REBOOT_COLD);
                    }
                } else {
                    LOG_INF("MQTT reconnection initiated successfully");
                }
            }
            
            k_sleep(K_SECONDS(2));
            continue;
        }

        if (!mqtt_is_connected_robust(&client)) {
            LOG_WRN("MQTT connectivity check failed, marking as disconnected");
            mqtt_connected = false;
            continue;
        }

        reconnect_failures = 0;
        
        LOG_INF("MQTT and LTE connected: MQTT: %d, LTE: %d", mqtt_connected, lte_connected_ok);
        
        if ((start - last_fota_check) >= fota_interval_ms) {
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
 * @brief Initialize MQTT connection and start thread
 */
void mqtt_init(void)
{
    int err;

    LOG_INF("Initializing MQTT connection");

    set_user_pass();
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

/**
 * @brief Initialize all system components
 */
static int init(void)
{
    int err;
    
    k_thread_priority_set(k_current_get(), 13);
    LOG_INF("NEW APP STARTING");
    
    LOG_INF("Step 1: Opening persistent key...");
    err = open_persistent_key();
    if (err) {
        LOG_ERR("open_persistent_key: %d", err);
    } else {
        LOG_INF("Persistent key opened successfully");
    }
    
    LOG_INF("Step 2: Initializing GNSS...");
    k_sleep(K_MSEC(100));
    gnss_int();
    LOG_INF("GNSS initialization complete");
    
    LOG_INF("Step 3: Initializing LEDs...");
    err = dk_leds_init();
    if (err) {
        LOG_ERR("Failed to initialize the LEDs Library");
        return err;
    }
    LOG_INF("LEDs initialized successfully");

    
    LOG_INF("Step 4: Parsing encrypted blob...");
    parse_encrypted_blob();
    LOG_INF("Encrypted blob parsed");

    
    LOG_INF("Step 5: Testing decryption...");
    test_decrypt_all_config_entries();
    LOG_INF("Decryption test complete");
    
    LOG_INF("Step 6: Initializing modem...");
    err = modem_configure();
    if (err) {
        LOG_ERR("modem_configure failed: %d", err);
        return err;
    }
    
    LOG_INF("Modem initialized successfully");
    k_sleep(K_SECONDS(5));

    
    LOG_INF("Step 7: Initializing MQTT...");
    mqtt_init();
    LOG_INF("MQTT initialization complete");
    
    LOG_INF("All initialization steps completed successfully");
    return 0;
}

/**
 * @brief Main application entry point
 */
int main(void)
{
    int err, start, end;
    
    if (boot_write_img_confirmed() != 0) {
        printk("Failed to confirm firmware!\n");
    } else {
        printk("Firmware confirmed!\n");
    }
    
    err = init();
    if (err) {
        LOG_ERR("Initialization failed: %d", err);
    } else {
        LOG_INF("INIT GOOD");
    }
    
    while (1) {
        start = k_uptime_get();
        gnss_main_loop();
        
        if (update_lte_info) {
            k_mutex_lock(&json_mutex, K_FOREVER);
            pack_lte_data();
            k_mutex_unlock(&json_mutex);
            update_lte_info = false;
            publish_lte_info = true;
        }
        
        end = k_uptime_get();
    }
    
    return 0;
}