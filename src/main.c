#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <zephyr/device.h>     
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/devicetree.h>   
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <dk_buttons_and_leds.h>
#include <nrf_modem_gnss.h>
#include <nrf_modem_at.h>
#include <zephyr/net/mqtt.h>
#include <modem/modem_info.h>
#include "mqtt_connection.h"
#include "gnss.h"
#include "heartbeat.h"
#include "lte_helper.h"
#include "shell_commands.h"
#include "fota.h"
#include <string.h>
#include <stdio.h>



#define MQTT_THREAD_STACK_SIZE 2048
#define MQTT_THREAD_PRIORITY 1
#define JSON_BUF_SIZE 516
#define BAD_PUBLISH_LIMIT 5
#define ENCRYPTED_BLOB_ADDR ((const uint8_t *)0xFBE00)
#define ENCRYPTED_BLOB_SIZE 0x2000
/* MQTT structures */
static struct mqtt_client client;
static struct pollfd fds;
/* Semaphores */
K_MUTEX_DEFINE(json_mutex);
K_THREAD_STACK_DEFINE(mqtt_thread_stack, MQTT_THREAD_STACK_SIZE);
static struct k_thread mqtt_thread_data;
/*Logging*/
LOG_MODULE_REGISTER(loop, LOG_LEVEL_INF);

/*
Test Function for reading Hex Blobs
*/
void read_encrypted_blob(void)
{
    // Read blob into a buffer
    char buffer[ENCRYPTED_BLOB_SIZE + 1]; // +1 for null-termination safety
    memcpy(buffer, ENCRYPTED_BLOB_ADDR, ENCRYPTED_BLOB_SIZE);

    // Ensure it's null-terminated
    buffer[ENCRYPTED_BLOB_SIZE] = '\0';

    // If the blob is a string, print it
    printk("Blob content:\n%s\n", buffer);

    // Optionally: print as hex too
    for (int i = 0; i < 64 && i < ENCRYPTED_BLOB_SIZE; i++) {
        printk("%02X ", buffer[i]);
    }
    printk("\n");
}

int publish_all() {
    static int err = 0;
    static char topic[200];
    static char last_payload[sizeof(json_payload)] = {0};

    k_mutex_lock(&json_mutex, K_FOREVER);

    if (strcmp(json_payload, last_payload) == 0) {
        LOG_WRN("No new GNSS fix since last publish!");
        enum lte_lc_nw_reg_status status;
        lte_lc_nw_reg_status_get(&status);

        if (status != LTE_LC_NW_REG_REGISTERED_HOME || !mqtt_connected) {
            LOG_WRN("Not connected to LTE, or MQTT");
            k_sleep(K_SECONDS(5));
            return -ENOTCONN;
        }
        else {
            err = 0;
        }
    } 
    else {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/gnss_json");
        err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload, strlen(json_payload), topic);
        memcpy(last_payload, json_payload, sizeof(json_payload));
    }

    if (publish_lte_info) {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/lte_json");
        err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload_lte, strlen(json_payload_lte), topic);
        publish_lte_info = false;
    }

    k_mutex_unlock(&json_mutex);

    return err;
}

static void mqtt_handle() {
    static int bad_publish = 0;
    int err;
    int start_time = k_uptime_get_32();
    k_sleep(K_MSEC(interval_mqtt));
    
    int poll_start = k_uptime_get_32();
    int ret = poll(&fds, 1, 0);
    int poll_time = k_uptime_get_32() - poll_start;
    LOG_DBG("poll() took: %d ms", poll_time);
    
    if (ret < 0) {
        LOG_ERR("poll() error: %d", errno);
    } else if ((ret > 0) && (fds.revents & POLLIN)) {
        int input_start = k_uptime_get_32();
        mqtt_input(&client);
        int input_time = k_uptime_get_32() - input_start;
        LOG_DBG("mqtt_input took: %d ms", input_time);
    }
    
    LOG_DBG("MQTT Publish");
    
    int publish_start = k_uptime_get_32();
    err = publish_all();
    int publish_time = k_uptime_get_32() - publish_start;
    LOG_DBG("publish_all() took: %d ms", publish_time);
    
    
    int error_handling_start = k_uptime_get_32();
    if (err) {
        LOG_ERR("data_publish: %d", err);
        LOG_WRN("Bad publish count: %d", bad_publish);
        bad_publish++;
        if(bad_publish >= BAD_PUBLISH_LIMIT)
            sys_reboot(SYS_REBOOT_COLD);
    } 
    else {
        bad_publish = 0;
    }
    int error_handling_time = k_uptime_get_32() - error_handling_start;
    LOG_DBG("Error handling and heartbeat took: %d ms", error_handling_time);
    
    int total_time = k_uptime_get_32() - start_time;
    LOG_DBG("Total mqtt_handle() took: %d ms", total_time);
}




void mqtt_thread_fn(void *arg1, void *arg2, void *arg3) {
    int64_t last_fota_check = k_uptime_get();

    while (1) {
        int64_t start = k_uptime_get();

        enum lte_lc_nw_reg_status reg_status;
        int lte_err = lte_lc_nw_reg_status_get(&reg_status);

        bool lte_connected_ok = (lte_err == 0) &&
                                (reg_status == LTE_LC_NW_REG_REGISTERED_HOME ||
                                 reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING);
                                    
       
        if (mqtt_connected && lte_connected_ok) {
            LOG_INF("MQTT and LTE connected: MQTT: %d, LTE: %d",
                    mqtt_connected, lte_connected_ok);
            if ((start - last_fota_check) >= FOTA_CHECK_INTERVAL_MS) {
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
            else {
                mqtt_handle(); 
            }
            int64_t end = k_uptime_get();
            LOG_INF("MQTT Thread Took: %d ms", (int)(end - start));
        } else {
            LOG_WRN("MQTT or LTE not connected: MQTT: %d, LTE: %d",
                    mqtt_connected, lte_connected_ok);
            k_sleep(K_SECONDS(5));
        }

        
    }
}


void mqtt_init() {
    int err;
    
    LOG_INF("Connecting to MQTT broker");
    
    set_user_pass();
    k_sleep(K_SECONDS(1));
    err = client_init(&client);
    if (err) {
        LOG_ERR("client_init: %d", err);
    }
    k_sleep(K_SECONDS(1));
    //clear_user_pass();

    err = mqtt_connect(&client);
    if (err) {
        LOG_ERR("mqtt_connect: %d", err);
    }

    k_sleep(K_SECONDS(3));

    k_thread_create(&mqtt_thread_data, mqtt_thread_stack,
                K_THREAD_STACK_SIZEOF(mqtt_thread_stack),
                mqtt_thread_fn, NULL, NULL, NULL,
                MQTT_THREAD_PRIORITY, 0, K_NO_WAIT);
    

    err = fds_init(&client, &fds);
    if (err) {
        LOG_ERR("fds_init: %d", err);
    }
}

static int init() {
    
    int err;
    k_thread_priority_set(k_current_get(), 13);
    LOG_INF("NEW APP STARTING");
    err = open_persistent_key();
    if (err) {
        LOG_ERR("open_persistent_key: %d", err);
    }
    k_sleep(K_MSEC(100)); 
    gnss_int();
	err = dk_leds_init();
	if (err){
		LOG_ERR("Failed to initialize the LEDs Library");
        return err;
	}
    read_encrypted_blob();
    heartbeat_config(HB_COLOR_RED, 1, 500);
    LOG_INF("Initializing modem");
	err = modem_configure();
    if (err) {
        LOG_ERR("nrf_modem_lib_init failed: %d", err);
        return err;
    }
    LOG_INF("Modem initialized");
    k_sleep(K_SECONDS(5));
    mqtt_init();
    
    return 0;
}

int main(void) {
    if (boot_write_img_confirmed() != 0) {
        printk("Failed to confirm firmware!\n");
    } else {
        printk("Firmware confirmed!\n");
    }
	int err;
    err = init();
    if (err) {
        LOG_ERR("Initialization failed: %d", err);
    }
    else {
        LOG_INF("INIT GOOD");
    }
    while (1) {
        int start = k_uptime_get();
        gnss_main_loop();
        //int gnss_time = k_uptime_get();
        //LOG_INF("GNSS Main Loop Took: %d", gnss_time - start);
        if (update_lte_info) {
           k_mutex_lock(&json_mutex, K_FOREVER);
           pack_lte_data();
           k_mutex_unlock(&json_mutex);
           update_lte_info = false;
           publish_lte_info = true;
        }
        int end = k_uptime_get();
        LOG_INF("Main Loop Took: %d", end-start);

    }
    return 0;
}