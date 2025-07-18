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

#define MQTT_THREAD_STACK_SIZE 2048
#define MQTT_THREAD_PRIORITY 1
#define JSON_BUF_SIZE 516
#define BAD_PUBLISH_LIMIT 5
/* MQTT structures */
static struct mqtt_client client;
static struct pollfd fds;
static int bad_publish = 0;
/* Semaphores */
K_MUTEX_DEFINE(json_mutex);
K_THREAD_STACK_DEFINE(mqtt_thread_stack, MQTT_THREAD_STACK_SIZE);
static struct k_thread mqtt_thread_data;
/*Logging*/
LOG_MODULE_REGISTER(loop, LOG_LEVEL_INF);

int publish_all() {
    int err = 0;
    static char topic[200];
    static char last_payload[sizeof(json_payload)] = {0};

    k_mutex_lock(&json_mutex, K_FOREVER);

    if (strcmp(json_payload, last_payload) == 0) {
        LOG_WRN("No new GNSS fix since last publish!");
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
    int err;
    int start_time = k_uptime_get_32();
    
   
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
        bad_publish++;
        if(bad_publish >= BAD_PUBLISH_LIMIT)
            sys_reboot(SYS_REBOOT_COLD);
    } else {
        bad_publish = 0;
    }
    int error_handling_time = k_uptime_get_32() - error_handling_start;
    LOG_DBG("Error handling and heartbeat took: %d ms", error_handling_time);
    
    int total_time = k_uptime_get_32() - start_time;
    LOG_DBG("Total mqtt_handle() took: %d ms", total_time);
}

void shell() {
    k_sleep(K_SECONDS(1));
    shell_mqtt_init();
    LOG_INF("Shell Initialized");
	LOG_INF("Tracker Demo Version %d.%d.%d started\n",CONFIG_TRACKER_VERSION_MAJOR,CONFIG_TRACKER_VERSION_MINOR,CONFIG_TRACKER_VERSION_PATCH);
	LOG_INF("Device ID: %s", mqtt_client_id);
    LOG_INF("MQTT Broker Host: %s", mqtt_broker_host);
    LOG_INF("MQTT Broker Port: %d", mqtt_broker_port);
    LOG_INF("MQTT Publish Interval (sec): %d", mqtt_publish_interval);
    LOG_INF("MQTT Connection Keep Alive (sec): %d", mqtt_keepalive);
}

void mqtt_thread_fn(void *arg1, void *arg2, void *arg3) {
    while (1) {
        int start = k_uptime_get();
        mqtt_handle();  // this will publish and manage the connection
        k_msleep(39);
        int end = k_uptime_get();
        LOG_INF("MQTT Thread Took: %d", end - start);
    }
}

void mqtt_init() {
    int err;
    
    LOG_INF("Connecting to MQTT broker");
    
    
    
    err = client_init(&client);
    if (err) {
        LOG_ERR("client_init: %d", err);
    }
    
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
	shell();
    gnss_int();
	err = dk_leds_init();
	if (err){
		LOG_ERR("Failed to initialize the LEDs Library");
        return err;
	}
    
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
    heartbeat_config(HB_COLOR_BLUE, 1, 500);
    return 0;
}

int main(void) {
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
        
        if (update_lte_info) {
           k_mutex_lock(&json_mutex, K_FOREVER);
           pack_lte_data();
           k_mutex_unlock(&json_mutex);
           update_lte_info = false;
           publish_lte_info = true;
        }
        k_msleep(15);
        int end = k_uptime_get();
        LOG_INF("Main Loop Took: %d", end-start);

    }
    return 0;
}