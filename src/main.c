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
#include "config.h"
#include "encryption_helper.h"
#include "sensor.h"
#include "../drivers/led/led_driver.h"
LOG_MODULE_REGISTER(loop, LOG_LEVEL_INF);

/**
 * @brief Initialize all system components
 */
static int init(void)
{
    int err = 0;
    
    LOG_INF("NEW APP STARTING");
    
    err = open_persistent_key();
    if (err) {
        LOG_ERR("open_persistent_key: %d", err);
    } else {
        LOG_INF("Persistent key opened successfully");
    }

    const struct device *i2c = DEVICE_DT_GET(DT_NODELABEL(i2c_bb0));
    if (device_is_ready(i2c) && ktd2026_init(&g_ktd, i2c, 0x30) == 0 && ktd2026_init(&k_ktd, i2c, 0x31) == 0) {
        LOG_INF("KTD2026 initialized successfully");
        ktd2026_blink_white_1hz_30();
        ktd2026_blink_white_1hz_31();
    } 
    else {
        LOG_ERR("Failed to initialize KTD2026 LED driver");
        return -ENODEV;
    }


    sensor_init();
    k_sleep(K_MSEC(30000)); // Wait for sensor initialization
    parse_encrypted_blob(); 
    config_init();
    gnss_int();
    err = modem_configure();
    if (err) {
        LOG_ERR("modem_configure failed: %d", err);
        return err;
    }
    lte_data_start();
    mqtt_init();

    return 0;
}

/**
 * @brief Main application entry point
 */
int main(void)
{
    int err, start, end;
    k_sleep(K_MSEC(2000));
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
        end = k_uptime_get();
    }
    
    return 0;
}