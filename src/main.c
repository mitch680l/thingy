/*
 *  Thingy91X/nRF9151 -  Demonstartion
 *
 *  This application demonstrates the following:
 *  1. Application CLI (Shell commands to configure non-volatile device settings)
 *  2. LTE Connectivity (Uses power saving modes)
 *  3. GNSS Position Reporting (A-GPS/SUPL assistnace not utilized in this firmware)
 *  4. JSON Message Creation
 *  5. MQTT message publishing
 * 
 */

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
#include "shell_commands.h"
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/sensor.h>
#define MQTT_THREAD_STACK_SIZE 2048
#define MQTT_THREAD_PRIORITY 1
#define JSON_BUF_SIZE 516
#define BAD_PUBLISH_LIMIT 5
#define FORMAT_STRING "Current uptime is: %d"
/* JSON globals */
static char json_payload2[JSON_BUF_SIZE] = "NO LTE";
static char json_payload3[JSON_BUF_SIZE] = "NO SENSOR DATA";
/* MQTT structures */
static struct mqtt_client client;
static struct pollfd fds;
static int bad_publish = 0;
/*LTE globals*/
static bool update_lte_info = false;
static bool publish_lte_info = false;

/* Semaphores */
K_SEM_DEFINE(lte_connected, 0, 1);
K_MUTEX_DEFINE(json_mutex);
/* Logger */
/*MCC+MNC*/
typedef struct {
    const char *mccmnc;
    const char *name;
} OperatorEntry;

static const OperatorEntry operator_table[] = {
    {"302720", "Canada - Rogers"},
    {"302610", "Canada - Bell"},
    {"302220", "Canada - Telus"},
    {"310260", "United States - T-Mobile"},
    {"310410", "United States - AT&T"},
    {"311480", "United States - Verizon"},
    {"312530", "United States - Dish"},
    {"313100", "United States - FirstNet"},
    {"334020", "Mexico - Telcel"},
    {"334030", "Mexico - AT&T Mexico"},
    {"334050", "Mexico - Movistar"},
};

LOG_MODULE_REGISTER(loop, LOG_LEVEL_INF);
/*Sensors*/
const struct device *sensor_dev = DEVICE_DT_GET(DT_ALIAS(temp_sensor));
const struct device *accel      = DEVICE_DT_GET(DT_ALIAS(acl));
const struct device *mag        = DEVICE_DT_GET(DT_ALIAS(magnetometer));
const struct device *imu        = DEVICE_DT_GET(DT_ALIAS(imu));
static void pack_sensor_data(void)
{
	static struct sensor_value temp     = {0}, press = {0}, humid = {0}, gas = {0};
	static struct sensor_value accel_val[3] = {{0}}, mag_val[3] = {{0}};
	static struct sensor_value imu_acc[3]   = {{0}}, imu_gyro[3] = {{0}};

#define TRY_FETCH(dev) ((dev) && sensor_sample_fetch(dev) >= 0)
#define TRY_GET(dev, chan, val) ((dev) && sensor_channel_get(dev, chan, val) >= 0)

	if (!TRY_FETCH(sensor_dev)) {
		LOG_WRN("Ambient sensor fetch failed");
	}
	if (!TRY_FETCH(accel)) {
		LOG_WRN("Accelerometer fetch failed");
	}
	if (!TRY_FETCH(mag)) {
		LOG_WRN("Magnetometer fetch failed");
	}
	if (!TRY_FETCH(imu)) {
		LOG_WRN("IMU fetch failed");
	}

	if (!TRY_GET(sensor_dev, SENSOR_CHAN_AMBIENT_TEMP, &temp)) {
		temp.val1 = 0; temp.val2 = 0;
	}
	if (!TRY_GET(sensor_dev, SENSOR_CHAN_PRESS, &press)) {
		press.val1 = 0; press.val2 = 0;
	}
	if (!TRY_GET(sensor_dev, SENSOR_CHAN_HUMIDITY, &humid)) {
		humid.val1 = 0; humid.val2 = 0;
	}
	if (!TRY_GET(sensor_dev, SENSOR_CHAN_GAS_RES, &gas)) {
		gas.val1 = 0; gas.val2 = 0;
	}

	if (!TRY_GET(accel, SENSOR_CHAN_ACCEL_XYZ, accel_val)) {
		memset(accel_val, 0, sizeof(accel_val));
	}
	if (!TRY_GET(mag, SENSOR_CHAN_MAGN_XYZ, mag_val)) {
		memset(mag_val, 0, sizeof(mag_val));
	}
	if (!TRY_GET(imu, SENSOR_CHAN_ACCEL_XYZ, imu_acc)) {
		memset(imu_acc, 0, sizeof(imu_acc));
	}
	if (!TRY_GET(imu, SENSOR_CHAN_GYRO_XYZ, imu_gyro)) {
		memset(imu_gyro, 0, sizeof(imu_gyro));
	}

	snprintk(json_payload3, sizeof(json_payload3),
		"{"
			"\"temp\":%d.%06d,\"press\":%d.%06d,\"humidity\":%d.%06d,\"gas\":%d.%06d,"
			"\"accel\":{\"x\":%d.%06d,\"y\":%d.%06d,\"z\":%d.%06d},"
			"\"mag\":{\"x\":%d.%06d,\"y\":%d.%06d,\"z\":%d.%06d},"
			"\"imu\":{\"acc\":{\"x\":%d.%06d,\"y\":%d.%06d,\"z\":%d.%06d},"
			"\"gyro\":{\"x\":%d.%06d,\"y\":%d.%06d,\"z\":%d.%06d}}"
		"}",
		temp.val1, abs(temp.val2),
		press.val1, abs(press.val2),
		humid.val1, abs(humid.val2),
		gas.val1, abs(gas.val2),

		accel_val[0].val1, abs(accel_val[0].val2),
		accel_val[1].val1, abs(accel_val[1].val2),
		accel_val[2].val1, abs(accel_val[2].val2),

		mag_val[0].val1, abs(mag_val[0].val2),
		mag_val[1].val1, abs(mag_val[1].val2),
		mag_val[2].val1, abs(mag_val[2].val2),

		imu_acc[0].val1, abs(imu_acc[0].val2),
		imu_acc[1].val1, abs(imu_acc[1].val2),
		imu_acc[2].val1, abs(imu_acc[2].val2),

		imu_gyro[0].val1, abs(imu_gyro[0].val2),
		imu_gyro[1].val1, abs(imu_gyro[1].val2),
		imu_gyro[2].val1, abs(imu_gyro[2].val2)
	);

	LOG_DBG("Sensor data packed");
}

static void init_sensors(void) {
    struct sensor_value full_scale, sampling_freq, oversampling;
    
	if (!device_is_ready(sensor_dev)) {
		LOG_ERR("Atmospheric sensor not ready");
	}
    LOG_INF("Atmospheric sensor ready");
	if (!device_is_ready(accel)) {
		LOG_ERR("Accelerometer not ready");
	}
    LOG_INF("Accelerometer ready");
	if (!device_is_ready(mag)) {
		LOG_ERR("Magnetometer not ready");
	}
    LOG_INF("Magnetometer ready");
	if (!device_is_ready(imu)) {
		LOG_ERR("IMU not ready");
	}
    LOG_INF("IMU ready");
    full_scale.val1 = 2;        
	full_scale.val2 = 0;
	sampling_freq.val1 = 2;       
	sampling_freq.val2 = 0;
	oversampling.val1 = 1;   
	oversampling.val2 = 0;
    sensor_attr_set(imu, SENSOR_CHAN_ACCEL_XYZ, SENSOR_ATTR_FULL_SCALE,
			&full_scale);
	sensor_attr_set(imu, SENSOR_CHAN_ACCEL_XYZ, SENSOR_ATTR_OVERSAMPLING,
			&oversampling);
    sensor_attr_set(imu, SENSOR_CHAN_ACCEL_XYZ,
			SENSOR_ATTR_SAMPLING_FREQUENCY,
			&sampling_freq);
    full_scale.val1 = 500;     
	full_scale.val2 = 0;
	sampling_freq.val1 = 100;    
	sampling_freq.val2 = 0;
	oversampling.val1 = 1;
	oversampling.val2 = 0;
    sensor_attr_set(imu, SENSOR_CHAN_GYRO_XYZ, SENSOR_ATTR_FULL_SCALE,
			&full_scale);
	sensor_attr_set(imu, SENSOR_CHAN_GYRO_XYZ, SENSOR_ATTR_OVERSAMPLING,
			&oversampling);
	sensor_attr_set(imu, SENSOR_CHAN_GYRO_XYZ,
			SENSOR_ATTR_SAMPLING_FREQUENCY,
			&sampling_freq);

    sensor_attr_set(accel, SENSOR_CHAN_ACCEL_XYZ,
            SENSOR_ATTR_SAMPLING_FREQUENCY, &sampling_freq);
    sensor_attr_set(mag, SENSOR_CHAN_MAGN_XYZ,
            SENSOR_ATTR_SAMPLING_FREQUENCY, &sampling_freq);
    sensor_attr_set(sensor_dev, SENSOR_CHAN_AMBIENT_TEMP,
            SENSOR_ATTR_SAMPLING_FREQUENCY, &sampling_freq);
    sensor_attr_set(sensor_dev, SENSOR_CHAN_PRESS,
            SENSOR_ATTR_SAMPLING_FREQUENCY, &sampling_freq);
    sensor_attr_set(sensor_dev, SENSOR_CHAN_HUMIDITY,
            SENSOR_ATTR_SAMPLING_FREQUENCY, &sampling_freq);
    sensor_attr_set(sensor_dev, SENSOR_CHAN_GAS_RES,
            SENSOR_ATTR_SAMPLING_FREQUENCY, &sampling_freq);
    LOG_INF("Sensors initialized");
  
}



const char *lookup_operator_name(const char *mccmnc)
{
    if (mccmnc == NULL || strlen(mccmnc) < 5)
        return "Invalid Operator Code";

    for (int i = 0; i < sizeof(operator_table) / sizeof(operator_table[0]); i++) {
        if (strcmp(operator_table[i].mccmnc, mccmnc) == 0) {
            return operator_table[i].name;
        }
    }
    return "Uknown Operator";
}

static void pack_lte_data(void)
{
    enum modem_info;
    LOG_INF("Preparing to print LTE data");
    int ret;
    char lte_rsp[20] = "uknown";
    char lte_area[20] = "uknown";
    char lte_operator[20] = "uknown";
    char lte_cell_id[20] = "uknown";
    const char *lte_operator_decoded;
    ret = modem_info_init();
    if (ret < 0) {
        LOG_ERR("Failed to initialize modem info: %d", ret);
        return;  // Return early if modem_info_init fails
    }
    ret = modem_info_string_get(MODEM_INFO_RSRP, lte_rsp, sizeof(lte_rsp));
    if (ret < 0) {
        LOG_ERR("Failed to get LTE RSRP: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_AREA_CODE, lte_area, sizeof(lte_area));
    if (ret < 0) {
        LOG_ERR("Failed to get tracking area code: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_OPERATOR, lte_operator, sizeof(lte_operator));
    if (ret < 0) {
        LOG_ERR("FAILED TO GET OPERATOR.");
    }
    lte_operator_decoded = lookup_operator_name(lte_operator);
    ret = modem_info_string_get(MODEM_INFO_CELLID, lte_cell_id, sizeof(lte_cell_id));
    if (ret < 0) {
        LOG_ERR("Failed to get cell ID: %d", ret);
    }
    
   


    
    //LOG_INF("LTE Data:");
    //LOG_INF("  RSRP: %s", lte_rsp);
    //LOG_INF("  LTE Mode: %s", lte_mode);
    //LOG_INF("  GPS Mode: %s", lte_gps_mode);

   
    // Format the JSON string using local strings
    //LOG_INF("Copying LTE data to json_payload2");
    int len = snprintf(json_payload2, sizeof(json_payload2),
        "{"
          "\"RSRP\":\"%s\","
          "\"AreaCode\":\"%s\","
          "\"Operator\":\"%s\","
          "\"CellID\":\"%s\","
        "}",
        lte_rsp,
        lte_area,
        lte_operator_decoded,
        lte_cell_id
    );
    
    if (len < 0) {
        LOG_ERR("Failed to format LTE JSON: %d", len);
        return;
    } else if ((size_t)len >= sizeof(json_payload2)) {  // Fixed: proper cast
        LOG_WRN("LTE JSON truncated (%d bytes needed)", len);
    }
    
    //LOG_INF("LTE Data: %s", json_payload2);
}



static void lte_handler(const struct lte_lc_evt *const evt) {
    switch (evt->type) {
        case LTE_LC_EVT_NW_REG_STATUS:
            /* Only proceed once registered (home or roaming) */
            if ((evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME) ||
                (evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING)) {
                LOG_INF("Network registration status: %s",
                    evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ?
                    "Connected - home network" :
                    "Connected - roaming");
                k_sem_give(&lte_connected);
            }
            break;
        case LTE_LC_EVT_RRC_UPDATE:
            LOG_INF("RRC mode: %s",
                evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ?
                "Connected" : "Idle");
            break;

        case LTE_LC_EVT_CELL_UPDATE:
            LOG_INF("LTE cell changed: Cell ID: %d, Tracking area: %d",
                evt->cell.id,
                evt->cell.tac);
            update_lte_info = true;
            break;

        case LTE_LC_EVT_LTE_MODE_UPDATE:
            switch (evt->lte_mode) {
                case LTE_LC_LTE_MODE_LTEM:
                    LOG_INF("LTE mode updated: LTE-M");
                    break;
                case LTE_LC_LTE_MODE_NBIOT:
                    LOG_INF("LTE mode updated: NB-IoT");
                    break;
                case LTE_LC_LTE_MODE_NONE:
                    LOG_INF("LTE mode updated: None (off)");
                    break;
                default:
                    LOG_INF("LTE mode updated: Unknown");
                    break;
                }
        break;

        default:
            break;
    }
}

static int modem_configure(void)
{
	int err;
	err = nrf_modem_lib_init();
	if (err) {
		LOG_ERR("Failed to initialize the modem library, error: %d", err);
		return err;
	}

    
    lte_lc_system_mode_set(LTE_LC_SYSTEM_MODE_LTEM, 
                           LTE_LC_SYSTEM_MODE_PREFER_AUTO);

    lte_lc_psm_req(false);
    //lte_lc_edrx_req(false);
    lte_lc_func_mode_set(LTE_LC_FUNC_MODE_NORMAL);
	LOG_INF("Connecting to LTE network");
	err = lte_lc_connect_async(lte_handler);
	if (err) {
		LOG_ERR("Error in lte_lc_connect_async, error: %d", err);
		return err;
	}
    
	k_sem_take(&lte_connected, K_FOREVER);
	LOG_INF("Connected to LTE network");
	
	return 0;
}


int publish_all() {
    int err = 0;
    static char topic[200];
    static char last_payload[sizeof(json_payload)] = {0};  // Tracks last GNSS payload

    k_mutex_lock(&json_mutex, K_FOREVER);

    // Check if GNSS payload is new
    if (strcmp(json_payload, last_payload) == 0) {
        LOG_WRN("No new GNSS fix since last publish!");
    } 
    else {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/gnss_json");
        err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload, strlen(json_payload), topic);
        // Update last known payload
        memcpy(last_payload, json_payload, sizeof(json_payload));
    }

    if (publish_lte_info) {
        snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/lte_json");
        err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
                           (uint8_t *)json_payload2, strlen(json_payload2), topic);
        publish_lte_info = false;
    }

    k_mutex_unlock(&json_mutex);

    return err;
}

static void mqtt_handle() {
    int err;
    int start_time = k_uptime_get_32();
    
    // Time the poll operation
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
    
    // Time the publish operation
    int publish_start = k_uptime_get_32();
    err = publish_all();
    int publish_time = k_uptime_get_32() - publish_start;
    LOG_DBG("publish_all() took: %d ms", publish_time);
    
    // Time the error handling and heartbeat
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
    
    // Total function time
    int total_time = k_uptime_get_32() - start_time;
    LOG_DBG("Total mqtt_handle() took: %d ms", total_time);
}

K_THREAD_STACK_DEFINE(mqtt_thread_stack, MQTT_THREAD_STACK_SIZE);
static struct k_thread mqtt_thread_data;

void mqtt_thread_fn(void *arg1, void *arg2, void *arg3) {
    while (1) {
        int start = k_uptime_get();
        mqtt_handle();  // this will publish and manage the connection
        k_msleep(39);
        int end = k_uptime_get();
        LOG_INF("MQTT Thread Took: %d", end - start);
    }
}
//Initialize dependencies
static int init() {
    int err;
    k_thread_priority_set(k_current_get(), 13);
	k_sleep(K_SECONDS(1));
    shell_mqtt_init();
    LOG_INF("Shell Initialized");
	LOG_INF("Tracker Demo Version %d.%d.%d started\n",CONFIG_TRACKER_VERSION_MAJOR,CONFIG_TRACKER_VERSION_MINOR,CONFIG_TRACKER_VERSION_PATCH);
	LOG_INF("Device ID: %s", mqtt_client_id);
    LOG_INF("MQTT Broker Host: %s", mqtt_broker_host);
    LOG_INF("MQTT Broker Port: %d", mqtt_broker_port);
    LOG_INF("MQTT Publish Interval (sec): %d", mqtt_publish_interval);
    LOG_INF("MQTT Connection Keep Alive (sec): %d", mqtt_keepalive);
    //init_sensors();
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
    LOG_INF("Connecting to MQTT broker");
    err = client_init(&client);
    if (err) {
        LOG_ERR("client_init: %d", err);
        return err;
    }
    err = mqtt_connect(&client);
    if (err) {
        LOG_ERR("mqtt_connect: %d", err);
        return err;
    }

    k_sleep(K_SECONDS(1));

    k_thread_create(&mqtt_thread_data, mqtt_thread_stack,
                K_THREAD_STACK_SIZEOF(mqtt_thread_stack),
                mqtt_thread_fn, NULL, NULL, NULL,
                MQTT_THREAD_PRIORITY, 0, K_NO_WAIT);
    err = fds_init(&client, &fds);
    if (err) {
        LOG_ERR("fds_init: %d", err);
        return err;
    }
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




