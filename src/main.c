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
#include "heartbeat.h"
#include "shell_commands.h"
#include <zephyr/drivers/sensor.h>

#define JSON_BUF_SIZE 516
#define SLEEP_CHUNK_MS 500
#define BAD_PUBLISH_LIMIT 5
#define FORMAT_STRING "Current uptime is: %d"
/* JSON globals */
static char json_payload[JSON_BUF_SIZE] = "NO PVT";
static char json_payload2[JSON_BUF_SIZE] = "NO LTE";
static char json_payload3[JSON_BUF_SIZE] = "NO SENSOR DATA";
/* MQTT structures */
static struct mqtt_client client;
static struct pollfd fds;
static int bad_publish = 0;
/*LTE globals*/
static bool update_lte_info = false;
/* GNSS globals*/
static bool first_fix = true;
static struct nrf_modem_gnss_pvt_data_frame current_pvt;
/* Semaphores */
K_SEM_DEFINE(lte_connected, 0, 1);
K_SEM_DEFINE(gnss_fix_sem, 0, 1);
/* Logger */
LOG_MODULE_REGISTER(loop, LOG_LEVEL_INF);
/*Sensors*/
const struct device *sensor_dev = DEVICE_DT_GET(DT_ALIAS(temp_sensor));
const struct device *accel      = DEVICE_DT_GET(DT_ALIAS(acl));
const struct device *mag        = DEVICE_DT_GET(DT_ALIAS(magnetometer));
const struct device *imu        = DEVICE_DT_GET(DT_ALIAS(imu));

static void pack_sensor_data(void)
{
	static struct sensor_value temp, press, humid, gas;
	static struct sensor_value accel_val[3], mag_val[3];
	static struct sensor_value imu_acc[3], imu_gyro[3];

	bool ok = true;

	// Fetch samples
	ok &= sensor_sample_fetch(sensor_dev) >= 0;
	ok &= sensor_sample_fetch(accel) >= 0;
	ok &= sensor_sample_fetch(mag) >= 0;
	ok &= sensor_sample_fetch(imu) >= 0;

	// Read values
	ok &= sensor_channel_get(sensor_dev, SENSOR_CHAN_AMBIENT_TEMP, &temp) >= 0;
	ok &= sensor_channel_get(sensor_dev, SENSOR_CHAN_PRESS, &press) >= 0;
	ok &= sensor_channel_get(sensor_dev, SENSOR_CHAN_HUMIDITY, &humid) >= 0;
	ok &= sensor_channel_get(sensor_dev, SENSOR_CHAN_GAS_RES, &gas) >= 0;

	ok &= sensor_channel_get(accel, SENSOR_CHAN_ACCEL_XYZ, accel_val) >= 0;
	ok &= sensor_channel_get(mag, SENSOR_CHAN_MAGN_XYZ, mag_val) >= 0;
	ok &= sensor_channel_get(imu, SENSOR_CHAN_ACCEL_XYZ, imu_acc) >= 0;
	ok &= sensor_channel_get(imu, SENSOR_CHAN_GYRO_XYZ, imu_gyro) >= 0;

	if (!ok) {
		LOG_ERR("Sensor read failed");
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

static void pack_lte_data(void)
{
    enum modem_info;
    LOG_INF("Preparing to print LTE data");
    int ret;
    char lte_rsp[20] = "uknown";
    char lte_current_band[20] = "uknown";
    char lte_sup_band[20] = "uknown";
    char lte_area[20] = "uknown";
    char lte_ue_mode[20] = "uknown";
    char lte_operator[20] = "uknown";
    char lte_mcc[20] = "uknown";
    char lte_mnc[20] = "uknown";
    char lte_cell_id[20] = "uknown";
    char modem_ip_address[20] = "uknown";
    char battery_voltage[20] = "uknown";
    char temp[20] = "uknown";
    char lte_mode[20] = "uknown";
    char lte_gps_mode[20] = "uknown";
    char time[30] = "uknown";

    ret = modem_info_init();
    if (ret < 0) {
        LOG_ERR("Failed to initialize modem info: %d", ret);
        return;  // Return early if modem_info_init fails
    }

    ret = modem_info_string_get(MODEM_INFO_RSRP, lte_rsp, sizeof(lte_rsp));
    if (ret < 0) {
        LOG_ERR("Failed to get LTE RSRP: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_CUR_BAND, lte_current_band, sizeof(lte_current_band));
    if (ret < 0) {
        LOG_ERR("Failed to get current LTE band: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_SUP_BAND, lte_sup_band, sizeof(lte_sup_band));
    if (ret < 0) {
        //LOG_ERR("Failed to get supported LTE bands: %d", ret);
        //Known issue
    }
    ret = modem_info_string_get(MODEM_INFO_AREA_CODE, lte_area, sizeof(lte_area));
    if (ret < 0) {
        LOG_ERR("Failed to get tracking area code: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_UE_MODE, lte_ue_mode, sizeof(lte_ue_mode));
    if (ret < 0) {
        LOG_ERR("Failed to get UE mode: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_OPERATOR, lte_operator, sizeof(lte_operator));
    if (ret < 0) {
        LOG_ERR("Failed to get operator name: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_MCC, lte_mcc, sizeof(lte_mcc));
    if (ret < 0) {
        //LOG_ERR("Failed to get mobile country code: %d", ret);
        // Known issue
    }
    ret = modem_info_string_get(MODEM_INFO_MNC, lte_mnc, sizeof(lte_mnc));
    if (ret < 0) {
        //LOG_ERR("Failed to get mobile network code: %d", ret);
        // Known issue
    }
    ret = modem_info_string_get(MODEM_INFO_CELLID, lte_cell_id, sizeof(lte_cell_id));
    if (ret < 0) {
        LOG_ERR("Failed to get cell ID: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_IP_ADDRESS, modem_ip_address, sizeof(modem_ip_address));
    if (ret < 0) {
        LOG_ERR("Failed to get IP address: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_BATTERY, battery_voltage, sizeof(battery_voltage));
    if (ret < 0) {
        LOG_ERR("Failed to get battery voltage: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_TEMP, temp, sizeof(temp));
    if (ret < 0) {
        LOG_ERR("Failed to get temperature: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_LTE_MODE, lte_mode, sizeof(lte_mode));
    if (ret < 0) {
        LOG_ERR("Failed to get LTE mode: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_GPS_MODE, lte_gps_mode, sizeof(lte_gps_mode));
    if (ret < 0) {
        LOG_ERR("Failed to get GPS mode: %d", ret);
    }
    ret = modem_info_string_get(MODEM_INFO_DATE_TIME, time, sizeof(time));
    if (ret < 0) {
        LOG_ERR("Failed to get date and time: %d", ret);
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
          "\"CurrentBand\":\"%s\","
          "\"SupportedBands\":\"%s\","
          "\"AreaCode\":\"%s\","
          "\"UE_Mode\":\"%s\","
          "\"Operator\":\"%s\","
          "\"MCC\":\"%s\","
          "\"MNC\":\"%s\","
          "\"CellID\":\"%s\","
          "\"IP_Address\":\"%s\","
          "\"Battery_Voltage\":\"%s\","
          "\"Temperature\":\"%s\","
          "\"Time\":\"%s\""
        "}",
        lte_rsp,
        lte_current_band,
        lte_sup_band,
        lte_area,
        lte_ue_mode,
        lte_operator,
        lte_mcc,
        lte_mnc,
        lte_cell_id,
        modem_ip_address,
        battery_voltage,
        temp,
        time
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
                update_lte_info = true;
                k_sem_give(&lte_connected);
            }
            break;
        case LTE_LC_EVT_RRC_UPDATE:
            LOG_INF("RRC mode: %s",
                evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ?
                "Connected" : "Idle");
            update_lte_info = true;
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
    /*
    struct lte_lc_psm_cfg psm_cfg = {
    .tau = -1,           
    .active_time = 1       
    };
    lte_lc_psm_param_set_seconds(psm_cfg.tau,psm_cfg.active_time); // Set PSM parameters to 1,1
    lte_lc_psm_req(true);
    */
    lte_lc_system_mode_set(LTE_LC_SYSTEM_MODE_LTEM_GPS, 
                           LTE_LC_SYSTEM_MODE_PREFER_AUTO);

    
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

static void gnss_event_handler(int event)
{
    int err;
    
    switch (event) {
    case NRF_MODEM_GNSS_EVT_PVT: {
        /* Read the latest PVT frame */
        err = nrf_modem_gnss_read(&current_pvt,
                                  sizeof(current_pvt),
                                  NRF_MODEM_GNSS_DATA_PVT);
        if (err) {
            LOG_ERR("GNSS read failed: %d", err);
            break;
        }

        /* Show how many satellites are in view while acquiring first fix*/
        if(first_fix){
            int sat_count = 0;
            for (int i = 0; i < ARRAY_SIZE(current_pvt.sv); i++) {
                if (current_pvt.sv[i].signal) {
                    sat_count++;
                }
            }
            LOG_INF(" Satellites in view: %d", sat_count);
        }
        break;
    }
	case NRF_MODEM_GNSS_EVT_FIX: 
        /* Handle first fix event */
        if(first_fix){
		    LOG_INF("GNSS fix event");   
            first_fix = false;
        }       
		/* Grab the new PVT data */
		err = nrf_modem_gnss_read(&current_pvt, sizeof(current_pvt), NRF_MODEM_GNSS_DATA_PVT);
		if (err) {
			LOG_ERR("Failed to read PVT on FIX: %d", err);
			break;
		}
		
		#if CONFIG_TRACKER_PERIODIC_INTERVAL <= 1
			/* In single-shot (0) or continuous (1) mode, wake the main loop here */
			k_sem_give(&gnss_fix_sem);
		#endif

		break;


    case NRF_MODEM_GNSS_EVT_SLEEP_AFTER_FIX:
        LOG_INF("GNSS sleep after fix");
        k_sem_give(&gnss_fix_sem);
        break;

    case NRF_MODEM_GNSS_EVT_PERIODIC_WAKEUP:
        LOG_INF("GNSS periodic wakeup");
        break;

    case NRF_MODEM_GNSS_EVT_BLOCKED:
        LOG_ERR("GNSS is blocked by LTE event");
        break;

    case NRF_MODEM_GNSS_EVT_SLEEP_AFTER_TIMEOUT:
        LOG_INF("GNSS sleep after timeout");
        break;

    default:
        break;
    }
}

static int gnss_init_and_start(void)
{
    int err;
    #if defined(CONFIG_GNSS_HIGH_ACCURACY_TIMING_SOURCE)
        if (nrf_modem_gnss_timing_source_set(NRF_MODEM_GNSS_TIMING_SOURCE_TCXO)){
            LOG_ERR("Failed to set TCXO timing source");
            return -1;
        }
    #endif
    #if defined(CONFIG_GNSS_LOW_ACCURACY) || defined (CONFIG_BOARD_THINGY91_NRF9160_NS)
        uint8_t use_case;
        use_case = NRF_MODEM_GNSS_USE_CASE_MULTIPLE_HOT_START | NRF_MODEM_GNSS_USE_CASE_LOW_ACCURACY;
        if (nrf_modem_gnss_use_case_set(use_case) != 0) {
            LOG_ERR("Failed to set low accuracy use case");
            return -1;
        }
    #else 
        /* Use Case: continuous tracking, no scheduled downloads */
        uint32_t uc = NRF_MODEM_GNSS_USE_CASE_MULTIPLE_HOT_START
                    | NRF_MODEM_GNSS_USE_CASE_SCHED_DOWNLOAD_DISABLE;

        err = nrf_modem_gnss_use_case_set(uc);
        if (err) {
            LOG_WRN("GNSS use_case_set: %d", err);
        }

    #endif
        /* Configure GNSS event handler . */
        if (nrf_modem_gnss_event_handler_set(gnss_event_handler) != 0) {
            LOG_ERR("Failed to set GNSS event handler");
            return -1;
        }

        if (nrf_modem_gnss_fix_interval_set(CONFIG_TRACKER_PERIODIC_INTERVAL) != 0) {
            LOG_ERR("Failed to set GNSS fix interval");
            return -1;
        }

        if (nrf_modem_gnss_fix_retry_set(CONFIG_TRACKER_PERIODIC_TIMEOUT) != 0) {
            LOG_ERR("Failed to set GNSS fix retry");
            return -1;
        }

        if (nrf_modem_gnss_start() != 0) {
            LOG_ERR("Failed to start GNSS");
            return -1;
        }
        if (nrf_modem_gnss_prio_mode_enable() != 0){
            LOG_ERR("Error setting GNSS priority mode");
            return -1;
        }
        return 0;
    }

static void pack_fix_data(struct nrf_modem_gnss_pvt_data_frame *pvt_data)
{
    /* Build the JSON string from GNSS PVT data */
    int len = snprintf(json_payload, sizeof(json_payload),
        "{"
          "\"GNSS\":{"
            "\"device_id\":\"%s\","
            "\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
            "\"lat\":%.6f,"
            "\"lon\":%.6f,"
            "\"alt\":%.1f,"
            "\"speed\":%.2f,"
            "\"heading\":%.1f,"
            "\"vert_speed\":%.2f"
          "}"
        "}",
        mqtt_client_id,
        pvt_data->datetime.year,
        pvt_data->datetime.month,
        pvt_data->datetime.day,
        pvt_data->datetime.hour,
        pvt_data->datetime.minute,
        pvt_data->datetime.seconds,
        pvt_data->datetime.ms,
        pvt_data->latitude,
        pvt_data->longitude,
        (double)pvt_data->altitude,
        (double)pvt_data->speed,
        (double)pvt_data->heading,
        (double)pvt_data->vertical_speed
    );

    if (len < 0) {
        LOG_ERR("Failed to format JSON: %d", len);
        return;
    } else if ((size_t)len >= sizeof(json_payload)) {
        LOG_WRN("JSON truncated (%d bytes needed)", len);
    }

    /* Print the JSON payload */
	//LOG_INF("%s", json_payload);
}

int publish_all() {
	int err;
    static char topic[200];
   
    snprintf(topic, sizeof(topic), "%s%s",mqtt_client_id,"/gnss_json");
	err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
		(uint8_t *)json_payload, strlen(json_payload),
		topic);

    snprintf(topic, sizeof(topic), "%s%s",mqtt_client_id,"/sensor_json");
    err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
        (uint8_t *)json_payload3, strlen(json_payload3),
        topic);
    /*
    snprintf(topic, sizeof(topic), "%s%s", mqtt_client_id, "/lte_json");
    err = data_publish(&client, MQTT_QOS_0_AT_MOST_ONCE,
        (uint8_t *)json_payload2, strlen(json_payload2),
        topic);

    */
   
    return err;
}

static void button_handler(uint32_t button_state, uint32_t has_changed)
{
	switch (has_changed) {
	case DK_BTN1_MSK:
		if (button_state & DK_BTN1_MSK){
			int err = publish_all();
			if (err) {
				LOG_ERR("Failed to publish message, %d", err);
				return;
			}
		}
		break;
	}

}

//Get new GNSS fix imediately pack data into internal buffer (JSON format)
static void new_fix() {
    int ret;
    while (k_sem_take(&gnss_fix_sem, K_NO_WAIT) == 0) { /* nothing */ }
    heartbeat_config(HB_COLOR_YELLOW, 1, 500);
    ret = k_sem_take(&gnss_fix_sem, K_FOREVER);
    pack_fix_data(&current_pvt);
}

//Initialize dependencies
static int init() {
    int err;
    
    /* Delay on bootup so PC USB has time to connect to the serial port*/
	k_sleep(K_SECONDS(1));

    /* Shell Commands - Initialize first to retrieve device settings from non-volatile memory*/
    shell_mqtt_init();
    LOG_INF("Shell Initialized");
    
	/* Display banner and device settings */
	LOG_INF("Tracker Demo Version %d.%d.%d started\n",CONFIG_TRACKER_VERSION_MAJOR,CONFIG_TRACKER_VERSION_MINOR,CONFIG_TRACKER_VERSION_PATCH);
	LOG_INF("Device ID: %s", mqtt_client_id);
    LOG_INF("MQTT Broker Host: %s", mqtt_broker_host);
    LOG_INF("MQTT Broker Port: %d", mqtt_broker_port);
    LOG_INF("MQTT Publish Interval (sec): %d", mqtt_publish_interval);
    //LOG_INF("MQTT Subscribe Topic: %s", mqtt_subscribe_topic);
    LOG_INF("MQTT Connection Keep Alive (sec): %d", mqtt_keepalive);
    
	LOG_INF("GNSS Periodic Interval: %d", CONFIG_TRACKER_PERIODIC_INTERVAL);
	LOG_INF("GNSS Periodic Timeout: %d", CONFIG_TRACKER_PERIODIC_TIMEOUT);

	/* Initializations */
    init_sensors();
    /* LEDs and Button */
	err = dk_leds_init();
	if (err){
		LOG_ERR("Failed to initialize the LEDs Library");
        return err;
	}
    heartbeat_config(HB_COLOR_RED, 1, 500);
	err = dk_buttons_init(button_handler);
	if (err) {
		LOG_ERR("Failed to initialize button handler: %d", err);
		return err;
	}
	/* Modem */
    LOG_INF("Initializing modem");
	err = modem_configure();
    if (err) {
        LOG_ERR("nrf_modem_lib_init failed: %d", err);
        return err;
    }
    LOG_INF("Modem initialized");
    pack_lte_data();
    
	/* Decativate LTE until GNSS fix is achieved */
	LOG_INF("Deactivating LTE radio for GNSS fix");
	err = lte_lc_func_mode_set(LTE_LC_FUNC_MODE_DEACTIVATE_LTE);
	if (err) {
		LOG_ERR("Failed to decativate LTE and enable GNSS functional mode");
		return err;
	}

    /* GNSS - get first fix */
    LOG_INF("Starting GNSS");
	gnss_init_and_start();
	/* Wait for first GNSS fix*/
    LOG_INF("Waiting for first GNSS fix");
    /* Indicate Yellow for new fix */
    heartbeat_config(HB_COLOR_YELLOW, 1, 500);
	k_sem_take(&gnss_fix_sem, K_FOREVER);
    LOG_INF("GNSS Fix acheived");


    /* Bring up LTE connection */
    /* Indicate Blue fast blink for LTE connection operation*/
    heartbeat_config(HB_COLOR_BLUE, 2, 250);
    /* Activate LTE */
    LOG_INF("Activating LTE radio");
    err = lte_lc_func_mode_set(LTE_LC_FUNC_MODE_ACTIVATE_LTE);
    if (err) {
        LOG_ERR("ACTIVATE_LTE failed: %d", err);
        return err;
    }
    /* Attach to LTE network */
    LOG_INF("Attaching LTE (async)");
    err = lte_lc_connect_async(lte_handler);
    if (err) {
        LOG_ERR("connect_async failed: %d", err);
        return err;
    }
    k_sem_take(&lte_connected, K_FOREVER);


    /* Connect to MQTT server */
    /* One-time MQTT setup */
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
    err = fds_init(&client, &fds);
    if (err) {
        LOG_ERR("fds_init: %d", err);
        return err;
    }
    heartbeat_config(HB_COLOR_BLUE, 1, 500);
    return 0;
}

// Handle MQTT connection and publish data
static void mqtt_handle() {
    int err;
/* Publish the JSON to the MQTT broker*/
    //LOG_INF("MQTT Poll and Ping");
    /* Do a quick, non-blocking poll to handle any incoming packets */
    int ret = poll(&fds, 1, 0);
    if (ret < 0) {
        LOG_ERR("poll() error: %d", errno);
    } else if ((ret > 0) && (fds.revents & POLLIN)) {
        mqtt_input(&client);
    }
    /* Send keep-alive ping*/
    //mqtt_live(&client);

    /* Publish the JSON */
    //LOG_INF("MQTT Publish");
    

    err = publish_all();
    
    if (err) {
        LOG_ERR("data_publish: %d", err);
        /* Indicate Red fast blink for bad publish */
        heartbeat_config(HB_COLOR_RED, 2, 250);
        bad_publish++;
        if(bad_publish >= BAD_PUBLISH_LIMIT)
            sys_reboot(SYS_REBOOT_COLD);
        
    } else {
        /* Indicate Green for valid publish */
        
        heartbeat_config(HB_COLOR_GREEN, 2, 250);
        bad_publish = 0;
        
    }
}

int main(void) {
	int err;
    err = init();
    if (err) {
        LOG_ERR("Initialization failed: %d", err);
        sys_reboot(SYS_REBOOT_COLD);
    }

    while (1) {
        int err;
        int start = k_uptime_get_32();
        //err = nrf_modem_gnss_prio_mode_enable();
       
        new_fix(); //blocking

        //err = nrf_modem_gnss_prio_mode_disable();
        int fixtime = k_uptime_get_32() - start;
        LOG_INF("New GNSS fix took: %d ms", fixtime);
        pack_sensor_data();
        if (update_lte_info) {
            //pack_lte_data();
            update_lte_info = false;
        }

        mqtt_handle();

        
        int end = k_uptime_get_32() - start;
        LOG_INF("Full Loop Took: %d ms", end);
    }
    return 0;
}