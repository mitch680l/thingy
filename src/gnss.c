#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/logging/log.h>
#include "gnss.h"
#include "shell_commands.h" 
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include "config.h"
#include "heartbeat.h"

struct gps_rate_config {
    uint8_t rate_hz;
    uint16_t meas_rate_ms;
    uint16_t nav_rate_cycles;
};

static const struct gps_rate_config rate_configs[] = {
    {1,  1000, 1},
    {5,  200,  1},
    {10, 100,  1},
    {15, 66,  1},
    {20, 50,   1},
    {25, 40,   1},
};

static uint8_t cfg_rate_template[] = {
    0xB5, 0x62,           
    0x06, 0x08,           
    0x06, 0x00,           
    0x00, 0x00,           
    0x01, 0x00,           
    0x01, 0x00,           
    0x00, 0x00            
};

static uint8_t cfg_msg_nav_pvt[] = {
    0xB5, 0x62,           
    0x06, 0x01,           
    0x03, 0x00,           
    0x01, 0x07,           
    0x01,                 
    0x00, 0x00            
};

static uint8_t cfg_valset_rate_template[] = {
    0xB5, 0x62,           
    0x06, 0x8A,           
    0x0D, 0x00,           
    0x00,                 
    0x01,                 
    0x00, 0x00,           
    0x01, 0x00, 0x21, 0x30,
    0x00, 0x00,           
    0x02, 0x00, 0x21, 0x30,
    0x01, 0x00,           
    0x00, 0x00            
};

static uint8_t rxbuf[GPS_READ_BUFFER_SIZE];
static uint8_t partial_buffer[GPS_READ_BUFFER_SIZE * 2];
static size_t partial_buffer_len = 0;
static struct ubx_nav_pvt_t pvt;
static uint32_t last_tow = 0;
static int pvt_count = 0;
static int read_count = 0;
static int fix_count_in_period = 0;
static uint32_t fix_rate_start_time = 0;
static bool gps_configured = false;
static uint32_t last_read_time = 0;
static double actual_rate = 0.0;
LOG_MODULE_REGISTER(gnss_opt);

const struct device *i2c_dev = DEVICE_DT_GET(I2C_NODE);

/**
 * Calculate UBX checksum for message validation
 * @param data - data buffer to calculate checksum for
 * @param len - length of data buffer
 * @param ck_a - pointer to store first checksum byte
 * @param ck_b - pointer to store second checksum byte
 * @return void - fills checksum output parameters
 */
inline void ubx_checksum(const uint8_t *data, size_t len, uint8_t *ck_a, uint8_t *ck_b) {
    *ck_a = 0;
    *ck_b = 0;
    for (size_t i = 0; i < len; i++) {
        *ck_a += data[i];
        *ck_b += *ck_a;
    }
}

/**
 * Find GPS rate configuration for target frequency
 * @param target_hz - desired GPS update rate in Hz
 * @return pointer to matching rate configuration or default 10Hz config
 */
const struct gps_rate_config* get_rate_config(uint8_t target_hz) {
    for (int i = 0; i < ARRAY_SIZE(rate_configs); i++) {
        if (rate_configs[i].rate_hz == target_hz) {
            return &rate_configs[i];
        }
    }
    return &rate_configs[2];
}




/**
 * Format NAV-PVT data into JSON string
 * @param pvt - pointer to UBX NAV-PVT structure
 * @return void - updates global json_payload with formatted GPS data
 */
void format_nav_pvt_json(const struct ubx_nav_pvt_t *pvt) {
    double lat = (double)pvt->lat / 1e7;
    double lon = (double)pvt->lon / 1e7;
    double alt = (double)pvt->hMSL / 1000.0;
    double speed = (double)pvt->gSpeed / 1000.0;
    
    k_mutex_lock(&json_mutex, K_FOREVER);
    snprintk(json_payload, sizeof(json_payload),
        "{\"time\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\","
        "\"lat\":%d.%07d,\"lon\":%d.%07d,"
        "\"fixType\":%d,\"numSV\":%d,"
        "\"alt_m\":%d.%02d,\"gSpeed\":%d.%02d,"
        "\"rate\":%f}",
        pvt->year, pvt->month, pvt->day,
        pvt->hour, pvt->min, pvt->sec,
        (int)lat, abs((int)((lat - (int)lat) * 1e7)),
        (int)lon, abs((int)((lon - (int)lon) * 1e7)),
        pvt->fixType, pvt->numSV,
        (int)alt, abs((int)((alt - (int)alt) * 100)),
        (int)speed, abs((int)((speed - (int)speed) * 100)),
        actual_rate);
    k_mutex_unlock(&json_mutex);
}

/**
 * Parse UBX NAV-PVT message from buffer
 * @param buf - data buffer to parse
 * @param len - buffer length
 * @param out - output structure to fill with parsed data
 * @return true if valid NAV-PVT message parsed, false otherwise
 */
bool parse_nav_pvt(const uint8_t *buf, size_t len, struct ubx_nav_pvt_t *out) {
    if (len < 8 + NAV_PVT_LEN) return false;
    
    for (size_t i = 0; i <= len - (8 + NAV_PVT_LEN); i++) {
        if (buf[i] == 0xB5 && buf[i+1] == 0x62 && buf[i+2] == 0x01 && buf[i+3] == 0x07) {
            uint16_t payload_len = buf[i+4] | (buf[i+5] << 8);
            if (payload_len != NAV_PVT_LEN) continue;
            
            if (i + 8 + payload_len > len) {
                break;
            }
            
            memcpy(out, &buf[i+6], NAV_PVT_LEN);
            
            #ifdef VERIFY_CHECKSUM
            uint8_t ck_a, ck_b;
            ubx_checksum(&buf[i+2], 4 + payload_len, &ck_a, &ck_b);
            if (buf[i+6+payload_len] != ck_a || buf[i+7+payload_len] != ck_b) {
                continue;
            }
            #endif
            
            return true;
        }
    }
    return false;
}

/**
 * Process incoming GPS data with partial message handling
 * @param new_data - incoming data buffer
 * @param new_len - data length
 * @return number of bytes processed, updates global pvt structure if valid message found
 */
size_t process_gps_data(const uint8_t *new_data, size_t new_len) {
    size_t processed = 0;
    
    if (partial_buffer_len > 0) {
        size_t copy_len = MIN(new_len, sizeof(partial_buffer) - partial_buffer_len);
        memcpy(partial_buffer + partial_buffer_len, new_data, copy_len);
        partial_buffer_len += copy_len;
        
        if (parse_nav_pvt(partial_buffer, partial_buffer_len, &pvt)) {
            partial_buffer_len = 0;
            processed = copy_len;
            return processed;
        }
        
        if (partial_buffer_len > GPS_READ_BUFFER_SIZE) {
            LOG_WRN("Partial buffer overflow, resetting");
            partial_buffer_len = 0;
        }
    }
    
    if (parse_nav_pvt(new_data, new_len, &pvt)) {
        processed = new_len;
        return processed;
    }
    
    for (int i = new_len - 1; i >= 0; i--) {
        if (new_data[i] == 0xB5 && i + 1 < new_len && new_data[i+1] == 0x62) {
            size_t partial_len = new_len - i;
            if (partial_len < 8 + NAV_PVT_LEN) {
                memcpy(partial_buffer, new_data + i, partial_len);
                partial_buffer_len = partial_len;
                processed = i;
                LOG_DBG("Stored partial UBX message (%zu bytes)", partial_len);
                break;
            }
        }
    }
    
    return processed;
}

/**
 * Parse UBX ACK/NAK message from buffer
 * @param buf - data buffer to parse
 * @param len - buffer length
 * @param cls - message class to match
 * @param id - message ID to match
 * @return true if ACK received, false if NAK or not found
 */
bool parse_ack(const uint8_t *buf, size_t len, uint8_t cls, uint8_t id) {
    if (len < 10) return false;
    
    for (size_t i = 0; i <= len - 10; i++) {
        if (buf[i] == 0xB5 && buf[i+1] == 0x62 && buf[i+2] == 0x05) {
            if (buf[i+3] == 0x01 && buf[i+6] == cls && buf[i+7] == id) {
                return true;
            } else if (buf[i+3] == 0x00 && buf[i+6] == cls && buf[i+7] == id) {
                return false;
            }
        }
    }
    return false;
}

/**
 * Send UBX message to GPS and wait for acknowledgment
 * @param msg - message buffer to send
 * @param len - message length
 * @param desc - description for logging
 * @return true if message sent and ACK received, false otherwise
 */
bool send_ubx_message(uint8_t *msg, size_t len, const char *desc) {
    uint8_t ck_a, ck_b;
    ubx_checksum(&msg[2], len - 4, &ck_a, &ck_b);
    msg[len - 2] = ck_a;
    msg[len - 1] = ck_b;
    
    int ret = i2c_write(i2c_dev, msg, len, M10S_ADDR);
    if (ret != 0) {
        LOG_ERR("Failed to send %s: %d", desc, ret);
        return false;
    }
    
    uint32_t timeout = k_uptime_get_32() + GPS_CONFIG_TIMEOUT_MS;
    while (k_uptime_get_32() < timeout) {
        k_sleep(K_MSEC(50));
        
        ret = i2c_burst_read(i2c_dev, M10S_ADDR, 0xFF, rxbuf, 256);
        if (ret == 0) {
            bool ack_result = parse_ack(rxbuf, 256, msg[2], msg[3]);
            if (ack_result) {
                LOG_INF("%s: ACK received", desc);
                return true;
            }
        }
    }
    
    LOG_WRN("%s: No ACK received", desc);
    return false;
}

/**
 * Configure GPS update rate using multiple UBX methods
 * @param target_hz - desired update rate in Hz
 * @return true if at least one configuration method succeeded
 */
bool configure_gps_rate(uint8_t target_hz) {
    const struct gps_rate_config *config = get_rate_config(target_hz);
    bool success = false;
    
    LOG_INF("Configuring GPS for %d Hz (meas_rate: %d ms)", target_hz, config->meas_rate_ms);
    
    uint8_t cfg_rate_msg[sizeof(cfg_rate_template)];
    memcpy(cfg_rate_msg, cfg_rate_template, sizeof(cfg_rate_template));
    cfg_rate_msg[6] = config->meas_rate_ms & 0xFF;
    cfg_rate_msg[7] = (config->meas_rate_ms >> 8) & 0xFF;
    
    if (send_ubx_message(cfg_rate_msg, sizeof(cfg_rate_msg), "CFG-RATE")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    if (send_ubx_message(cfg_msg_nav_pvt, sizeof(cfg_msg_nav_pvt), "CFG-MSG NAV-PVT")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    uint8_t cfg_valset_msg[sizeof(cfg_valset_rate_template)];
    memcpy(cfg_valset_msg, cfg_valset_rate_template, sizeof(cfg_valset_rate_template));
    cfg_valset_msg[12] = config->meas_rate_ms & 0xFF;
    cfg_valset_msg[13] = (config->meas_rate_ms >> 8) & 0xFF;
    
    if (send_ubx_message(cfg_valset_msg, sizeof(cfg_valset_msg), "VALSET Rate")) {
        success = true;
    }
    
    return success;
}

/**
 * Initialize GNSS system - power on, configure I2C, setup GPS
 * @return void - initializes GPS hardware and configuration
 */
void gnss_int(void) {
    LOG_INF("Starting MAX-M10S GPS at %d Hz", gnss_config.update_rate);
    k_sleep(K_MSEC(GPS_STARTUP_DELAY_MS-13));
    
    if (!device_is_ready(i2c_dev)) {
        LOG_ERR("I2C device not ready");
        return;
    }
    
    for (int attempt = 0; attempt < GPS_MAX_CONFIG_ATTEMPTS; attempt++) {
        LOG_INF("Configuration attempt %d/%d", attempt + 1, GPS_MAX_CONFIG_ATTEMPTS);
        if (configure_gps_rate(gnss_config.update_rate)) {
            gps_configured = true;
            break;
        }
        k_sleep(K_MSEC(500));
    }
    
    if (!gps_configured) {
        LOG_WRN("GPS configuration failed, continuing with default settings");
    }
    
    LOG_INF("GPS initialization complete, starting data collection...");
    last_read_time = k_uptime_get_32();
}

/**
 * Main GNSS processing loop - reads and processes GPS data
 * @return void - continuously processes GPS data and updates position info
 */
void gnss_main_loop(void) {
    uint32_t current_time = k_uptime_get_32();
    
    k_sleep(K_MSEC((1000 / gnss_config.update_rate)-13));
    
    last_read_time = current_time;
    
    memset(rxbuf, 0, GPS_READ_BUFFER_SIZE);
    int ret = i2c_burst_read(i2c_dev, M10S_ADDR, 0xFF, rxbuf, GPS_READ_BUFFER_SIZE);
    read_count++;
    
    if (ret != 0) {
        if (read_count % 100 == 0) {
            LOG_WRN("I2C read failed: %d (count: %d)", ret, read_count);
        }
        return;
    }

    size_t actual_data_len = 0;
    for (int i = GPS_READ_BUFFER_SIZE - 1; i >= 0; i--) {
        if (rxbuf[i] != 0) {
            actual_data_len = i + 1;
            break;
        }
    }
    
    if (actual_data_len == 0) {
        return;
    }

    process_gps_data(rxbuf, actual_data_len);
    
    if (pvt.iTOW != last_tow) {
        last_tow = pvt.iTOW;
        pvt_count++;
        
        if (fix_rate_start_time == 0 && pvt.fixType >= 2) {
            fix_rate_start_time = current_time;
            fix_count_in_period = 0;
        }
        
        if (pvt.fixType >= 2) {
            format_nav_pvt_json(&pvt);
            fix_count_in_period++;
            
            if (fix_rate_start_time > 0 && current_time - fix_rate_start_time >= 10000) {
                actual_rate = fix_count_in_period / 10.0;
                LOG_INF("GPS Rate: %.1f Hz (target: %d Hz, fixes: %d, total: %d)", 
                        actual_rate, gnss_config.update_rate, fix_count_in_period, pvt_count);
                pvt_count = 0;
                fix_rate_start_time = current_time;
                fix_count_in_period = 0;
            }
        } else {
            if (pvt_count % 50 == 0) {
                LOG_INF("Acquiring fix... (type: %d, sats: %d)", pvt.fixType, pvt.numSV);
            }
        }
    }

    if (pvt.numSV == 0) {
        ktd2026_blink_red_1hz_31();
    }
    else if (pvt.fixType >= 2) {
        ktd2026_blink_green_1hz_31();
    } else {
        ktd2026_blink_yellow_1hz_31();
    }

    if (read_count % 500 == 0) {
        LOG_DBG("Read stats: %d reads, %d PVT messages, rate: %d Hz, partial: %zu bytes", 
                read_count, pvt_count, gnss_config.update_rate, partial_buffer_len);
    }
}