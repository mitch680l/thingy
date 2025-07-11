#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "gnss.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

// Configuration constants
#define GPS_TARGET_RATE_HZ 25  // Change this to desired rate (1, 5, 10, 25 Hz)
#define GPS_READ_BUFFER_SIZE 1024  // Larger buffer for high-speed reads
#define GPS_READ_INTERVAL_MS (1000 / (GPS_TARGET_RATE_HZ * 3))  // Read 3x faster than target rate
#define GPS_STARTUP_DELAY_MS 2000  // Startup delay
#define GPS_CONFIG_TIMEOUT_MS 500  // Configuration timeout
#define GPS_MAX_CONFIG_ATTEMPTS 3

// Rate configuration lookup table
struct gps_rate_config {
    uint8_t rate_hz;
    uint16_t meas_rate_ms;
    uint16_t nav_rate_cycles;
};

static const struct gps_rate_config rate_configs[] = {
    {1,  1000, 1},
    {5,  200,  1},
    {10, 100,  1},
    {25, 40,   1}
};

// Optimized UBX message templates
static uint8_t cfg_rate_template[] = {
    0xB5, 0x62,           // UBX header
    0x06, 0x08,           // CFG-RATE
    0x06, 0x00,           // Length
    0x00, 0x00,           // Measurement rate (will be filled)
    0x01, 0x00,           // Navigation rate
    0x01, 0x00,           // Time reference
    0x00, 0x00            // Checksum (will be calculated)
};

static uint8_t cfg_msg_nav_pvt[] = {
    0xB5, 0x62,           // UBX header
    0x06, 0x01,           // CFG-MSG
    0x03, 0x00,           // Length
    0x01, 0x07,           // NAV-PVT
    0x01,                 // Rate
    0x00, 0x00            // Checksum (will be calculated)
};

// VALSET configuration for modern receivers
static uint8_t cfg_valset_rate_template[] = {
    0xB5, 0x62,           // UBX header
    0x06, 0x8A,           // CFG-VALSET
    0x0D, 0x00,           // Length
    0x00,                 // Version
    0x01,                 // Layer (RAM)
    0x00, 0x00,           // Reserved
    // CFG-RATE-MEAS key (0x30210001)
    0x01, 0x00, 0x21, 0x30,
    0x00, 0x00,           // Value (will be filled)
    // CFG-RATE-NAV key (0x30210002)
    0x02, 0x00, 0x21, 0x30,
    0x01, 0x00,           // Value (1 cycle)
    0x00, 0x00            // Checksum (will be calculated)
};

// Global variables
static uint8_t rxbuf[GPS_READ_BUFFER_SIZE];
static uint8_t partial_buffer[GPS_READ_BUFFER_SIZE * 2];  // Buffer for handling partial reads
static size_t partial_buffer_len = 0;
static struct ubx_nav_pvt_t pvt;
static uint32_t last_tow = 0;
static int pvt_count = 0;
static int read_count = 0;
char json_payload[512] = "NO PVT";
static int fix_count_in_period = 0;
static uint32_t fix_rate_start_time = 0;
static bool gps_configured = false;
static uint32_t last_read_time = 0;

LOG_MODULE_REGISTER(gnss_opt);

const struct device *gpio0 = DEVICE_DT_GET(GPIO0_NODE);
const struct device *i2c_dev = DEVICE_DT_GET(I2C_NODE);

// Helper functions
inline void ubx_checksum(const uint8_t *data, size_t len, uint8_t *ck_a, uint8_t *ck_b) {
    *ck_a = 0;
    *ck_b = 0;
    for (size_t i = 0; i < len; i++) {
        *ck_a += data[i];
        *ck_b += *ck_a;
    }
}

const struct gps_rate_config* get_rate_config(uint8_t target_hz) {
    for (int i = 0; i < ARRAY_SIZE(rate_configs); i++) {
        if (rate_configs[i].rate_hz == target_hz) {
            return &rate_configs[i];
        }
    }
    // Default to 10Hz if not found
    return &rate_configs[2];
}

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
        "\"rate\":%d}",
        pvt->year, pvt->month, pvt->day,
        pvt->hour, pvt->min, pvt->sec,
        (int)lat, abs((int)((lat - (int)lat) * 1e7)),
        (int)lon, abs((int)((lon - (int)lon) * 1e7)),
        pvt->fixType, pvt->numSV,
        (int)alt, abs((int)((alt - (int)alt) * 100)),
        (int)speed, abs((int)((speed - (int)speed) * 100)),
        GPS_TARGET_RATE_HZ);
    k_mutex_unlock(&json_mutex);
}

bool parse_nav_pvt(const uint8_t *buf, size_t len, struct ubx_nav_pvt_t *out) {
    // Optimized parser with early exit conditions
    if (len < 8 + NAV_PVT_LEN) return false;
    
    for (size_t i = 0; i <= len - (8 + NAV_PVT_LEN); i++) {
        // Look for UBX header + NAV-PVT
        if (buf[i] == 0xB5 && buf[i+1] == 0x62 && buf[i+2] == 0x01 && buf[i+3] == 0x07) {
            uint16_t payload_len = buf[i+4] | (buf[i+5] << 8);
            if (payload_len != NAV_PVT_LEN) continue;
            
            // Check if we have enough data for complete message
            if (i + 8 + payload_len > len) {
                break;  // Incomplete message, will be handled in next read
            }
            
            // Fast copy
            memcpy(out, &buf[i+6], NAV_PVT_LEN);
            
            // Optional checksum verification for critical applications
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

size_t process_gps_data(const uint8_t *new_data, size_t new_len) {
    size_t processed = 0;
    
    // Combine with partial buffer if we have leftover data
    if (partial_buffer_len > 0) {
        size_t copy_len = MIN(new_len, sizeof(partial_buffer) - partial_buffer_len);
        memcpy(partial_buffer + partial_buffer_len, new_data, copy_len);
        partial_buffer_len += copy_len;
        
        // Try to parse from combined buffer
        if (parse_nav_pvt(partial_buffer, partial_buffer_len, &pvt)) {
            // Successfully parsed, clear partial buffer
            partial_buffer_len = 0;
            processed = copy_len;
            return processed;
        }
        
        // If combined buffer is getting too large, reset it
        if (partial_buffer_len > GPS_READ_BUFFER_SIZE) {
            LOG_WRN("Partial buffer overflow, resetting");
            partial_buffer_len = 0;
        }
    }
    
    // Try to parse directly from new data
    if (parse_nav_pvt(new_data, new_len, &pvt)) {
        processed = new_len;
        return processed;
    }
    
    // Look for start of UBX message at the end of buffer for partial handling
    for (int i = new_len - 1; i >= 0; i--) {
        if (new_data[i] == 0xB5 && i + 1 < new_len && new_data[i+1] == 0x62) {
            // Found potential start of UBX message
            size_t partial_len = new_len - i;
            if (partial_len < 8 + NAV_PVT_LEN) {  // Not a complete message
                // Store partial message for next read
                memcpy(partial_buffer, new_data + i, partial_len);
                partial_buffer_len = partial_len;
                processed = i;  // Mark everything before this as processed
                LOG_DBG("Stored partial UBX message (%zu bytes)", partial_len);
                break;
            }
        }
    }
    
    return processed;
}

bool parse_ack(const uint8_t *buf, size_t len, uint8_t cls, uint8_t id) {
    if (len < 10) return false;
    
    for (size_t i = 0; i <= len - 10; i++) {
        if (buf[i] == 0xB5 && buf[i+1] == 0x62 && buf[i+2] == 0x05) {
            if (buf[i+3] == 0x01 && buf[i+6] == cls && buf[i+7] == id) {
                return true;  // ACK
            } else if (buf[i+3] == 0x00 && buf[i+6] == cls && buf[i+7] == id) {
                return false; // NAK
            }
        }
    }
    return false;
}

bool send_ubx_message(uint8_t *msg, size_t len, const char *desc) {
    // Calculate checksum
    uint8_t ck_a, ck_b;
    ubx_checksum(&msg[2], len - 4, &ck_a, &ck_b);
    msg[len - 2] = ck_a;
    msg[len - 1] = ck_b;
    
    // Send message
    int ret = i2c_write(i2c_dev, msg, len, M10S_ADDR);
    if (ret != 0) {
        LOG_ERR("Failed to send %s: %d", desc, ret);
        return false;
    }
    
    // Wait for response with timeout
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

bool configure_gps_rate(uint8_t target_hz) {
    const struct gps_rate_config *config = get_rate_config(target_hz);
    bool success = false;
    
    LOG_INF("Configuring GPS for %d Hz (meas_rate: %d ms)", target_hz, config->meas_rate_ms);
    
    // Method 1: Legacy CFG-RATE
    uint8_t cfg_rate_msg[sizeof(cfg_rate_template)];
    memcpy(cfg_rate_msg, cfg_rate_template, sizeof(cfg_rate_template));
    cfg_rate_msg[6] = config->meas_rate_ms & 0xFF;
    cfg_rate_msg[7] = (config->meas_rate_ms >> 8) & 0xFF;
    
    if (send_ubx_message(cfg_rate_msg, sizeof(cfg_rate_msg), "CFG-RATE")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    // Method 2: Enable NAV-PVT messages
    if (send_ubx_message(cfg_msg_nav_pvt, sizeof(cfg_msg_nav_pvt), "CFG-MSG NAV-PVT")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    // Method 3: Modern VALSET approach
    uint8_t cfg_valset_msg[sizeof(cfg_valset_rate_template)];
    memcpy(cfg_valset_msg, cfg_valset_rate_template, sizeof(cfg_valset_rate_template));
    cfg_valset_msg[12] = config->meas_rate_ms & 0xFF;
    cfg_valset_msg[13] = (config->meas_rate_ms >> 8) & 0xFF;
    
    if (send_ubx_message(cfg_valset_msg, sizeof(cfg_valset_msg), "VALSET Rate")) {
        success = true;
    }
    
    return success;
}

void gnss_int(void) {
    LOG_INF("Starting MAX-M10S GPS at %d Hz", GPS_TARGET_RATE_HZ);
    
    // Initialize GPIO
    if (!device_is_ready(gpio0)) {
        LOG_ERR("GPIO0 device not ready");
        return;
    }
    
    // Power on QWIIC with optimized timing
    gpio_pin_configure(gpio0, 3, GPIO_OUTPUT | GPIO_ACTIVE_HIGH);
    gpio_pin_set(gpio0, 3, 1);
    LOG_INF("QWIIC power on, waiting for GPS startup...");
    k_sleep(K_MSEC(GPS_STARTUP_DELAY_MS));
    
    // Initialize I2C
    if (!device_is_ready(i2c_dev)) {
        LOG_ERR("I2C device not ready");
        return;
    }
    
    // Configure GPS with multiple attempts
    for (int attempt = 0; attempt < GPS_MAX_CONFIG_ATTEMPTS; attempt++) {
        LOG_INF("Configuration attempt %d/%d", attempt + 1, GPS_MAX_CONFIG_ATTEMPTS);
        if (configure_gps_rate(GPS_TARGET_RATE_HZ)) {
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

void gnss_main_loop(void) {
    uint32_t current_time = k_uptime_get_32();
    
    // Adaptive read timing based on target rate
    if (current_time - last_read_time < GPS_READ_INTERVAL_MS) {
        k_sleep(K_MSEC(1));  // Small sleep to prevent busy waiting
        return;
    }
    
    last_read_time = current_time;
    
    // Clear buffer and read
    memset(rxbuf, 0, GPS_READ_BUFFER_SIZE);
    int ret = i2c_burst_read(i2c_dev, M10S_ADDR, 0xFF, rxbuf, GPS_READ_BUFFER_SIZE);
    read_count++;
    
    if (ret != 0) {
        if (read_count % 100 == 0) {
            LOG_WRN("I2C read failed: %d (count: %d)", ret, read_count);
        }
        return;
    }
    
    // Check how much data we actually got
    size_t actual_data_len = 0;
    for (int i = GPS_READ_BUFFER_SIZE - 1; i >= 0; i--) {
        if (rxbuf[i] != 0) {
            actual_data_len = i + 1;
            break;
        }
    }
    
    if (actual_data_len == 0) {
        return;  // No data received
    }
    
    // Process GPS data with partial read handling
    size_t processed = process_gps_data(rxbuf, actual_data_len);
    
    // Check if we got a valid PVT message
    if (pvt.iTOW != last_tow) {
        last_tow = pvt.iTOW;
        pvt_count++;
        
        // Initialize timing on first fix
        if (fix_rate_start_time == 0 && pvt.fixType >= 2) {
            fix_rate_start_time = current_time;
            fix_count_in_period = 0;
        }
        
        if (pvt.fixType >= 2) {
            format_nav_pvt_json(&pvt);
            fix_count_in_period++;
            
            // Calculate and log fix rate every 10 seconds
            if (fix_rate_start_time > 0 && current_time - fix_rate_start_time >= 10000) {
                float actual_rate = (float)fix_count_in_period / 10.0f;
                LOG_INF("GPS Rate: %.1f Hz (target: %d Hz, fixes: %d, total: %d)", 
                        actual_rate, GPS_TARGET_RATE_HZ, fix_count_in_period, pvt_count);
                
                // Reset counters
                fix_rate_start_time = current_time;
                fix_count_in_period = 0;
            }
        } else {
            // Reduce logging frequency for no-fix messages
            if (pvt_count % 50 == 0) {
                LOG_INF("Acquiring fix... (type: %d, sats: %d)", pvt.fixType, pvt.numSV);
            }
        }
    }
    
    // Periodic debug info including partial buffer status
    if (read_count % 500 == 0) {
        LOG_DBG("Read stats: %d reads, %d PVT messages, rate: %d Hz, partial: %zu bytes", 
                read_count, pvt_count, GPS_TARGET_RATE_HZ, partial_buffer_len);
    }
}

// Utility function to change rate at runtime
bool gnss_set_rate(uint8_t new_rate_hz) {
    LOG_INF("Changing GPS rate from %d Hz to %d Hz", GPS_TARGET_RATE_HZ, new_rate_hz);
    
    if (configure_gps_rate(new_rate_hz)) {
        // Reset counters and partial buffer
        fix_rate_start_time = 0;
        fix_count_in_period = 0;
        partial_buffer_len = 0;  // Clear any partial data
        LOG_INF("GPS rate changed successfully");
        return true;
    }
    
    LOG_ERR("Failed to change GPS rate");
    return false;
}