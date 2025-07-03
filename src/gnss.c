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



uint8_t cfg_rate_10hz[] = {
    0xB5, 0x62,           
    0x06, 0x08,           
    0x06, 0x00,            
    0x28, 0x00,            
    0x01, 0x00,            
    0x01, 0x00,             
    0x00, 0x00             
};


uint8_t cfg_msg_nav_pvt[] = {
    0xB5, 0x62,            
    0x06, 0x01,             
    0x03, 0x00,           
    0x01, 0x07,             
    0x01,                  
    0x00, 0x00           
};


uint8_t cfg_valset_rate[] = {
    0xB5, 0x62,           
    0x06, 0x8A,         
    0x09, 0x00,           
    0x00,                 
    0x01,                
    0x00, 0x00,          
   
    0xA7, 0x00, 0x91, 0x20, 
    0x01,                  
   
    0x00, 0x00             
};


uint8_t cfg_valset_pvt[] = {
    0xB5, 0x62,           
    0x06, 0x8A,           
    0x15, 0x00,           
    0x00,                 
    0x01,                  
    0x00, 0x00,           

    0x01, 0x00, 0x21, 0x30, 
    0x28, 0x00,             

    0x02, 0x00, 0x21, 0x30,
    0x01, 0x00,

    0x03, 0x00, 0x21, 0x30,
    0x01, 0x00,

    0x00, 0x00        
};
uint8_t rxbuf[512];
struct ubx_nav_pvt_t pvt;
uint32_t last_tow = 0;
int pvt_count = 0;
int read_count = 0;
char json_payload[512] = "NO PVT";
static int fix_count_in_period = 0;
static uint32_t fix_rate_start_time = 0;
LOG_MODULE_REGISTER(i2ctest);
const struct device *gpio0 = DEVICE_DT_GET(GPIO0_NODE);
const struct device *i2c_dev = DEVICE_DT_GET(I2C_NODE);
void ubx_checksum(const uint8_t *data, size_t len, uint8_t *ck_a, uint8_t *ck_b) {
    *ck_a = 0;
    *ck_b = 0;
    for (size_t i = 0; i < len; i++) {
        *ck_a += data[i];
        *ck_b += *ck_a;
    }
}

void format_nav_pvt_json(const struct ubx_nav_pvt_t *pvt)
{
    double lat = (double)pvt->lat / 1e7;
    double lon = (double)pvt->lon / 1e7;
    double alt = (double)pvt->hMSL / 1000.0;
    double speed = (double)pvt->gSpeed / 1000.0;
    k_mutex_lock(&json_mutex, K_FOREVER);
    snprintk(json_payload, sizeof(json_payload),
        "{\"time\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\","
        "\"lat\":%d.%07d,\"lon\":%d.%07d,"
        "\"fixType\":%d,\"numSV\":%d,"
        "\"alt_m\":%d.%02d,\"gSpeed\":%d.%02d}",
        pvt->year, pvt->month, pvt->day,
        pvt->hour, pvt->min, pvt->sec,
        (int)lat, abs((int)((lat - (int)lat) * 1e7)),
        (int)lon, abs((int)((lon - (int)lon) * 1e7)),
        pvt->fixType, pvt->numSV,
        (int)alt, abs((int)((alt - (int)alt) * 100)),
        (int)speed, abs((int)((speed - (int)speed) * 100)));
    k_mutex_unlock(&json_mutex);
}

bool parse_nav_pvt(const uint8_t *buf, size_t len, struct ubx_nav_pvt_t *out) {
    for (size_t i = 0; i + 8 + NAV_PVT_LEN <= len; i++) {
        if (buf[i] == 0xB5 && buf[i+1] == 0x62 && buf[i+2] == 0x01 && buf[i+3] == 0x07) {
            uint16_t payload_len = buf[i+4] | (buf[i+5] << 8);
            if (payload_len != NAV_PVT_LEN) {
                LOG_DBG("NAV-PVT payload length mismatch: expected %d, got %d", NAV_PVT_LEN, payload_len);
                continue;
            }
            
            // Copy the payload
            memcpy(out, &buf[i+6], NAV_PVT_LEN);
            
            // Verify checksum (optional, but good practice)
            uint8_t ck_a, ck_b;
            ubx_checksum(&buf[i+2], 4 + payload_len, &ck_a, &ck_b);
            if (buf[i+6+payload_len] != ck_a || buf[i+7+payload_len] != ck_b) {
                LOG_DBG("NAV-PVT checksum mismatch");
                continue;
            }
            
            LOG_DBG("Found NAV-PVT at offset %d", i);
            return true;
        }
    }
    return false;
}

bool parse_ack(const uint8_t *buf, size_t len, uint8_t cls, uint8_t id) {
    for (size_t i = 0; i + 10 <= len; i++) {
        if (buf[i] == 0xB5 && buf[i+1] == 0x62 && buf[i+2] == 0x05) {
            if (buf[i+3] == 0x01 && buf[i+6] == cls && buf[i+7] == id) {
                LOG_INF("Got ACK for class 0x%02X id 0x%02X", cls, id);
                return true;
            } else if (buf[i+3] == 0x00) {
                LOG_WRN("Got NAK for class 0x%02X id 0x%02X", buf[i+6], buf[i+7]);
                return false;
            }
        }
    }
    return false;
}

bool send_ubx_message(uint8_t *msg, size_t len, const char *desc) {
    // Calculate and set checksum
    uint8_t ck_a, ck_b;
    ubx_checksum(&msg[2], len - 4, &ck_a, &ck_b);
    msg[len - 2] = ck_a;
    msg[len - 1] = ck_b;
    
    LOG_INF("Sending %s...", desc);
    int ret = i2c_write(i2c_dev, msg, len, M10S_ADDR);
    if (ret != 0) {
        LOG_ERR("Failed to send %s: %d", desc, ret);
        return false;
    }
    
    // Wait for response
    k_sleep(K_MSEC(100));
    
    // Check for ACK
    uint8_t rxbuf[256];
    ret = i2c_burst_read(i2c_dev, M10S_ADDR, 0xFF, rxbuf, sizeof(rxbuf));
    if (ret == 0) {
        if (parse_ack(rxbuf, sizeof(rxbuf), msg[2], msg[3])) {
            LOG_INF("%s configured successfully", desc);
            return true;
        }
    }
    
    LOG_WRN("No ACK received for %s", desc);
    return false;
}

bool configure_gps_10hz(void) {
    bool success = false;
    
    // Try multiple configuration methods
    LOG_INF("Trying legacy CFG-RATE message...");
    if (send_ubx_message(cfg_rate_10hz, sizeof(cfg_rate_10hz), "CFG-RATE 10Hz")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    LOG_INF("Trying legacy CFG-MSG for NAV-PVT...");
    if (send_ubx_message(cfg_msg_nav_pvt, sizeof(cfg_msg_nav_pvt), "CFG-MSG NAV-PVT")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    // Also try the newer VALSET method
    LOG_INF("Trying VALSET rate configuration...");
    if (send_ubx_message(cfg_valset_rate, sizeof(cfg_valset_rate), "VALSET Rate")) {
        success = true;
    }
    
    k_sleep(K_MSEC(100));
    
    LOG_INF("Trying VALSET PVT configuration...");
    if (send_ubx_message(cfg_valset_pvt, sizeof(cfg_valset_pvt), "VALSET PVT")) {
        success = true;
    }
    
    return success;
}

void gnss_int() {
    LOG_INF("Starting MAX-M10S 10Hz GPS Configuration");

    if (!device_is_ready(gpio0)) {
        LOG_ERR("GPIO0 device not ready");
        return;
    }
    LOG_INF("GPIO0 device ready");

    // Power on QWIIC
    gpio_pin_configure(gpio0, 3, GPIO_OUTPUT | GPIO_ACTIVE_HIGH);
    gpio_pin_set(gpio0, 3, 1);
    LOG_INF("QWIIC power on... Waiting for GPS startup");
    k_sleep(K_MSEC(1500));  // Give GPS more time to start

    if (!device_is_ready(i2c_dev)) {
        LOG_ERR("I2C2 not ready");
        return;
    }
    LOG_INF("I2C2 ready");

    // Configure GPS for 10Hz
    bool config_success = false;
    for (int attempt = 0; attempt < 2; attempt++) {
        LOG_INF("Configuration attempt %d", attempt + 1);
        if (configure_gps_10hz()) {
            config_success = true;
            break;
        }
        k_sleep(K_MSEC(500));
    }
    
    if (!config_success) {
        LOG_WRN("Configuration may have failed, but continuing...");
    }

    

    LOG_INF("Starting GPS data collection...");
}

void gnss_main_loop() {
    memset(rxbuf, 0, sizeof(rxbuf));  // Clear buffer
        int ret = i2c_burst_read(i2c_dev, M10S_ADDR, 0xFF, rxbuf, sizeof(rxbuf));
        read_count++;
        
        if (ret == 0) {
            // Look for UBX sync pattern in the data
            bool found_ubx = false;
            for (int i = 0; i < 16; i++) {
                if (rxbuf[i] == 0xB5 && rxbuf[i+1] == 0x62) {
                    found_ubx = true;
                    break;
                }
            }
            
            // Log first few bytes to see what we're getting
            if (read_count <= 3 || (read_count % 50 == 0)) {
                LOG_DBG("Read %d: %s UBX data found. First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", 
                    read_count, found_ubx ? "✓" : "✗",
                    rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3], 
                    rxbuf[4], rxbuf[5], rxbuf[6], rxbuf[7],
                    rxbuf[8], rxbuf[9], rxbuf[10], rxbuf[11],
                    rxbuf[12], rxbuf[13], rxbuf[14], rxbuf[15]);
            }
            
            if (parse_nav_pvt(rxbuf, sizeof(rxbuf), &pvt)) {
                // Check if this is a new measurement
                if (pvt.iTOW != last_tow) {
                    last_tow = pvt.iTOW;
                    pvt_count++;
                    
                    // Track fix rate timing
                    uint32_t current_time = k_uptime_get_32();
                    if (fix_rate_start_time == 0) {
                        fix_rate_start_time = current_time;
                        fix_count_in_period = 0;
                    }
                    
                    if (pvt.fixType >= 2) {
                        format_nav_pvt_json(&pvt);
                        fix_count_in_period++;
                        
                        // Log fix rate every 10 seconds
                        if (current_time - fix_rate_start_time >= 10000) {
                            float fix_rate = (float)fix_count_in_period / 10.0f;
                            LOG_INF("GNSS Fix Rate: %.1f Hz (%d fixes in 10s, total: %d)", 
                                    fix_rate, fix_count_in_period, pvt_count);
                            
                            // Reset for next period
                            fix_rate_start_time = current_time;
                            fix_count_in_period = 0;
                        }
                    } else {
                        LOG_INF("No fix yet (fixType: %d, satellites: %d)", pvt.fixType, pvt.numSV);
                    }
                    
                    // Log update rate every 10 seconds (keep your existing log)
                    if (pvt_count % 100 == 0) {
                        LOG_DBG("Received %d PVT messages", pvt_count);
                    }
                }
            }
        } else {
            if (read_count <= 5) {
                LOG_ERR("I2C read failed: %d", ret);
            }
        }
}