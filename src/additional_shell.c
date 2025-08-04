#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* GNSS Module Control - Based on Pinout Table */
static bool gnss_enabled = false;
static bool gnss_safe_boot = false;

/* GNSS Pin Definitions from Schematic Analysis */
#define GNSS_RST_PIN    12  /* P0.12 - GNSS_RST (pin 9 on MAX-M10S) */
#define GNSS_PPS_PIN    11  /* P0.11 - GNSS_PPS (pin 4 TIMEPULSE on MAX-M10S) */
#define GNSS_SAFE_PIN   15  /* P0.15 - GNSS_SAFE (pin 18 SAFEBOOT on MAX-M10S) */
#define GNSS_I2C_ADDR   0x42 /* u-blox default I2C address */
/* Note: GNSS power controlled by NPM1300 via VGNSS + 1V8_SW rails, not GPIO */

/* Basic hello command */
static int cmd_hello(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Hello! Kestrel board test application");
    shell_print(sh, "");
    shell_print(sh, "Available Commands:");
    shell_print(sh, "  gnss     - u-blox MAX M10S GNSS control");
    shell_print(sh, "  npm1300  - NPM1300 PMIC control (BUCK/LDSW/Charger/VBUS)");
    shell_print(sh, "  i2c      - I2C bus scanning");
    shell_print(sh, "");
    shell_print(sh, "Quick Start:");
    shell_print(sh, "  npm1300 test_i2c     # Test NPM1300 I2C connectivity");
    shell_print(sh, "  npm1300 scan_regs    # Scan all registers for non-zero values");
    shell_print(sh, "  npm1300 read 0x00    # Test register read with debug");
    shell_print(sh, "  npm1300 status       # Check PMIC status");
    shell_print(sh, "  gnss enable          # Initialize GNSS");
    shell_print(sh, "  gnss test 2 0x42     # Test GNSS communication");
    return 0;
}

/* I2C scan command */
static int cmd_i2c_scan(const struct shell *sh, size_t argc, char **argv)
{
    const struct device *i2c_dev;
    int i2c_instance = 2; // default to i2c2
    
    if (argc > 1) {
        i2c_instance = atoi(argv[1]);
    }
    
    switch (i2c_instance) {
        case 1:
            //i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
            shell_print(sh, "Scanning I2C1...");
            break;
        case 2:
            i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c2));
            shell_print(sh, "Scanning I2C2...");
            break;
        default:
            shell_error(sh, "Invalid I2C instance. Use 1 or 2");
            return -EINVAL;
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C device not ready");
        return -ENODEV;
    }
    
    shell_print(sh, "     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
    
    for (uint8_t i = 0; i < 128; i += 16) {
        shell_fprintf(sh, SHELL_NORMAL, "%02x: ", i);
        
        for (uint8_t j = 0; j < 16; j++) {
            uint8_t addr = i + j;
            
            if (addr < 0x08 || addr > 0x77) {
                shell_fprintf(sh, SHELL_NORMAL, "   ");
                continue;
            }
            
                            uint8_t dummy;
                int ret = i2c_read(i2c_dev, &dummy, 1, addr);
                
                if (ret == 0) {
                    shell_fprintf(sh, SHELL_NORMAL, "%02x ", addr);
                } else {
                    shell_fprintf(sh, SHELL_NORMAL, "-- ");
                }
        }
        shell_print(sh, "");
    }
    
    return 0;
}

/* GNSS GPIO Control Functions */
static int gnss_control_gpio(uint8_t pin, bool state, const char *name)
{
    const struct device *gpio_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
    
    if (!device_is_ready(gpio_dev)) {
        LOG_ERR("GPIO device not ready");
        return -ENODEV;
    }
    
    int ret = gpio_pin_configure(gpio_dev, pin, GPIO_OUTPUT_ACTIVE);
    if (ret != 0) {
        LOG_ERR("Failed to configure %s pin %d: %d", name, pin, ret);
        return ret;
    }
    
    ret = gpio_pin_set(gpio_dev, pin, state ? 1 : 0);
    if (ret == 0) {
        LOG_INF("%s (P0.%d) set %s", name, pin, state ? "HIGH" : "LOW");
    } else {
        LOG_ERR("Failed to set %s pin: %d", name, ret);
    }
    
    return ret;
}

static int gnss_read_gpio(uint8_t pin, const char *name)
{
    const struct device *gpio_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
    
    if (!device_is_ready(gpio_dev)) {
        return -ENODEV;
    }
    
    gpio_pin_configure(gpio_dev, pin, GPIO_INPUT);
    return gpio_pin_get(gpio_dev, pin);
}



/* GNSS Enable - Power rail controlled (no GPIO power control) */
static int cmd_gnss_enable(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Initializing u-blox MAX M10S GNSS module...");
    shell_print(sh, "Note: GNSS is power-rail controlled (VGNSS + 1V8_SW)");
    
    // Step 1: Ensure not in safe boot mode (normal operation)
    int ret = gnss_control_gpio(GNSS_SAFE_PIN, false, "GNSS_SAFE");
    if (ret != 0) {
        shell_error(sh, "Failed to configure safe boot pin");
        return ret;
    }
    shell_print(sh, "  GNSS_SAFE disabled (normal boot mode)");
    
    // Step 2: Reset sequence to initialize GNSS
    shell_print(sh, "  Performing GNSS reset sequence...");
    gnss_control_gpio(GNSS_RST_PIN, false, "GNSS_RST");  // Assert reset
    k_sleep(K_MSEC(100));
    gnss_control_gpio(GNSS_RST_PIN, true, "GNSS_RST");   // Release reset
    k_sleep(K_MSEC(2000));  // u-blox needs 1-2 seconds for startup
    shell_print(sh, "  GNSS reset and initialization completed");
    
    gnss_enabled = true;
    
    shell_print(sh, "  MAX M10S should now be responsive on I2C");
    shell_print(sh, "  Test with: gnss test 2 0x42");
    shell_print(sh, "  Monitor PPS with: gnss pps");
    shell_print(sh, "  Wait 30+ seconds for satellite acquisition");
    shell_print(sh, "");
    shell_print(sh, "Power Analysis:");
    shell_print(sh, "  - LNA_EN tied to VGNSS + 1V8_SW (always powered)");
    shell_print(sh, "  - Check NPM1300 power rail status if still not working");
    
    return 0;
}

static int cmd_gnss_disable(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Disabling external u-blox MAX M10S GNSS module...");
    
    // Put GNSS in reset state to reduce power
    int ret = gnss_control_gpio(GNSS_RST_PIN, false, "GNSS_RST");
    if (ret == 0) {
        shell_print(sh, "  GNSS held in reset (low power)");
        gnss_enabled = false;
        shell_print(sh, "  External GNSS module disabled");
    } else {
        shell_error(sh, "Failed to reset GNSS");
    }
    
    return ret;
}

/* GNSS Safe Boot Mode Control */
static int cmd_gnss_safe(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: gnss safe <on|off>");
        shell_print(sh, "Safe boot mode for GNSS firmware recovery");
        return -EINVAL;
    }
    
    bool safe_mode = (strcmp(argv[1], "on") == 0);
    
    shell_print(sh, "Setting GNSS safe boot mode: %s", safe_mode ? "ON" : "OFF");
    
    int ret = gnss_control_gpio(GNSS_SAFE_PIN, safe_mode, "GNSS_SAFE");
    if (ret == 0) {
        gnss_safe_boot = safe_mode;
        shell_print(sh, "  GNSS_SAFE (P0.15) set %s", safe_mode ? "HIGH" : "LOW");
        if (safe_mode) {
            shell_print(sh, "  WARNING: GNSS will boot in safe/recovery mode");
            shell_print(sh, "  Power cycle GNSS to activate safe mode");
        }
    } else {
        shell_error(sh, "Failed to set safe boot mode");
    }
    
    return ret;
}

/* GNSS PPS Monitor */
static int cmd_gnss_pps(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Monitoring GNSS PPS signal (P0.11) for 10 seconds...");
    shell_print(sh, "PPS = Pulse Per Second (indicates GPS fix)");
    shell_print(sh, "");
    
    int pps_count = 0;
    int last_state = gnss_read_gpio(GNSS_PPS_PIN, "GNSS_PPS");
    
    for (int i = 0; i < 1000; i++) {  // 10 seconds at 10ms intervals
        int current_state = gnss_read_gpio(GNSS_PPS_PIN, "GNSS_PPS");
        
        if (current_state == 1 && last_state == 0) {
            // Rising edge detected
            pps_count++;
            shell_print(sh, "PPS pulse %d detected at %d.%02ds", 
                       pps_count, i/100, (i%100)/10);
        }
        
        last_state = current_state;
        k_sleep(K_MSEC(10));
    }
    
    shell_print(sh, "");
    shell_print(sh, "PPS Monitor Results:");
    shell_print(sh, "  Total pulses: %d", pps_count);
    
    if (pps_count >= 8 && pps_count <= 12) {
        shell_print(sh, "  Normal PPS rate - GPS has fix!");
    } else if (pps_count > 0) {
        shell_print(sh, "  WARNING: Irregular PPS - GPS acquiring fix");
    } else {
        shell_print(sh, "  ERROR: No PPS detected - GPS no fix or disabled");
    }
    
    return 0;
}

/* GNSS Status - External u-blox MAX M10S */
static int cmd_gnss_status(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "External u-blox MAX M10S GNSS Status:");
    shell_print(sh, "");
    
    // Read GPIO states for external GNSS control
    int reset_state = gnss_read_gpio(GNSS_RST_PIN, "GNSS_RST");
    int pps_state = gnss_read_gpio(GNSS_PPS_PIN, "GNSS_PPS");
    int safe_state = gnss_read_gpio(GNSS_SAFE_PIN, "GNSS_SAFE");
    
    shell_print(sh, "External GNSS GPIO Status:");
    shell_print(sh, "  GNSS_RST (P0.12): %s", reset_state ? "HIGH (Normal)" : "LOW (Reset)");
    shell_print(sh, "  GNSS_PPS (P0.11): %s", pps_state ? "HIGH" : "LOW");
    shell_print(sh, "  GNSS_SAFE (P0.15): %s", safe_state ? "HIGH (Safe mode)" : "LOW (Normal)");
    
    shell_print(sh, "");
    shell_print(sh, "Software Status:");
    shell_print(sh, "  External GNSS: %s", gnss_enabled ? "Enabled" : "Disabled");
    shell_print(sh, "  Safe boot: %s", gnss_safe_boot ? "Enabled" : "Disabled");
    shell_print(sh, "  I2C Address: 0x42");
    shell_print(sh, "  Communication: I2C2");
    
    shell_print(sh, "");
    shell_print(sh, "Hardware Architecture:");
    shell_print(sh, "  Internal nRF9151 GNSS: COEX0 controlled");
    shell_print(sh, "  External u-blox MAX M10S: GPIO controlled");
    
    shell_print(sh, "");
    shell_print(sh, "External GNSS Pin Functions:");
    shell_print(sh, "  P0.12 (pin 72) -> GNSS reset control");
    shell_print(sh, "  P0.11 (pin 70) -> GNSS PPS time reference");
    shell_print(sh, "  P0.15 (pin 75) -> GNSS safe boot mode");
    
    shell_print(sh, "");
    shell_print(sh, "Power Analysis (from schematic):");
    shell_print(sh, "  GNSS LNA_EN -> VGNSS + 1V8_SW power rails");
    shell_print(sh, "  Power controlled by NPM1300 regulators (not GPIO)");
    shell_print(sh, "  VIO_SEL grounded -> I/O voltage level set");
    shell_print(sh, "  If GNSS not responding: check NPM1300 rail status");
    
    return 0;
}

/* GNSS I2C Scanner */
static int cmd_gnss_scan(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Scanning for u-blox MAX M10S on I2C buses...");
    
    const struct device *i2c_buses[] = {
       // DEVICE_DT_GET(DT_NODELABEL(i2c1)),
        DEVICE_DT_GET(DT_NODELABEL(i2c2))
    };
    const char *bus_names[] = {"I2C1", "I2C2"};
    uint8_t gnss_addrs[] = {0x42, 0x43, 0x44, 0x45};
    const char *addr_names[] = {"0x42 (default)", "0x43", "0x44", "0x45"};
    
    bool found = false;
    
    for (int bus = 0; bus < 2; bus++) {
        if (!device_is_ready(i2c_buses[bus])) {
            shell_warn(sh, "%s not ready", bus_names[bus]);
            continue;
        }
        
        shell_print(sh, "\nScanning %s:", bus_names[bus]);
        
        for (int addr_idx = 0; addr_idx < 4; addr_idx++) {
            uint8_t addr = gnss_addrs[addr_idx];
            uint8_t dummy;
            int ret = i2c_read(i2c_buses[bus], &dummy, 1, addr);
            
            if (ret == 0) {
                shell_print(sh, "  GNSS found at %s on %s", addr_names[addr_idx], bus_names[bus]);
                found = true;
                
                // Test consistency
                k_sleep(K_MSEC(10));
                ret = i2c_read(i2c_buses[bus], &dummy, 1, addr);
                if (ret == 0) {
                    shell_print(sh, "     Device responds consistently");
                    shell_print(sh, "     Use 'gnss test %d 0x%02x' to read data", bus + 1, addr);
                }
            } else if (ret == -EIO) {
                shell_print(sh, "  WARNING: Device detected at %s (not responding)", addr_names[addr_idx]);
                found = true;
            }
        }
    }
    
    if (!found) {
        shell_error(sh, "\nERROR: No GNSS found on I2C");
        shell_print(sh, "Troubleshooting:");
        shell_print(sh, "  1. Run 'gnss enable' first");
        shell_print(sh, "  2. Check 'gnss status' for power state");
        shell_print(sh, "  3. Wait 30+ seconds after enable");
        shell_print(sh, "  4. Try 'i2c scan 1' and 'i2c scan 2'");
    } else {
        shell_print(sh, "\nGNSS detection completed");
    }
    
    return 0;
}

/* GNSS I2C Data Test */
static int cmd_gnss_test(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(sh, "Usage: gnss test <bus> <addr>");
        shell_print(sh, "Example: gnss test 2 0x42");
        return -EINVAL;
    }
    
    int bus_num = atoi(argv[1]);
    uint8_t addr = strtol(argv[2], NULL, 0);
    
    const struct device *i2c_dev;
    if (bus_num == 1) {
        //i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    } else if (bus_num == 2) {
        i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c2));
    } else {
        shell_error(sh, "Invalid I2C bus. Use 1 or 2");
        return -EINVAL;
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C%d not ready", bus_num);
        return -ENODEV;
    }
    
    shell_print(sh, "Testing u-blox MAX M10S at I2C%d address 0x%02x", bus_num, addr);
    
    uint8_t test_data[32];
    int ret = i2c_read(i2c_dev, test_data, sizeof(test_data), addr);
    
    if (ret == 0) {
        shell_print(sh, "  I2C read successful (%d bytes)", sizeof(test_data));
        shell_print(sh, "  Data received:");
        shell_hexdump(sh, test_data, sizeof(test_data));
        
        // Look for NMEA or UBX patterns
        bool has_nmea = false;
        bool has_ubx = false;
        
        for (int i = 0; i < sizeof(test_data) - 1; i++) {
            if (test_data[i] == '$' && test_data[i+1] == 'G') {
                has_nmea = true;
            }
            if (test_data[i] == 0xB5 && test_data[i+1] == 0x62) {
                has_ubx = true;
            }
        }
        
        if (has_nmea) {
            shell_print(sh, "  NMEA sentences detected - GPS outputting text data");
        } else if (has_ubx) {
            shell_print(sh, "  UBX protocol detected - GPS outputting binary data");
        } else {
            shell_print(sh, "  INFO: No NMEA/UBX detected - GPS may be starting up");
        }
        
    } else if (ret == -EIO) {
        shell_warn(sh, "  WARNING: Device present but not responding");
        shell_print(sh, "  This can happen when GPS is acquiring satellites");
    } else {
        shell_error(sh, "  ERROR: I2C communication failed: %d", ret);
    }
    
    return 0;
}

/* GNSS I2C Data Reader */
static int cmd_gnss_read(const struct shell *sh, size_t argc, char **argv)
{
    const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c2));
    uint8_t addr = GNSS_I2C_ADDR;
    
    if (argc >= 2) {
        addr = strtol(argv[1], NULL, 0);
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    shell_print(sh, "Reading GNSS data from I2C2 address 0x%02x (10 seconds)...", addr);
    shell_print(sh, "Looking for NMEA sentences and UBX messages...");
    shell_print(sh, "");
    
    uint8_t buffer[64];
    int total_reads = 0;
    int successful_reads = 0;
    int nmea_count = 0;
    
    for (int i = 0; i < 100; i++) {  // 10 seconds
        int ret = i2c_read(i2c_dev, buffer, sizeof(buffer), addr);
        total_reads++;
        
        if (ret == 0) {
            successful_reads++;
            
            // Look for NMEA sentences
            for (int j = 0; j < sizeof(buffer) - 6; j++) {
                if (buffer[j] == '$' && buffer[j+1] == 'G') {
                    nmea_count++;
                    
                    // Try to extract NMEA sentence
                    char nmea[32] = {0};
                    int len = 0;
                    for (int k = j; k < sizeof(buffer) && k < j + 31; k++) {
                        if (buffer[k] == '\r' || buffer[k] == '\n') break;
                        if (buffer[k] >= 0x20 && buffer[k] <= 0x7E) {
                            nmea[len++] = buffer[k];
                        }
                    }
                    
                    if (len > 6) {
                        shell_print(sh, "NMEA: %s", nmea);
                    }
                    break;
                }
            }
        }
        
        k_sleep(K_MSEC(100));
    }
    
    shell_print(sh, "");
    shell_print(sh, "GNSS I2C Read Summary:");
    shell_print(sh, "  Total read attempts: %d", total_reads);
    shell_print(sh, "  Successful reads: %d", successful_reads);
    shell_print(sh, "  NMEA sentences found: %d", nmea_count);
    
    if (successful_reads == 0) {
        shell_error(sh, "  ERROR: No I2C communication");
        shell_print(sh, "  Check: GPS enabled, correct address, I2C bus");
    } else if (nmea_count == 0) {
        shell_warn(sh, "  WARNING: I2C works but no NMEA data");
        shell_print(sh, "  GPS may be acquiring satellites (wait longer)");
    } else {
        shell_print(sh, "  GNSS I2C communication working!");
    }
    
    return 0;
}

/* Generic I2C Read Command */
static int cmd_i2c_read(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 4) {
        shell_error(sh, "Usage: i2c read <bus> <addr> <reg>");
        shell_print(sh, "  bus: 1 or 2 (I2C bus number)");
        shell_print(sh, "  addr: I2C device address (hex, e.g., 0x6b)");
        shell_print(sh, "  reg: Register address (hex, e.g., 0x00)");
        return -EINVAL;
    }
    
    uint8_t bus = strtol(argv[1], NULL, 10);
    uint8_t addr = strtol(argv[2], NULL, 16);
    uint8_t reg = strtol(argv[3], NULL, 16);
    
    if (bus != 1 && bus != 2) {
        shell_error(sh, "Bus must be 1 or 2");
        return -EINVAL;
    }
    
    const struct device *i2c_dev;
    if (bus == 1) {
       // i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    } else {
        i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c2));
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C%d not ready", bus);
        return -ENODEV;
    }
    
    uint8_t data;
    int ret = i2c_reg_read_byte(i2c_dev, addr, reg, &data);
    
    if (ret == 0) {
        shell_print(sh, "I2C%d[0x%02x] reg 0x%02x = 0x%02x", bus, addr, reg, data);
    } else {
        shell_error(sh, "I2C%d[0x%02x] reg 0x%02x read failed: %d", bus, addr, reg, ret);
    }
    
    return ret;
}

/* Generic I2C Write Command */
static int cmd_i2c_write(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 5) {
        shell_error(sh, "Usage: i2c write <bus> <addr> <reg> <value>");
        shell_print(sh, "  bus: 1 or 2 (I2C bus number)");
        shell_print(sh, "  addr: I2C device address (hex, e.g., 0x6b)");
        shell_print(sh, "  reg: Register address (hex, e.g., 0x00)");
        shell_print(sh, "  value: Value to write (hex, e.g., 0xff)");
        return -EINVAL;
    }
    
    uint8_t bus = strtol(argv[1], NULL, 10);
    uint8_t addr = strtol(argv[2], NULL, 16);
    uint8_t reg = strtol(argv[3], NULL, 16);
    uint8_t value = strtol(argv[4], NULL, 16);
    
    if (bus != 1 && bus != 2) {
        shell_error(sh, "Bus must be 1 or 2");
        return -EINVAL;
    }
    
    const struct device *i2c_dev;
    if (bus == 1) {
       // i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1)); 
    } else {
        i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c2));
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C%d not ready", bus);
        return -ENODEV;
    }
    
    shell_print(sh, "Writing I2C%d[0x%02x] reg 0x%02x = 0x%02x", bus, addr, reg, value);
    
    int ret = i2c_reg_write_byte(i2c_dev, addr, reg, value);
    
    if (ret == 0) {
        shell_print(sh, "Write successful");
        
        // Read back to verify (optional)
        uint8_t readback;
        ret = i2c_reg_read_byte(i2c_dev, addr, reg, &readback);
        if (ret == 0) {
            shell_print(sh, "Readback: 0x%02x %s", readback, 
                       (readback == value) ? "(matches)" : "(WARNING: different!)");
        }
    } else {
        shell_error(sh, "ERROR: Write failed: %d", ret);
    }
    
    return ret;
}

/* I2C Device Probe */
static int cmd_i2c_probe(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 3) {
        shell_error(sh, "Usage: i2c probe <bus> <addr>");
        shell_print(sh, "  bus: 1 or 2 (I2C bus number)");
        shell_print(sh, "  addr: I2C device address (hex, e.g., 0x6b)");
        return -EINVAL;
    }
    
    uint8_t bus = strtol(argv[1], NULL, 10);
    uint8_t addr = strtol(argv[2], NULL, 16);
    
    if (bus != 1 && bus != 2) {
        shell_error(sh, "Bus must be 1 or 2");
        return -EINVAL;
    }
    
    const struct device *i2c_dev;
    if (bus == 1) {
        //i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    } else {
        i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c2));
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C%d not ready", bus);
        return -ENODEV;
    }
    
    shell_print(sh, "Probing I2C%d address 0x%02x...", bus, addr);
    
    // Try to read a few common registers
    uint8_t test_regs[] = {0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF};
    bool device_responds = false;
    
    for (int i = 0; i < 6; i++) {
        uint8_t reg = test_regs[i];
        uint8_t data;
        int ret = i2c_reg_read_byte(i2c_dev, addr, reg, &data);
        
        if (ret == 0) {
            shell_print(sh, "  Reg 0x%02x = 0x%02x", reg, data);
            device_responds = true;
        } else {
            shell_print(sh, "  Reg 0x%02x = no response", reg);
        }
    }
    
    if (device_responds) {
        shell_print(sh, "Device at 0x%02x responds", addr);
    } else {
        shell_print(sh, "ERROR: No response from device at 0x%02x", addr);
    }
    
    return 0;
}

/* Shell command definitions */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_i2c,
    SHELL_CMD(scan, NULL, "Scan I2C bus. Usage: i2c scan [1|2]", cmd_i2c_scan),
    SHELL_CMD(read, NULL, "Read I2C register. Usage: i2c read <bus> <addr> <reg>", cmd_i2c_read),
    SHELL_CMD(write, NULL, "Write I2C register. Usage: i2c write <bus> <addr> <reg> <value>", cmd_i2c_write),
    SHELL_CMD(probe, NULL, "Probe I2C device. Usage: i2c probe <bus> <addr>", cmd_i2c_probe),
    SHELL_SUBCMD_SET_END
);




/* ========================================================================
 * NPM1300 PMIC Control Interface
 * ======================================================================== */

#define NPM1300_I2C_ADDR    0x6b
#define NPM1300_I2C_BUS     DEVICE_DT_GET(DT_NODELABEL(i2c2))

/* NPM1300 Register Access Helper */
static int npm1300_reg_read(uint8_t reg, uint8_t *data)
{
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    
    if (!device_is_ready(i2c_dev)) {
        return -ENODEV;
    }
    
    return i2c_reg_read_byte(i2c_dev, NPM1300_I2C_ADDR, reg, data);
}

static int npm1300_reg_write(uint8_t reg, uint8_t data)
{
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    
    if (!device_is_ready(i2c_dev)) {
        return -ENODEV;
    }
    
    return i2c_reg_write_byte(i2c_dev, NPM1300_I2C_ADDR, reg, data);
}

/* NPM1300 Generic Register Read/Write with multiple access methods */
static int cmd_npm1300_read(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 read <reg>");
        shell_print(sh, "Example: npm1300 read 0x03");
        return -EINVAL;
    }
    
    uint8_t reg = strtol(argv[1], NULL, 0);
    uint8_t data;
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    shell_print(sh, "Reading NPM1300 register 0x%02x using multiple methods:", reg);
    
    // Method 1: Standard register read (what we were using)
    int ret1 = i2c_reg_read_byte(i2c_dev, NPM1300_I2C_ADDR, reg, &data);
    shell_print(sh, "Method 1 (reg_read_byte): %s, data=0x%02x", 
               ret1 == 0 ? "SUCCESS" : "FAILED", ret1 == 0 ? data : 0);
    
    // Method 2: Write register address, then read data
    uint8_t data2;
    int ret2a = i2c_write(i2c_dev, &reg, 1, NPM1300_I2C_ADDR);
    int ret2b = i2c_read(i2c_dev, &data2, 1, NPM1300_I2C_ADDR);
    shell_print(sh, "Method 2 (write+read): write=%s, read=%s, data=0x%02x", 
               ret2a == 0 ? "OK" : "FAIL", ret2b == 0 ? "OK" : "FAIL", 
               (ret2a == 0 && ret2b == 0) ? data2 : 0);
    
    // Method 3: Combined write/read transaction
    uint8_t data3;
    struct i2c_msg msgs[2];
    msgs[0].buf = &reg;
    msgs[0].len = 1;
    msgs[0].flags = I2C_MSG_WRITE;
    msgs[1].buf = &data3;
    msgs[1].len = 1;
    msgs[1].flags = I2C_MSG_READ | I2C_MSG_STOP;
    
    int ret3 = i2c_transfer(i2c_dev, msgs, 2, NPM1300_I2C_ADDR);
    shell_print(sh, "Method 3 (i2c_transfer): %s, data=0x%02x", 
               ret3 == 0 ? "SUCCESS" : "FAILED", ret3 == 0 ? data3 : 0);
    
    // Method 4: Try without register address (direct read)
    uint8_t data4;
    int ret4 = i2c_read(i2c_dev, &data4, 1, NPM1300_I2C_ADDR);
    shell_print(sh, "Method 4 (direct_read): %s, data=0x%02x", 
               ret4 == 0 ? "SUCCESS" : "FAILED", ret4 == 0 ? data4 : 0);
    
    // Show which methods worked
    if (ret1 == 0) {
        shell_print(sh, "Standard method works: NPM1300[0x%02x] = 0x%02x", reg, data);
        return 0;
    } else if (ret2a == 0 && ret2b == 0) {
        shell_print(sh, "Write+Read method works: NPM1300[0x%02x] = 0x%02x", reg, data2);
        return 0;
    } else if (ret3 == 0) {
        shell_print(sh, "Transfer method works: NPM1300[0x%02x] = 0x%02x", reg, data3);
        return 0;
    } else {
        shell_error(sh, "All NPM1300 read methods failed");
        return -EIO;
    }
}

static int cmd_npm1300_write(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(sh, "Usage: npm1300 write <reg> <value>");
        shell_print(sh, "Example: npm1300 write 0x00 0x01");
        return -EINVAL;
    }
    
    uint8_t reg = strtol(argv[1], NULL, 0);
    uint8_t value = strtol(argv[2], NULL, 0);
    
    int ret = npm1300_reg_write(reg, value);
    if (ret == 0) {
        shell_print(sh, "NPM1300[0x%02x] = 0x%02x (written)", reg, value);
    } else {
        shell_error(sh, "NPM1300 write failed: %d", ret);
    }
    
    return ret;
}

/* NPM1300 BUCK Regulator Control */
static int cmd_npm1300_buck_enable(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 buck enable <1|2>");
        return -EINVAL;
    }
    
    int buck_num = atoi(argv[1]);
    if (buck_num < 1 || buck_num > 2) {
        shell_error(sh, "Invalid BUCK number. Use 1 or 2");
        return -EINVAL;
    }
    
    uint8_t enable_reg = (buck_num == 1) ? 0x00 : 0x02;  // BUCK1ENASET/BUCK2ENASET
    
    shell_print(sh, "Enabling BUCK%d regulator...", buck_num);
    
    int ret = npm1300_reg_write(enable_reg, 0x01);
    if (ret == 0) {
        shell_print(sh, "  BUCK%d enable pulse sent", buck_num);
        
        // Read status
        uint8_t status;
        ret = npm1300_reg_read(0x34, &status);  // BUCKSTATUS
        if (ret == 0) {
            shell_print(sh, "  BUCK Status: 0x%02x", status);
        }
    } else {
        shell_error(sh, "  ERROR: BUCK%d enable failed: %d", buck_num, ret);
    }
    
    return ret;
}

static int cmd_npm1300_buck_disable(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 buck disable <1|2>");
        return -EINVAL;
    }
    
    int buck_num = atoi(argv[1]);
    if (buck_num < 1 || buck_num > 2) {
        shell_error(sh, "Invalid BUCK number. Use 1 or 2");
        return -EINVAL;
    }
    
    uint8_t disable_reg = (buck_num == 1) ? 0x01 : 0x03;  // BUCK1ENACLR/BUCK2ENACLR
    
    shell_print(sh, "Disabling BUCK%d regulator...", buck_num);
    
    int ret = npm1300_reg_write(disable_reg, 0x01);
    if (ret == 0) {
        shell_print(sh, "  BUCK%d disable pulse sent", buck_num);
    } else {
        shell_error(sh, "  ERROR: BUCK%d disable failed: %d", buck_num, ret);
    }
    
    return ret;
}

static int cmd_npm1300_buck_voltage(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(sh, "Usage: npm1300 buck voltage <1|2> <voltage_code>");
        shell_print(sh, "Voltage codes: consult NPM1300 datasheet");
        return -EINVAL;
    }
    
    int buck_num = atoi(argv[1]);
    uint8_t voltage_code = strtol(argv[2], NULL, 0);
    
    if (buck_num < 1 || buck_num > 2) {
        shell_error(sh, "Invalid BUCK number. Use 1 or 2");
        return -EINVAL;
    }
    
    uint8_t voltage_reg = (buck_num == 1) ? 0x08 : 0x0A;  // BUCK1NORMVOUT/BUCK2NORMVOUT
    
    shell_print(sh, "Setting BUCK%d voltage to 0x%02x...", buck_num, voltage_code);
    
    int ret = npm1300_reg_write(voltage_reg, voltage_code);
    if (ret == 0) {
        shell_print(sh, "  BUCK%d voltage set to 0x%02x", buck_num, voltage_code);
    } else {
        shell_error(sh, "  ERROR: BUCK%d voltage set failed: %d", buck_num, ret);
    }
    
    return ret;
}

static int cmd_npm1300_buck_status(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 BUCK Regulator Status:");
    shell_print(sh, "");
    
    // Read BUCK status register
    uint8_t buck_status;
    int ret = npm1300_reg_read(0x34, &buck_status);
    if (ret == 0) {
        shell_print(sh, "  BUCK Status (0x34): 0x%02x", buck_status);
    } else {
        shell_error(sh, "  BUCK Status read failed: %d", ret);
        return ret;
    }
    
    // Read individual BUCK voltage status
    uint8_t buck1_vout, buck2_vout;
    ret = npm1300_reg_read(0x10, &buck1_vout);  // BUCK1VOUTSTATUS
    if (ret == 0) {
        shell_print(sh, "  BUCK1 VOUT Status (0x10): 0x%02x", buck1_vout);
    }
    
    ret = npm1300_reg_read(0x11, &buck2_vout);  // BUCK2VOUTSTATUS
    if (ret == 0) {
        shell_print(sh, "  BUCK2 VOUT Status (0x11): 0x%02x", buck2_vout);
    }
    
    shell_print(sh, "");
    shell_print(sh, "Register Map:");
    shell_print(sh, "  0x00: BUCK1 Enable Set    0x01: BUCK1 Enable Clear");
    shell_print(sh, "  0x02: BUCK2 Enable Set    0x03: BUCK2 Enable Clear");
    shell_print(sh, "  0x08: BUCK1 Normal Vout   0x0A: BUCK2 Normal Vout");
    shell_print(sh, "  0x34: BUCK Status");
    
    return 0;
}

/* NPM1300 Load Switch (LDSW) Control */
static int cmd_npm1300_ldsw_enable(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 ldsw enable <1|2>");
        return -EINVAL;
    }
    
    int ldsw_num = atoi(argv[1]);
    if (ldsw_num < 1 || ldsw_num > 2) {
        shell_error(sh, "Invalid LDSW number. Use 1 or 2");
        return -EINVAL;
    }
    
    uint8_t enable_reg = (ldsw_num == 1) ? 0x00 : 0x02;  // TASKLDSW1SET/TASKLDSW2SET
    
    shell_print(sh, "Enabling LDSW%d (Load Switch %d)...", ldsw_num, ldsw_num);
    
    int ret = npm1300_reg_write(enable_reg, 0x01);
    if (ret == 0) {
        shell_print(sh, "  LDSW%d enable pulse sent", ldsw_num);
        
        // Read status
        uint8_t status;
        ret = npm1300_reg_read(0x04, &status);  // LDSWSTATUS
        if (ret == 0) {
            shell_print(sh, "  LDSW Status: 0x%02x", status);
        }
    } else {
        shell_error(sh, "  ERROR: LDSW%d enable failed: %d", ldsw_num, ret);
    }
    
    return ret;
}

static int cmd_npm1300_ldsw_disable(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 ldsw disable <1|2>");
        return -EINVAL;
    }
    
    int ldsw_num = atoi(argv[1]);
    if (ldsw_num < 1 || ldsw_num > 2) {
        shell_error(sh, "Invalid LDSW number. Use 1 or 2");
        return -EINVAL;
    }
    
    uint8_t disable_reg = (ldsw_num == 1) ? 0x01 : 0x03;  // TASKLDSW1CLR/TASKLDSW2CLR
    
    shell_print(sh, "Disabling LDSW%d (Load Switch %d)...", ldsw_num, ldsw_num);
    
    int ret = npm1300_reg_write(disable_reg, 0x01);
    if (ret == 0) {
        shell_print(sh, "  LDSW%d disable pulse sent", ldsw_num);
    } else {
        shell_error(sh, "  ERROR: LDSW%d disable failed: %d", ldsw_num, ret);
    }
    
    return ret;
}

static int cmd_npm1300_ldsw_voltage(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(sh, "Usage: npm1300 ldsw voltage <1|2> <voltage_code>");
        shell_print(sh, "Voltage codes: consult NPM1300 datasheet");
        return -EINVAL;
    }
    
    int ldsw_num = atoi(argv[1]);
    uint8_t voltage_code = strtol(argv[2], NULL, 0);
    
    if (ldsw_num < 1 || ldsw_num > 2) {
        shell_error(sh, "Invalid LDSW number. Use 1 or 2");
        return -EINVAL;
    }
    
    uint8_t voltage_reg = (ldsw_num == 1) ? 0x0C : 0x0D;  // LDSW1VOUTSEL/LDSW2VOUTSEL
    
    shell_print(sh, "Setting LDSW%d voltage to 0x%02x...", ldsw_num, voltage_code);
    
    int ret = npm1300_reg_write(voltage_reg, voltage_code);
    if (ret == 0) {
        shell_print(sh, "  LDSW%d voltage set to 0x%02x", ldsw_num, voltage_code);
    } else {
        shell_error(sh, "  ERROR: LDSW%d voltage set failed: %d", ldsw_num, ret);
    }
    
    return ret;
}

static int cmd_npm1300_ldsw_status(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Load Switch (LDSW) Status:");
    shell_print(sh, "");
    
    // Read LDSW status register
    uint8_t ldsw_status;
    int ret = npm1300_reg_read(0x04, &ldsw_status);
    if (ret == 0) {
        shell_print(sh, "  LDSW Status (0x04): 0x%02x", ldsw_status);
        shell_print(sh, "    Bit 0: LDSW1 %s", (ldsw_status & 0x01) ? "ON" : "OFF");
        shell_print(sh, "    Bit 1: LDSW2 %s", (ldsw_status & 0x02) ? "ON" : "OFF");
    } else {
        shell_error(sh, "  LDSW Status read failed: %d", ret);
        return ret;
    }
    
    // Read configuration registers
    uint8_t ldsw_config;
    ret = npm1300_reg_read(0x07, &ldsw_config);
    if (ret == 0) {
        shell_print(sh, "  LDSW Config (0x07): 0x%02x", ldsw_config);
    }
    
    // Read LDO mode selections
    uint8_t ldsw1_ldosel, ldsw2_ldosel;
    ret = npm1300_reg_read(0x08, &ldsw1_ldosel);
    if (ret == 0) {
        shell_print(sh, "  LDSW1 LDO Select (0x08): 0x%02x", ldsw1_ldosel);
    }
    
    ret = npm1300_reg_read(0x09, &ldsw2_ldosel);
    if (ret == 0) {
        shell_print(sh, "  LDSW2 LDO Select (0x09): 0x%02x", ldsw2_ldosel);
    }
    
    // Read voltage settings
    uint8_t ldsw1_vout, ldsw2_vout;
    ret = npm1300_reg_read(0x0C, &ldsw1_vout);
    if (ret == 0) {
        shell_print(sh, "  LDSW1 VOUT (0x0C): 0x%02x", ldsw1_vout);
    }
    
    ret = npm1300_reg_read(0x0D, &ldsw2_vout);
    if (ret == 0) {
        shell_print(sh, "  LDSW2 VOUT (0x0D): 0x%02x", ldsw2_vout);
    }
    
    shell_print(sh, "");
    shell_print(sh, "Load Switch Functions:");
    shell_print(sh, "  LDSW1: Programmable load switch/LDO");
    shell_print(sh, "  LDSW2: Sensor power (boot-on in device tree)");
    shell_print(sh, "  Note: LDSW2 likely powers GNSS module");
    
    shell_print(sh, "");
    shell_print(sh, "Register Map:");
    shell_print(sh, "  0x00: LDSW1 Enable    0x01: LDSW1 Disable");
    shell_print(sh, "  0x02: LDSW2 Enable    0x03: LDSW2 Disable");
    shell_print(sh, "  0x0C: LDSW1 Voltage   0x0D: LDSW2 Voltage");
    
    return 0;
}

/* NPM1300 Charger Control */
static int cmd_npm1300_charger_enable(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Enabling NPM1300 battery charger...");
    
    int ret = npm1300_reg_write(0x04, 0x01);  // BCHGENABLESET
    if (ret == 0) {
        shell_print(sh, "  Charger enable pulse sent");
        
        // Read charger status
        uint8_t status;
        ret = npm1300_reg_read(0x34, &status);  // BCHGCHARGESTATUS
        if (ret == 0) {
            shell_print(sh, "  Charger Status: 0x%02x", status);
        }
    } else {
        shell_error(sh, "  ERROR: Charger enable failed: %d", ret);
    }
    
    return ret;
}

static int cmd_npm1300_charger_disable(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Disabling NPM1300 battery charger...");
    
    int ret = npm1300_reg_write(0x05, 0x01);  // BCHGENABLECLR
    if (ret == 0) {
        shell_print(sh, "  Charger disable pulse sent");
    } else {
        shell_error(sh, "  ERROR: Charger disable failed: %d", ret);
    }
    
    return ret;
}

static int cmd_npm1300_charger_status(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Charger Status:");
    shell_print(sh, "");
    
    struct {
        uint8_t reg;
        const char *name;
    } charger_regs[] = {
        {0x34, "Charge Status"},
        {0x36, "Error Reason"},
        {0x37, "Error Sensor"},
        {0x32, "NTC Status"},
        {0x33, "Die Temp Status"},
        {0x2D, "Current Limit Status"},
    };
    
    for (int i = 0; i < 6; i++) {
        uint8_t data;
        int ret = npm1300_reg_read(charger_regs[i].reg, &data);
        if (ret == 0) {
            shell_print(sh, "  %s (0x%02x): 0x%02x", charger_regs[i].name, charger_regs[i].reg, data);
        } else {
            shell_error(sh, "  %s read failed: %d", charger_regs[i].name, ret);
        }
    }
    
    return 0;
}

/* NPM1300 VBUSIN (USB Input) Control */
static int cmd_npm1300_vbusin_limit(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 vbusin limit <current_code>");
        shell_print(sh, "Current codes: consult NPM1300 datasheet");
        return -EINVAL;
    }
    
    uint8_t current_code = strtol(argv[1], NULL, 0);
    
    shell_print(sh, "Setting VBUS input current limit to 0x%02x...", current_code);
    
    // Write to VBUSINILIM0 register
    int ret = npm1300_reg_write(0x01, current_code);
    if (ret == 0) {
        shell_print(sh, "  VBUS current limit set to 0x%02x", current_code);
        
        // Trigger update
        ret = npm1300_reg_write(0x00, 0x01);  // TASKUPDATEILIMSW
        if (ret == 0) {
            shell_print(sh, "  Current limit update triggered");
        }
    } else {
        shell_error(sh, "  ERROR: VBUS current limit set failed: %d", ret);
    }
    
    return ret;
}

static int cmd_npm1300_vbusin_suspend(const struct shell *sh, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(sh, "Usage: npm1300 vbusin suspend <on|off>");
        return -EINVAL;
    }
    
    bool suspend_on = (strcmp(argv[1], "on") == 0);
    uint8_t suspend_val = suspend_on ? 0x01 : 0x00;
    
    shell_print(sh, "%s VBUS suspend mode...", suspend_on ? "Enabling" : "Disabling");
    
    int ret = npm1300_reg_write(0x03, suspend_val);  // VBUSSUSPEND
    if (ret == 0) {
        shell_print(sh, "  VBUS suspend mode %s", suspend_on ? "enabled" : "disabled");
    } else {
        shell_error(sh, "  ERROR: VBUS suspend control failed: %d", ret);
    }
    
    return ret;
}

static int cmd_npm1300_vbusin_status(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 VBUSIN (USB Input) Status:");
    shell_print(sh, "");
    
    // Read VBUS status registers
    uint8_t vbus_status;
    int ret = npm1300_reg_read(0x07, &vbus_status);
    if (ret == 0) {
        shell_print(sh, "  VBUS Status (0x07): 0x%02x", vbus_status);
        shell_print(sh, "    VBUS Present: %s", (vbus_status & 0x01) ? "YES" : "NO");
        shell_print(sh, "    VBUS Valid: %s", (vbus_status & 0x02) ? "YES" : "NO");
    } else {
        shell_error(sh, "  VBUS Status read failed: %d", ret);
    }
    
    // Read USB detection status
    uint8_t usb_detect;
    ret = npm1300_reg_read(0x05, &usb_detect);
    if (ret == 0) {
        shell_print(sh, "  USB Detect (0x05): 0x%02x", usb_detect);
    }
    
    // Read current limit settings
    uint8_t current_limit, startup_limit, suspend_mode;
    ret = npm1300_reg_read(0x01, &current_limit);
    if (ret == 0) {
        shell_print(sh, "  Current Limit (0x01): 0x%02x", current_limit);
    }
    
    ret = npm1300_reg_read(0x02, &startup_limit);
    if (ret == 0) {
        shell_print(sh, "  Startup Limit (0x02): 0x%02x", startup_limit);
    }
    
    ret = npm1300_reg_read(0x03, &suspend_mode);
    if (ret == 0) {
        shell_print(sh, "  Suspend Mode (0x03): 0x%02x (%s)", suspend_mode, 
                   suspend_mode ? "ENABLED" : "DISABLED");
    }
    
    shell_print(sh, "");
    shell_print(sh, "VBUS Input Functions:");
    shell_print(sh, "  - USB/Charger input current limiting");
    shell_print(sh, "  - USB detection and enumeration");
    shell_print(sh, "  - Power source management");
    
    shell_print(sh, "");
    shell_print(sh, "Register Map:");
    shell_print(sh, "  0x00: Update Current Limit  0x01: Current Limit");
    shell_print(sh, "  0x02: Startup Limit         0x03: Suspend Mode");
    shell_print(sh, "  0x05: USB Detect Status     0x07: VBUS Status");
    
    return 0;
}

/* NPM1300 System Status with Debugging */
static int cmd_npm1300_status(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 System Status (with I2C debugging):");
    shell_print(sh, "");
    
    // First test basic I2C connectivity
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "ERROR: I2C2 device not ready!");
        return -ENODEV;
    }
    shell_print(sh, "I2C2 device ready");
    
    // Test if NPM1300 responds at all
    uint8_t test_data;
    int ret = i2c_reg_read_byte(i2c_dev, NPM1300_I2C_ADDR, 0x00, &test_data);
    if (ret != 0) {
        shell_error(sh, "ERROR: NPM1300 not responding at 0x6b: %d", ret);
        shell_print(sh, "   Possible issues:");
        shell_print(sh, "   - NPM1300 not powered");
        shell_print(sh, "   - I2C address incorrect");
        shell_print(sh, "   - I2C bus issue");
        return ret;
    }
    shell_print(sh, "NPM1300 responds on I2C");
    
    struct {
        uint8_t reg;
        const char *name;
        const char *expected;
    } system_regs[] = {
        {0x00, "Product ID", "Should be non-zero (chip ID)"},
        {0x01, "Revision", "Should be non-zero (chip revision)"},
        {0x03, "System Status", "0x00 = no errors"},
        {0x04, "Charger Status", "0x00 = no charging activity"},
        {0x05, "Battery Status", "0x00 = no battery issues"},
        {0x06, "Buck Status", "0x00 = regulators off"},
        {0x07, "LDO Status", "0x00 = LDOs off"},
    };
    
    bool all_zero = true;
    for (int i = 0; i < 7; i++) {
        uint8_t data;
        ret = npm1300_reg_read(system_regs[i].reg, &data);
        if (ret == 0) {
            shell_print(sh, "  %s (0x%02x): 0x%02x - %s", 
                       system_regs[i].name, system_regs[i].reg, data, system_regs[i].expected);
            if (data != 0x00) all_zero = false;
        } else {
            shell_error(sh, "  %s read failed: %d", system_regs[i].name, ret);
        }
    }
    
    shell_print(sh, "");
    if (all_zero) {
        shell_warn(sh, "WARNING: All registers read 0x00 - This suggests:");
        shell_print(sh, "   1. NPM1300 in reset/default state");
        shell_print(sh, "   2. No power management activity");
        shell_print(sh, "   3. Regulators not initialized");
        shell_print(sh, "");
        shell_print(sh, "Try:");
        shell_print(sh, "   npm1300 debug     # Advanced debugging");
        shell_print(sh, "   npm1300 init      # Initialize NPM1300");
    } else {
        shell_print(sh, "NPM1300 appears to be active");
    }
    
    return 0;
}

/* NPM1300 Debug and Initialization */
static int cmd_npm1300_debug(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Advanced Debugging:");
    shell_print(sh, "");
    
    // Test multiple register ranges to see if addressing is correct
    shell_print(sh, "Testing register ranges...");
    
    uint8_t ranges[][3] = {
        {0x00, 0x0F, 0},  // System registers
        {0x10, 0x1F, 0},  // Status registers  
        {0x20, 0x2F, 0},  // Control registers
        {0x30, 0x3F, 0},  // More status
    };
    
    for (int range = 0; range < 4; range++) {
        uint8_t start = ranges[range][0];
        uint8_t end = ranges[range][1];
        bool found_nonzero = false;
        
        for (uint8_t reg = start; reg <= end; reg++) {
            uint8_t data;
            int ret = npm1300_reg_read(reg, &data);
            if (ret == 0 && data != 0x00) {
                if (!found_nonzero) {
                    shell_print(sh, "  Range 0x%02x-0x%02x:", start, end);
                    found_nonzero = true;
                }
                shell_print(sh, "    0x%02x = 0x%02x", reg, data);
            }
        }
        
        if (!found_nonzero) {
            shell_print(sh, "  Range 0x%02x-0x%02x: All zeros", start, end);
        }
    }
    
    shell_print(sh, "");
    shell_print(sh, "I2C Communication Test:");
    
    // Test raw I2C read/write
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    uint8_t test_data;
    
    // Try reading register 0x00 multiple times
    for (int i = 0; i < 3; i++) {
        int ret = i2c_reg_read_byte(i2c_dev, NPM1300_I2C_ADDR, 0x00, &test_data);
        shell_print(sh, "  Read attempt %d: ret=%d, data=0x%02x", i+1, ret, test_data);
        k_sleep(K_MSEC(10));
    }
    
    return 0;
}

/* NPM1300 I2C Address and Hardware Test */
static int cmd_npm1300_probe(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 I2C Address and Hardware Probe:");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    // Test multiple I2C addresses around 0x6b
    uint8_t test_addresses[] = {0x6a, 0x6b, 0x6c, 0x6d, 0x70, 0x71};
    const char *addr_names[] = {"0x6a", "0x6b (current)", "0x6c", "0x6d", "0x70", "0x71"};
    
    shell_print(sh, "Testing I2C addresses for NPM1300-like devices...");
    for (int i = 0; i < 6; i++) {
        uint8_t addr = test_addresses[i];
        uint8_t product_id, revision;
        
        int ret1 = i2c_reg_read_byte(i2c_dev, addr, 0x00, &product_id);
        int ret2 = i2c_reg_read_byte(i2c_dev, addr, 0x01, &revision);
        
        shell_print(sh, "  %s: ", addr_names[i]);
        
        if (ret1 == 0 && ret2 == 0) {
            shell_print(sh, "    Responds: ProductID=0x%02x, Revision=0x%02x", product_id, revision);
            
            if (product_id != 0x00 || revision != 0x00) {
                shell_print(sh, "    STAR: This address has non-zero ID registers!");
            }
        } else {
            shell_print(sh, "    No response (ret1=%d, ret2=%d)", ret1, ret2);
        }
    }
    
    shell_print(sh, "");
    shell_print(sh, "Testing write/read back on current address (0x6b)...");
    
    // Try writing to a safe register and reading it back
    uint8_t test_reg = 0x03;  // System status - usually safe to write
    uint8_t original_val, test_val = 0x55;
    
    // Read original value
    int ret = i2c_reg_read_byte(i2c_dev, 0x6b, test_reg, &original_val);
    if (ret == 0) {
        shell_print(sh, "  Original value at 0x%02x: 0x%02x", test_reg, original_val);
        
        // Try writing a test pattern
        ret = i2c_reg_write_byte(i2c_dev, 0x6b, test_reg, test_val);
        if (ret == 0) {
            shell_print(sh, "  Write successful: 0x%02x -> 0x%02x", test_val, test_reg);
            
            // Read back
            uint8_t readback_val;
            ret = i2c_reg_read_byte(i2c_dev, 0x6b, test_reg, &readback_val);
            if (ret == 0) {
                shell_print(sh, "  Read back: 0x%02x", readback_val);
                
                if (readback_val == test_val) {
                    shell_print(sh, "  Write/read works - device is real");
                } else if (readback_val == original_val) {
                    shell_print(sh, "  WARNING: Write ignored - register may be read-only");
                } else {
                    shell_print(sh, "  QUESTION: Unexpected value - device behavior unclear");
                }
                
                // Restore original value
                i2c_reg_write_byte(i2c_dev, 0x6b, test_reg, original_val);
            }
        } else {
            shell_error(sh, "  Write failed: %d", ret);
        }
    } else {
        shell_error(sh, "  Initial read failed: %d", ret);
    }
    
    return 0;
}

/* NPM1300 Advanced Initialization and Unlock */
static int cmd_npm1300_unlock(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Advanced Unlock and Wake-up Sequence:");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    // Try common PMIC unlock/initialization sequences
    shell_print(sh, "Step 1: Attempting common PMIC unlock sequences...");
    
    // Method 1: Try writing to common unlock registers
    struct {
        uint8_t reg;
        uint8_t value;
        const char *description;
    } unlock_sequences[] = {
        {0xFF, 0x00, "Reset sequence"},
        {0xFF, 0x01, "Enable sequence"},
        {0x00, 0x01, "Product ID unlock"},
        {0x70, 0xAA, "Common unlock pattern 1"},
        {0x71, 0x55, "Common unlock pattern 2"},
        {0x80, 0x01, "Configuration enable"},
        {0x90, 0x01, "Register unlock"},
    };
    
    for (int i = 0; i < 7; i++) {
        uint8_t orig_val;
        int ret = i2c_reg_read_byte(i2c_dev, 0x6b, unlock_sequences[i].reg, &orig_val);
        
        shell_print(sh, "  Trying %s (0x%02x = 0x%02x)...", 
                   unlock_sequences[i].description, unlock_sequences[i].reg, unlock_sequences[i].value);
        
        ret = i2c_reg_write_byte(i2c_dev, 0x6b, unlock_sequences[i].reg, unlock_sequences[i].value);
        if (ret == 0) {
            shell_print(sh, "    Write successful");
            k_sleep(K_MSEC(10));
            
            // Test if anything changed by trying to read Product ID
            uint8_t product_id;
            ret = i2c_reg_read_byte(i2c_dev, 0x6b, 0x00, &product_id);
            if (ret == 0 && product_id != 0x00) {
                shell_print(sh, "    SUCCESS! Product ID now: 0x%02x", product_id);
                return 0;
            }
        } else {
            shell_print(sh, "    Write failed: %d", ret);
        }
    }
    
    shell_print(sh, "");
    shell_print(sh, "Step 2: Testing if device is actually present...");
    
    // Try rapid successive reads to see if device behavior changes
    uint8_t rapid_reads[10];
    for (int i = 0; i < 10; i++) {
        int ret = i2c_reg_read_byte(i2c_dev, 0x6b, 0x00, &rapid_reads[i]);
        if (ret != 0) {
            shell_error(sh, "  Read %d failed: %d", i, ret);
            return ret;
        }
        k_sleep(K_MSEC(1));
    }
    
    shell_print(sh, "  Rapid reads: ");
    bool all_same = true;
    for (int i = 0; i < 10; i++) {
        shell_fprintf(sh, SHELL_NORMAL, "0x%02x ", rapid_reads[i]);
        if (rapid_reads[i] != rapid_reads[0]) all_same = false;
    }
    shell_print(sh, "");
    
    if (all_same) {
        shell_warn(sh, "  All reads identical - suggests static/dummy response");
    } else {
        shell_print(sh, "  Reads vary - device may be active");
    }
    
    shell_print(sh, "");
    shell_print(sh, "Step 3: Hardware reset attempt...");
    
    // Look for a reset pin or try power cycling via regulators
    shell_print(sh, "  No software reset method found in NPM1300 datasheet");
    shell_print(sh, "  Device may need:");
    shell_print(sh, "    - Hardware reset pin toggle");
    shell_print(sh, "    - Power cycle");
    shell_print(sh, "    - Different initialization sequence");
    
    return 0;
}

/* Test if NPM1300 is a real device or ghost/stub */
static int cmd_npm1300_ghost_test(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Ghost/Stub Device Test:");
    shell_print(sh, "Testing if device is real or just a phantom...");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    
    // Test 1: Write different values to same register, see if any stick
    shell_print(sh, "Test 1: Write persistence test...");
    uint8_t test_values[] = {0x01, 0xAA, 0x55, 0xFF, 0x00};
    uint8_t test_reg = 0x03;  // System status register
    
    for (int i = 0; i < 5; i++) {
        uint8_t write_val = test_values[i];
        uint8_t read_val;
        
        // Write value
        int ret = i2c_reg_write_byte(i2c_dev, 0x6b, test_reg, write_val);
        if (ret != 0) {
            shell_error(sh, "  Write failed: %d", ret);
            continue;
        }
        
        // Read back immediately
        ret = i2c_reg_read_byte(i2c_dev, 0x6b, test_reg, &read_val);
        if (ret == 0) {
            shell_print(sh, "  Write 0x%02x -> Read 0x%02x (%s)", 
                       write_val, read_val, 
                       (write_val == read_val) ? "MATCH" : "NO MATCH");
        }
        
        k_sleep(K_MSEC(10));
    }
    
    shell_print(sh, "");
    shell_print(sh, "Test 2: Register address test...");
    
    // Test if different register addresses return different values
    uint8_t reg_tests[] = {0x00, 0x01, 0x03, 0x10, 0x20, 0x30, 0xFF};
    bool all_zero = true;
    
    for (int i = 0; i < 7; i++) {
        uint8_t data;
        int ret = i2c_reg_read_byte(i2c_dev, 0x6b, reg_tests[i], &data);
        if (ret == 0) {
            shell_print(sh, "  Register 0x%02x = 0x%02x", reg_tests[i], data);
            if (data != 0x00) all_zero = false;
        } else {
            shell_error(sh, "  Register 0x%02x read failed: %d", reg_tests[i], ret);
        }
    }
    
    shell_print(sh, "");
    if (all_zero) {
        shell_warn(sh, "WARNING: GHOST DEVICE DETECTED!");
        shell_print(sh, "  - All registers return 0x00");
        shell_print(sh, "  - Writes are ignored");
        shell_print(sh, "  - Product ID is 0x00 (impossible)");
        shell_print(sh, "");
        shell_print(sh, "Possible causes:");
        shell_print(sh, "  1. NPM1300 chip not populated");
        shell_print(sh, "  2. NPM1300 not powered");
        shell_print(sh, "  3. I2C bus has pull-ups giving false ACKs");
        shell_print(sh, "  4. Device tree stub responding");
    } else {
        shell_print(sh, "Device appears to have real registers");
    }
    
    return 0;
}

/* NPM1300 Power Cycle / Hardware Reset */
static int cmd_npm1300_reset(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Hardware Reset Sequence:");
    shell_print(sh, "Attempting to break power deadlock...");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    // Try to force-enable critical regulators via direct register writes
    shell_print(sh, "Step 1: Force-enable BUCK2 (3.3V main rail)...");
    
    // BUCK2 enable register (from your register map)
    uint8_t buck2_enable_reg = 0x01;  // BUCK2ENASET
    uint8_t enable_val = 0x04;        // BUCK2 enable bit
    
    int ret = i2c_reg_write_byte(i2c_dev, 0x6b, buck2_enable_reg, enable_val);
    if (ret == 0) {
        shell_print(sh, "   BUCK2 enable command sent");
    } else {
        shell_error(sh, "  ERROR: BUCK2 enable failed: %d", ret);
    }
    
    k_sleep(K_MSEC(100));  // Allow regulator startup time
    
    shell_print(sh, "Step 2: Force-enable GPIO2 (power switch)...");
    
    // Try to set GPIO2 high via direct register access
    // GPIO control registers vary by PMIC, try common addresses
    uint8_t gpio_enable_regs[] = {0x06, 0x07, 0x08, 0x09};  // Common GPIO control registers
    uint8_t gpio2_enable = 0x04;  // Bit 2 for GPIO2
    
    for (int i = 0; i < 4; i++) {
        ret = i2c_reg_write_byte(i2c_dev, 0x6b, gpio_enable_regs[i], gpio2_enable);
        if (ret == 0) {
            shell_print(sh, "  Tried GPIO register 0x%02x", gpio_enable_regs[i]);
        }
    }
    
    k_sleep(K_MSEC(50));
    
    shell_print(sh, "Step 3: Test if NPM1300 responds now...");
    
    uint8_t product_id, revision, system_status;
    ret = i2c_reg_read_byte(i2c_dev, 0x6b, 0x00, &product_id);
    int ret2 = i2c_reg_read_byte(i2c_dev, 0x6b, 0x01, &revision);
    int ret3 = i2c_reg_read_byte(i2c_dev, 0x6b, 0x03, &system_status);
    
    if (ret == 0 && ret2 == 0 && ret3 == 0) {
        shell_print(sh, "  Product ID: 0x%02x", product_id);
        shell_print(sh, "  Revision: 0x%02x", revision);
        shell_print(sh, "  System Status: 0x%02x", system_status);
        
        if (product_id != 0x00 || revision != 0x00 || system_status != 0x00) {
            shell_print(sh, "  SUCCESS! NPM1300 appears to be responding!");
            shell_print(sh, "  Try: npm1300 status");
            return 0;
        } else {
            shell_warn(sh, "  Still reading all zeros...");
        }
    } else {
        shell_error(sh, "  Read failed - communication issue");
    }
    
    shell_print(sh, "");
    shell_warn(sh, "Reset sequence complete but NPM1300 still not responsive.");
    shell_print(sh, "This suggests a deeper hardware issue:");
    shell_print(sh, "  - NPM1300 may need external reset pin toggle");
    shell_print(sh, "  - Insufficient power supply to NPM1300");  
    shell_print(sh, "  - Hardware damage to NPM1300");
    
    return 0;
}

/* Check NPM1300 interrupt pin status */
static int cmd_npm1300_int_check(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Interrupt Pin Check:");
    shell_print(sh, "Checking GPIO P0.3 (NPM1300 -> nRF9151 interrupt)");
    shell_print(sh, "");
    
    // Check if GPIO P0.3 is being driven by NPM1300
    const struct device *gpio_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
    if (!device_is_ready(gpio_dev)) {
        shell_error(sh, "GPIO0 not ready");
        return -ENODEV;
    }
    
    // Configure P0.3 as input to read NPM1300's interrupt signal
    int ret = gpio_pin_configure(gpio_dev, 3, GPIO_INPUT);
    if (ret != 0) {
        shell_error(sh, "Failed to configure P0.3 as input: %d", ret);
        return ret;
    }
    
    // Read the interrupt pin state
    int pin_state = gpio_pin_get(gpio_dev, 3);
    shell_print(sh, "NPM1300 interrupt pin (P0.3) state: %s", 
               pin_state ? "HIGH (interrupt active)" : "LOW (no interrupt)");
    
    if (pin_state) {
        shell_print(sh, "");
        shell_print(sh, "WARNING: NPM1300 is signaling an interrupt!");
        shell_print(sh, "This could indicate:");
        shell_print(sh, "  - Power management event");
        shell_print(sh, "  - Battery/charging status");  
        shell_print(sh, "  - System error condition");
        shell_print(sh, "  - NPM1300 is trying to communicate");
        shell_print(sh, "");
        shell_print(sh, "Try reading NPM1300 status registers to see what's wrong.");
    } else {
        shell_print(sh, "");
        shell_print(sh, "No interrupt from NPM1300.");
        shell_print(sh, "Either NPM1300 is OK, or it's not functional enough to signal.");
    }
    
    return 0;
}

/* NPM1300 GPIO Control for LEDs */
static int cmd_npm1300_gpio_test(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 GPIO Control Test:");
    shell_print(sh, "");
    
    if (argc < 3) {
        shell_error(sh, "Usage: npm1300 gpio <pin> <state>");
        shell_print(sh, "  pin: 0, 2 (GPIO0=button, GPIO2=power_switch)");
        shell_print(sh, "  state: 0 (low) or 1 (high)");
        return -EINVAL;
    }
    
    uint8_t gpio_pin = strtol(argv[1], NULL, 10);
    uint8_t gpio_state = strtol(argv[2], NULL, 10);
    
    if (gpio_pin != 0 && gpio_pin != 2) {
        shell_error(sh, "Only GPIO 0 and 2 are configured");
        return -EINVAL;
    }
    
    if (gpio_state > 1) {
        shell_error(sh, "State must be 0 or 1");
        return -EINVAL;
    }
    
    shell_print(sh, "Setting NPM1300 GPIO%d = %s", gpio_pin, gpio_state ? "HIGH" : "LOW");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    // Try different GPIO control register addresses for NPM1300
    uint8_t gpio_ctrl_regs[] = {0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};
    uint8_t gpio_mask = (1 << gpio_pin);
    uint8_t gpio_value = gpio_state ? gpio_mask : 0;
    
    bool success = false;
    for (int i = 0; i < 6; i++) {
        uint8_t reg = gpio_ctrl_regs[i];
        
        // Try to set the GPIO
        int ret = i2c_reg_write_byte(i2c_dev, 0x6b, reg, gpio_value);
        if (ret == 0) {
            shell_print(sh, "  Wrote 0x%02x to register 0x%02x", gpio_value, reg);
            
            // Read back to verify
            uint8_t readback;
            ret = i2c_reg_read_byte(i2c_dev, 0x6b, reg, &readback);
            if (ret == 0) {
                shell_print(sh, "  Read back: 0x%02x", readback);
                if ((readback & gpio_mask) == (gpio_value & gpio_mask)) {
                    shell_print(sh, "   GPIO%d successfully set to %s", gpio_pin, gpio_state ? "HIGH" : "LOW");
                    success = true;
                    break;
                }
            }
        }
    }
    
    if (!success) {
        shell_warn(sh, "  Could not verify GPIO state - but command was sent");
    }
    
    return 0;
}

/* LED Power and Test */
static int cmd_npm1300_led_power(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 LED Power Control:");
    shell_print(sh, "Enabling power for LED circuit...");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C2 not ready");
        return -ENODEV;
    }
    
    // Step 1: Enable BUCK2 (3.3V)
    shell_print(sh, "Step 1: Enable BUCK2 (3.3V rail)...");
    uint8_t buck2_enable_reg = 0x01;  // BUCK2ENASET
    uint8_t buck2_enable_val = 0x04;  // BUCK2 enable bit
    
    int ret = i2c_reg_write_byte(i2c_dev, 0x6b, buck2_enable_reg, buck2_enable_val);
    if (ret == 0) {
        shell_print(sh, "   BUCK2 enable command sent");
    } else {
        shell_error(sh, "  ERROR: BUCK2 enable failed: %d", ret);
        return ret;
    }
    
    k_sleep(K_MSEC(100));  // Allow regulator startup
    
    // Step 2: Enable GPIO2 (power switch for LED circuit)
    shell_print(sh, "Step 2: Enable GPIO2 (LED power switch)...");
    
    // Try to set GPIO2 high
    uint8_t gpio_regs[] = {0x06, 0x07, 0x08, 0x09};
    uint8_t gpio2_high = 0x04;  // Bit 2 for GPIO2
    
    for (int i = 0; i < 4; i++) {
        ret = i2c_reg_write_byte(i2c_dev, 0x6b, gpio_regs[i], gpio2_high);
        if (ret == 0) {
            shell_print(sh, "  Tried GPIO register 0x%02x", gpio_regs[i]);
        }
    }
    
    shell_print(sh, "   GPIO2 enable commands sent");
    
    k_sleep(K_MSEC(50));
    
    // Step 3: Enable LDO1 (nPM6001 enable - if connected to LED circuit)
    shell_print(sh, "Step 3: Enable LDO1 (additional power control)...");
    uint8_t ldo1_enable_reg = 0x00;  // TASKLDSW1SET  
    uint8_t ldo1_enable_val = 0x01;  // LDSW1 enable
    
    ret = i2c_reg_write_byte(i2c_dev, 0x6b, ldo1_enable_reg, ldo1_enable_val);
    if (ret == 0) {
        shell_print(sh, "   LDO1 enable command sent");
    }
    
    shell_print(sh, "");
    shell_print(sh, "LED power sequence complete!");
    shell_print(sh, "Now try controlling individual LEDs via nRF9151 GPIOs");
    shell_print(sh, "Check your schematic for which nRF9151 pins control the LEDs");
    
    return 0;
}

static int cmd_npm1300_init(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Attempting NPM1300 Initialization...");
    shell_print(sh, "");
    
    // Try to wake up or initialize the NPM1300
    // These are common initialization sequences for PMICs
    
    shell_print(sh, "Step 1: Enable basic regulators...");
    
    // Try enabling BUCK2 (main 3.3V rail) first
    int ret = npm1300_reg_write(0x02, 0x01);  // BUCK2ENASET
    if (ret == 0) {
        shell_print(sh, "   BUCK2 enable attempted");
    } else {
        shell_error(sh, "  ERROR: BUCK2 enable failed: %d", ret);
    }
    
    k_sleep(K_MSEC(100));  // Allow regulator to stabilize
    
    shell_print(sh, "Step 2: Enable sensor load switch (LDSW2)...");
    ret = npm1300_reg_write(0x02, 0x01);  // TASKLDSW2SET  
    if (ret == 0) {
        shell_print(sh, "   LDSW2 enable attempted");
    } else {
        shell_error(sh, "  ERROR: LDSW2 enable failed: %d", ret);
    }
    
    k_sleep(K_MSEC(100));
    
    shell_print(sh, "Step 3: Check if initialization worked...");
    
    // Read some status registers to see if anything changed
    uint8_t buck_status, ldsw_status;
    ret = npm1300_reg_read(0x34, &buck_status);
    if (ret == 0) {
        shell_print(sh, "  BUCK Status: 0x%02x", buck_status);
    }
    
    ret = npm1300_reg_read(0x04, &ldsw_status);  
    if (ret == 0) {
        shell_print(sh, "  LDSW Status: 0x%02x", ldsw_status);
    }
    
    shell_print(sh, "");
    shell_print(sh, "Initialization complete. Try 'npm1300 status' again.");
    
    return 0;
}

/* NPM1300 Basic I2C Connectivity Test */
static int cmd_npm1300_test_i2c(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Basic I2C Connectivity Test:");
    shell_print(sh, "Testing I2C2 at address 0x6b...");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    
    // Step 1: Check if I2C device is ready
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "ERROR: I2C2 device not ready!");
        return -ENODEV;
    }
    shell_print(sh, "Step 1: I2C2 device is ready");
    
    // Step 2: Test basic device presence (simple ping)
    uint8_t dummy;
    int ping_result = i2c_read(i2c_dev, &dummy, 1, NPM1300_I2C_ADDR);
    shell_print(sh, "Step 2: Device ping test: %s", 
               ping_result == 0 ? "SUCCESS (device responds)" : "FAILED (no response)");
    
    // Step 3: Test different I2C addresses around 0x6b
    shell_print(sh, "Step 3: Testing nearby I2C addresses...");
    uint8_t test_addrs[] = {0x6a, 0x6b, 0x6c, 0x6d};
    for (int i = 0; i < 4; i++) {
        uint8_t addr = test_addrs[i];
        int result = i2c_read(i2c_dev, &dummy, 1, addr);
        shell_print(sh, "  Address 0x%02x: %s", addr, 
                   result == 0 ? "RESPONDS" : "no response");
    }
    
    // Step 4: Test I2C bus scanning specifically around NPM1300 range
    shell_print(sh, "Step 4: Scanning I2C addresses 0x60-0x6F...");
    bool found_device = false;
    for (uint8_t addr = 0x60; addr <= 0x6F; addr++) {
        int result = i2c_read(i2c_dev, &dummy, 1, addr);
        if (result == 0) {
            shell_print(sh, "  Found device at 0x%02x", addr);
            found_device = true;
        }
    }
    
    if (!found_device) {
        shell_warn(sh, "  No devices found in NPM1300 address range");
    }
    
    // Step 5: Test with register 0x00 specifically 
    shell_print(sh, "Step 5: Testing register access at 0x6b...");
    uint8_t reg_data;
    int reg_result = i2c_reg_read_byte(i2c_dev, 0x6b, 0x00, &reg_data);
    shell_print(sh, "  Register 0x00 read: %s, data=0x%02x", 
               reg_result == 0 ? "SUCCESS" : "FAILED", 
               reg_result == 0 ? reg_data : 0);
    
    shell_print(sh, "");
    if (ping_result == 0 || reg_result == 0) {
        shell_print(sh, "RESULT: NPM1300 I2C communication partially working");
        shell_print(sh, "Try: npm1300 read 0x00");
    } else {
        shell_error(sh, "RESULT: NPM1300 I2C communication failed");
        shell_print(sh, "Possible issues:");
        shell_print(sh, "  - NPM1300 not powered or in reset");
        shell_print(sh, "  - Wrong I2C address");
        shell_print(sh, "  - I2C bus configuration issue");
        shell_print(sh, "  - Hardware problem");
    }
    
    return 0;
}

/* NPM1300 Register Scanner - Find non-zero registers */
static int cmd_npm1300_scan_regs(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "NPM1300 Register Scanner:");
    shell_print(sh, "Scanning for non-zero registers to find active/meaningful data...");
    shell_print(sh, "");
    
    const struct device *i2c_dev = NPM1300_I2C_BUS;
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "ERROR: I2C2 not ready");
        return -ENODEV;
    }
    
    // Define register ranges to scan based on NPM1300 datasheet
    struct {
        uint8_t start;
        uint8_t end;
        const char *description;
    } ranges[] = {
        {0x00, 0x0F, "System registers (Product ID, status, etc.)"},
        {0x10, 0x1F, "BUCK regulator registers"},
        {0x20, 0x2F, "LDO/LDSW registers"}, 
        {0x30, 0x3F, "Charger registers"},
        {0x40, 0x4F, "GPIO registers"},
        {0x50, 0x5F, "ADC registers"},
        {0x60, 0x6F, "Timer registers"},
        {0x70, 0x7F, "Event/interrupt registers"},
    };
    
    int total_nonzero = 0;
    int total_readable = 0;
    
    for (int range_idx = 0; range_idx < 8; range_idx++) {
        shell_print(sh, "%s (0x%02x-0x%02x):", 
                   ranges[range_idx].description,
                   ranges[range_idx].start, 
                   ranges[range_idx].end);
        
        bool found_in_range = false;
        
        for (uint8_t reg = ranges[range_idx].start; reg <= ranges[range_idx].end; reg++) {
            uint8_t data;
            int ret = i2c_reg_read_byte(i2c_dev, NPM1300_I2C_ADDR, reg, &data);
            
            if (ret == 0) {
                total_readable++;
                if (data != 0x00) {
                    shell_print(sh, "  0x%02x = 0x%02x", reg, data);
                    total_nonzero++;
                    found_in_range = true;
                }
            }
        }
        
        if (!found_in_range) {
            shell_print(sh, "  (all registers in this range are 0x00 or unreadable)");
        }
        shell_print(sh, "");
    }
    
    // Summary
    shell_print(sh, "Scan Summary:");
    shell_print(sh, "  Total readable registers: %d", total_readable);
    shell_print(sh, "  Non-zero registers found: %d", total_nonzero);
    
    if (total_nonzero == 0) {
        shell_warn(sh, "");
        shell_warn(sh, "WARNING: All registers return 0x00!");
        shell_print(sh, "This suggests:");
        shell_print(sh, "  1. NPM1300 is in deep reset/sleep mode");
        shell_print(sh, "  2. NPM1300 needs initialization sequence");
        shell_print(sh, "  3. Power rails not enabled");
        shell_print(sh, "  4. This might be a 'ghost' device (I2C pull-ups giving false ACKs)");
        shell_print(sh, "");
        shell_print(sh, "Try: npm1300 ghost");
    } else {
        shell_print(sh, "");
        shell_print(sh, "SUCCESS: Found active registers - NPM1300 is responding with real data!");
        shell_print(sh, "The PMIC appears to be functional.");
    }
    
    return 0;
}

/* NPM1300 Shell Command Structure */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_npm1300_buck,
    SHELL_CMD(enable, NULL, "Enable BUCK. Usage: npm1300 buck enable <1|2>", cmd_npm1300_buck_enable),
    SHELL_CMD(disable, NULL, "Disable BUCK. Usage: npm1300 buck disable <1|2>", cmd_npm1300_buck_disable),
    SHELL_CMD(voltage, NULL, "Set BUCK voltage. Usage: npm1300 buck voltage <1|2> <code>", cmd_npm1300_buck_voltage),
    SHELL_CMD(status, NULL, "Show BUCK regulator status", cmd_npm1300_buck_status),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_npm1300_ldsw,
    SHELL_CMD(enable, NULL, "Enable LDSW. Usage: npm1300 ldsw enable <1|2>", cmd_npm1300_ldsw_enable),
    SHELL_CMD(disable, NULL, "Disable LDSW. Usage: npm1300 ldsw disable <1|2>", cmd_npm1300_ldsw_disable),
    SHELL_CMD(voltage, NULL, "Set LDSW voltage. Usage: npm1300 ldsw voltage <1|2> <code>", cmd_npm1300_ldsw_voltage),
    SHELL_CMD(status, NULL, "Show load switch status", cmd_npm1300_ldsw_status),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_npm1300_charger,
    SHELL_CMD(enable, NULL, "Enable battery charger", cmd_npm1300_charger_enable),
    SHELL_CMD(disable, NULL, "Disable battery charger", cmd_npm1300_charger_disable),
    SHELL_CMD(status, NULL, "Show charger status", cmd_npm1300_charger_status),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_npm1300_vbusin,
    SHELL_CMD(limit, NULL, "Set input current limit. Usage: npm1300 vbusin limit <code>", cmd_npm1300_vbusin_limit),
    SHELL_CMD(suspend, NULL, "Control suspend mode. Usage: npm1300 vbusin suspend <on|off>", cmd_npm1300_vbusin_suspend),
    SHELL_CMD(status, NULL, "Show VBUS input status", cmd_npm1300_vbusin_status),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_npm1300,
    SHELL_CMD(read, NULL, "Read register. Usage: npm1300 read <reg>", cmd_npm1300_read),
    SHELL_CMD(write, NULL, "Write register. Usage: npm1300 write <reg> <value>", cmd_npm1300_write),
    SHELL_CMD(status, NULL, "Show system status with debugging", cmd_npm1300_status),
    SHELL_CMD(debug, NULL, "Advanced NPM1300 debugging", cmd_npm1300_debug),
    SHELL_CMD(probe, NULL, "Test I2C addresses and hardware detection", cmd_npm1300_probe),
    SHELL_CMD(unlock, NULL, "Attempt to unlock/wake NPM1300", cmd_npm1300_unlock),
    SHELL_CMD(reset, NULL, "Hardware reset sequence for NPM1300", cmd_npm1300_reset),
    SHELL_CMD(interrupt, NULL, "Check NPM1300 interrupt pin status", cmd_npm1300_int_check),
    SHELL_CMD(gpio, NULL, "Control NPM1300 GPIO. Usage: npm1300 gpio <pin> <state>", cmd_npm1300_gpio_test),
    SHELL_CMD(ledpower, NULL, "Enable power for LED circuit", cmd_npm1300_led_power),
    SHELL_CMD(ghost, NULL, "Test if NPM1300 is real or phantom device", cmd_npm1300_ghost_test),
    SHELL_CMD(init, NULL, "Initialize NPM1300 regulators", cmd_npm1300_init),
    SHELL_CMD(test_i2c, NULL, "Test basic NPM1300 I2C connectivity", cmd_npm1300_test_i2c),
    SHELL_CMD(scan_regs, NULL, "Scan NPM1300 registers for non-zero values", cmd_npm1300_scan_regs),
    SHELL_CMD(buck, &sub_npm1300_buck, "BUCK regulator control", NULL),
    SHELL_CMD(ldsw, &sub_npm1300_ldsw, "Load switch control", NULL),
    SHELL_CMD(charger, &sub_npm1300_charger, "Battery charger control", NULL),
    SHELL_CMD(vbusin, &sub_npm1300_vbusin, "VBUS input control", NULL),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_gnss,
    SHELL_CMD(enable, NULL, "Initialize MAX M10S GNSS module", cmd_gnss_enable),
    SHELL_CMD(disable, NULL, "Disable external MAX M10S GNSS module", cmd_gnss_disable),
    SHELL_CMD(status, NULL, "Show external GNSS status", cmd_gnss_status),
    SHELL_CMD(scan, NULL, "Scan for GNSS on I2C buses", cmd_gnss_scan),
    SHELL_CMD(test, NULL, "Test GNSS I2C. Usage: gnss test <bus> <addr>", cmd_gnss_test),
    SHELL_CMD(read, NULL, "Read GNSS data via I2C. Usage: gnss read [addr]", cmd_gnss_read),
    SHELL_CMD(safe, NULL, "Control safe boot mode. Usage: gnss safe <on|off>", cmd_gnss_safe),
    SHELL_CMD(pps, NULL, "Monitor PPS signal for GPS fix", cmd_gnss_pps),
    SHELL_SUBCMD_SET_END
);

// /* I2C LED Controller Commands */
// static int cmd_led_scan(const struct shell *sh, size_t argc, char **argv)
// {
//     shell_print(sh, "I2C LED Controller Scan (I2C1 - LED_SCL/LED_SDA):");
//     shell_print(sh, "First enabling LED power via NPM1300...");

//     // Enable LED power first
//     cmd_npm1300_led_power(sh, 0, NULL);
//     k_sleep(K_MSEC(500));

//     const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
//     if (!device_is_ready(i2c_dev))
//     {
//         shell_error(sh, "I2C1 not ready");
//         return -ENODEV;
//     }

//     shell_print(sh, "");
//     shell_print(sh, "Common LED controller I2C addresses:");
//     shell_print(sh, "  PCA9633/PCA9634: 0x62-0x65");
//     shell_print(sh, "  PCA9685: 0x40-0x7F");
//     shell_print(sh, "  IS31FL3236: 0x3C-0x3F");
//     shell_print(sh, "  LP5562: 0x30-0x33");
//     shell_print(sh, "");

//     shell_print(sh, "Scanning I2C1...");
//     shell_print(sh, "     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");

//     for (int addr = 0; addr < 128; addr++)
//     {
//         if (addr % 16 == 0)
//         {
//             shell_fprintf(sh, SHELL_NORMAL, "%02x: ", addr);
//         }

//         uint8_t dummy;
//         int ret = i2c_reg_read_byte(i2c_dev, addr, 0x00, &dummy);

//         if (ret == 0)
//         {
//             shell_fprintf(sh, SHELL_NORMAL, "%02x ", addr);
//         }
//         else
//         {
//             shell_fprintf(sh, SHELL_NORMAL, "-- ");
//         }

//         if (addr % 16 == 15)
//         {
//             shell_print(sh, "");
//         }
//     }

//     return 0;
// }

// static int cmd_led_test(const struct shell *sh, size_t argc, char **argv)
// {
//     shell_print(sh, "I2C LED Controller Test:");

//     if (argc < 2)
//     {
//         shell_error(sh, "Usage: led test <i2c_address>");
//         shell_print(sh, "  i2c_address: hex address (e.g., 0x62, 0x40)");
//         shell_print(sh, "  Try 'led scan' first to find LED controllers");
//         return -EINVAL;
//     }

//     uint8_t led_addr = strtol(argv[1], NULL, 16);

//     shell_print(sh, "Testing LED controller at I2C1 address 0x%02x", led_addr);

//     const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
//     if (!device_is_ready(i2c_dev))
//     {
//         shell_error(sh, "I2C1 not ready");
//         return -ENODEV;
//     }

//     // Step 1: Enable LED power
//     shell_print(sh, "Step 1: Enabling LED power via NPM1300...");
//     cmd_npm1300_led_power(sh, 0, NULL);
//     k_sleep(K_MSEC(500));

//     // Step 2: Read device registers
//     shell_print(sh, "Step 2: Reading LED controller registers...");
//     uint8_t test_regs[] = {0x00, 0x01, 0x02, 0x03, 0x80, 0x81, 0xFE, 0xFF};
//     for (int i = 0; i < 8; i++)
//     {
//         uint8_t reg = test_regs[i];
//         uint8_t data;
//         int ret = i2c_reg_read_byte(i2c_dev, led_addr, reg, &data);

//         if (ret == 0)
//         {
//             shell_print(sh, "  Register 0x%02x = 0x%02x", reg, data);
//         }
//         else
//         {
//             shell_print(sh, "  Register 0x%02x = read failed", reg);
//         }
//     }

//     // Step 3: Try LED patterns
//     shell_print(sh, "Step 3: Testing LED patterns...");

//     // Generic LED controller commands
//     struct
//     {
//         uint8_t reg;
//         uint8_t val;
//         const char *desc;
//     } commands[] = {
//         {0x00, 0x01, "Mode - enable oscillator"},
//         {0x01, 0x00, "Mode 2"},
//         {0x02, 0xFF, "LED0 - full brightness"},
//         {0x03, 0x80, "LED1 - half brightness"},
//         {0x04, 0x40, "LED2 - quarter brightness"},
//         {0x05, 0x00, "LED3 - off"},
//         {0x08, 0xAA, "LED output control"},
//     };

//     for (int i = 0; i < 7; i++)
//     {
//         int ret = i2c_reg_write_byte(i2c_dev, led_addr, commands[i].reg, commands[i].val);
//         shell_print(sh, "  %s: %s", commands[i].desc, ret == 0 ? "OK" : "FAIL");
//         k_sleep(K_MSEC(200));
//     }

//     shell_print(sh, "");
//     shell_print(sh, "LED test complete! Check for LED activity.");

//     return 0;
// }

// SHELL_STATIC_SUBCMD_SET_CREATE(sub_led,
//                                SHELL_CMD(scan, NULL, "Scan I2C1 for LED controllers", cmd_led_scan),
//                                SHELL_CMD(test, NULL, "Test I2C LED controller. Usage: led test <i2c_address>", cmd_led_test),
//                                SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(hello, NULL, "Test command", cmd_hello);
SHELL_CMD_REGISTER(i2c, &sub_i2c, "I2C commands", NULL);
//SHELL_CMD_REGISTER(led, &sub_led, "I2C LED controller commands", NULL);
SHELL_CMD_REGISTER(gnss, &sub_gnss, "u-blox MAX M10S GNSS commands", NULL);
SHELL_CMD_REGISTER(npm1300, &sub_npm1300, "NPM1300 PMIC control", NULL);
