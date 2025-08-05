#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

LOG_MODULE_REGISTER(led_shell, LOG_LEVEL_INF);

/* KTD2026EWE-TR LED Controller Register Definitions */
#define KTD2026_I2C_ADDR        0x30
#define KTD2026_EN_RST          0x00
#define KTD2026_FLASH_PERIOD    0x01
#define KTD2026_FLASH_DUTY      0x02
#define KTD2026_LED_EN          0x03
#define KTD2026_TRISE_TFALL     0x04
#define KTD2026_LED1            0x05
#define KTD2026_LED2            0x06
#define KTD2026_LED3            0x07
#define KTD2026_TIMER_CTRL      0x08
#define KTD2026_FLASH_PERIOD2   0x09
#define KTD2026_FLASH_DUTY2     0x0A
#define KTD2026_LED_EN2         0x0B
#define KTD2026_TRISE_TFALL2    0x0C
#define KTD2026_LED4            0x0D
#define KTD2026_LED5            0x0E
#define KTD2026_LED6            0x0F

/* LED Enable Register Bits */
#define KTD2026_LED_EN_LED1_EN  BIT(0)
#define KTD2026_LED_EN_LED2_EN  BIT(1)
#define KTD2026_LED_EN_LED3_EN  BIT(2)
#define KTD2026_LED_EN_LED4_EN  BIT(3)
#define KTD2026_LED_EN_LED5_EN  BIT(4)
#define KTD2026_LED_EN_LED6_EN  BIT(5)

/* Timer Control Register Bits */
#define KTD2026_TIMER_CTRL_TIMER_EN BIT(0)
#define KTD2026_TIMER_CTRL_TIMER_SEL_MASK 0x06
#define KTD2026_TIMER_CTRL_TIMER_SEL_SHIFT 1

/* LED Current Control */
#define KTD2026_LED_CURRENT_MAX 0x1F
#define KTD2026_LED_CURRENT_MIN 0x00

/* Flash Period and Duty Cycle */
#define KTD2026_FLASH_PERIOD_MAX 0x1F
#define KTD2026_FLASH_DUTY_MAX   0x07

/* I2C Device */
static const struct device *i2c_dev;

/* Function prototypes */
static int ktd2026_init(void);
static int ktd2026_write_reg(uint8_t reg, uint8_t value);
static int ktd2026_read_reg(uint8_t reg, uint8_t *value);
static int ktd2026_set_led_current(uint8_t led, uint8_t current);
static int ktd2026_set_led_enable(uint8_t led, bool enable);
static int ktd2026_set_flash_period(uint8_t period);
static int ktd2026_set_flash_duty(uint8_t duty);
static int ktd2026_set_timer_control(uint8_t timer_sel, bool enable);

/* Shell command handlers */
static int cmd_led_init(const struct shell *shell, size_t argc, char *argv[]);
static int cmd_led_on(const struct shell *shell, size_t argc, char *argv[]);
static int cmd_led_off(const struct shell *shell, size_t argc, char *argv[]);
static int cmd_led_set(const struct shell *shell, size_t argc, char *argv[]);
static int cmd_led_flash(const struct shell *shell, size_t argc, char *argv[]);
static int cmd_led_read(const struct shell *shell, size_t argc, char *argv[]);

/* Initialize KTD2026 LED controller */
static int ktd2026_init(void)
{
    int ret;
    uint8_t value;

    /* Get I2C device */
    i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    if (!device_is_ready(i2c_dev)) {
        LOG_ERR("I2C1 device not ready");
        return -ENODEV;
    }

    LOG_INF("I2C1 device is ready");

    /* Test basic I2C communication first */
    uint8_t test_data = 0x00;
    ret = i2c_write(i2c_dev, &test_data, 1, KTD2026_I2C_ADDR);
    if (ret < 0) {
        LOG_ERR("Basic I2C write test failed: %d", ret);
        return ret;
    }

    LOG_INF("Basic I2C communication test passed");

    /* Reset the device */
    ret = ktd2026_write_reg(KTD2026_EN_RST, 0x00);
    if (ret < 0) {
        LOG_ERR("Failed to reset KTD2026: %d", ret);
        return ret;
    }

    k_sleep(K_MSEC(10));

    /* Read back to verify communication */
    ret = ktd2026_read_reg(KTD2026_EN_RST, &value);
    if (ret < 0) {
        LOG_ERR("Failed to read KTD2026: %d", ret);
        return ret;
    }

    LOG_INF("KTD2026 initialized successfully, read value: 0x%02x", value);
    return 0;
}

/* Write register to KTD2026 */
static int ktd2026_write_reg(uint8_t reg, uint8_t value)
{
    uint8_t buf[2];
    int ret;

    buf[0] = reg;
    buf[1] = value;

    ret = i2c_write(i2c_dev, buf, sizeof(buf), KTD2026_I2C_ADDR);
    if (ret < 0) {
        LOG_ERR("I2C write failed: %d", ret);
        return ret;
    }

    return 0;
}

/* Read register from KTD2026 */
static int ktd2026_read_reg(uint8_t reg, uint8_t *value)
{
    int ret;

    ret = i2c_write_read(i2c_dev, KTD2026_I2C_ADDR, &reg, 1, value, 1);
    if (ret < 0) {
        LOG_ERR("I2C read failed: %d", ret);
        return ret;
    }

    return 0;
}

/* Set LED current (0-31) */
static int ktd2026_set_led_current(uint8_t led, uint8_t current)
{
    uint8_t reg;
    int ret;

    if (current > KTD2026_LED_CURRENT_MAX) {
        current = KTD2026_LED_CURRENT_MAX;
    }

    switch (led) {
    case 1:
        reg = KTD2026_LED1;
        break;
    case 2:
        reg = KTD2026_LED2;
        break;
    case 3:
        reg = KTD2026_LED3;
        break;
    case 4:
        reg = KTD2026_LED4;
        break;
    case 5:
        reg = KTD2026_LED5;
        break;
    case 6:
        reg = KTD2026_LED6;
        break;
    default:
        return -EINVAL;
    }

    ret = ktd2026_write_reg(reg, current);
    if (ret < 0) {
        LOG_ERR("Failed to set LED %d current: %d", led, ret);
        return ret;
    }

    return 0;
}

/* Enable/disable LED */
static int ktd2026_set_led_enable(uint8_t led, bool enable)
{
    uint8_t value;
    int ret;

    /* Read current LED enable register */
    ret = ktd2026_read_reg(KTD2026_LED_EN, &value);
    if (ret < 0) {
        return ret;
    }

    /* Set or clear the appropriate bit */
    switch (led) {
    case 1:
        if (enable) {
            value |= KTD2026_LED_EN_LED1_EN;
        } else {
            value &= ~KTD2026_LED_EN_LED1_EN;
        }
        break;
    case 2:
        if (enable) {
            value |= KTD2026_LED_EN_LED2_EN;
        } else {
            value &= ~KTD2026_LED_EN_LED2_EN;
        }
        break;
    case 3:
        if (enable) {
            value |= KTD2026_LED_EN_LED3_EN;
        } else {
            value &= ~KTD2026_LED_EN_LED3_EN;
        }
        break;
    case 4:
        if (enable) {
            value |= KTD2026_LED_EN_LED4_EN;
        } else {
            value &= ~KTD2026_LED_EN_LED4_EN;
        }
        break;
    case 5:
        if (enable) {
            value |= KTD2026_LED_EN_LED5_EN;
        } else {
            value &= ~KTD2026_LED_EN_LED5_EN;
        }
        break;
    case 6:
        if (enable) {
            value |= KTD2026_LED_EN_LED6_EN;
        } else {
            value &= ~KTD2026_LED_EN_LED6_EN;
        }
        break;
    default:
        return -EINVAL;
    }

    ret = ktd2026_write_reg(KTD2026_LED_EN, value);
    if (ret < 0) {
        LOG_ERR("Failed to set LED %d enable: %d", led, ret);
        return ret;
    }

    return 0;
}

/* Set flash period (0-31) */
static int ktd2026_set_flash_period(uint8_t period)
{
    int ret;

    if (period > KTD2026_FLASH_PERIOD_MAX) {
        period = KTD2026_FLASH_PERIOD_MAX;
    }

    ret = ktd2026_write_reg(KTD2026_FLASH_PERIOD, period);
    if (ret < 0) {
        LOG_ERR("Failed to set flash period: %d", ret);
        return ret;
    }

    return 0;
}

/* Set flash duty cycle (0-7) */
static int ktd2026_set_flash_duty(uint8_t duty)
{
    int ret;

    if (duty > KTD2026_FLASH_DUTY_MAX) {
        duty = KTD2026_FLASH_DUTY_MAX;
    }

    ret = ktd2026_write_reg(KTD2026_FLASH_DUTY, duty);
    if (ret < 0) {
        LOG_ERR("Failed to set flash duty: %d", ret);
        return ret;
    }

    return 0;
}

/* Set timer control */
static int ktd2026_set_timer_control(uint8_t timer_sel, bool enable)
{
    uint8_t value;
    int ret;

    /* Read current timer control register */
    ret = ktd2026_read_reg(KTD2026_TIMER_CTRL, &value);
    if (ret < 0) {
        return ret;
    }

    /* Clear timer selection bits */
    value &= ~KTD2026_TIMER_CTRL_TIMER_SEL_MASK;
    
    /* Set timer selection */
    value |= (timer_sel << KTD2026_TIMER_CTRL_TIMER_SEL_SHIFT) & KTD2026_TIMER_CTRL_TIMER_SEL_MASK;

    /* Set or clear enable bit */
    if (enable) {
        value |= KTD2026_TIMER_CTRL_TIMER_EN;
    } else {
        value &= ~KTD2026_TIMER_CTRL_TIMER_EN;
    }

    ret = ktd2026_write_reg(KTD2026_TIMER_CTRL, value);
    if (ret < 0) {
        LOG_ERR("Failed to set timer control: %d", ret);
        return ret;
    }

    return 0;
}

/* Shell command: Initialize LED controller */
static int cmd_led_init(const struct shell *shell, size_t argc, char *argv[])
{
    int ret;

    ret = ktd2026_init();
    if (ret < 0) {
        shell_error(shell, "LED init failed: %d", ret);
        return ret;
    }

    shell_print(shell, "LED controller initialized successfully");
    return 0;
}

/* Shell command: Turn LED on */
static int cmd_led_on(const struct shell *shell, size_t argc, char *argv[])
{
    int led;
    int ret;

    if (argc != 2) {
        shell_error(shell, "Usage: led_on <led_number>");
        return -EINVAL;
    }

    led = atoi(argv[1]);
    if (led < 1 || led > 6) {
        shell_error(shell, "LED number must be 1-6");
        return -EINVAL;
    }

    ret = ktd2026_set_led_enable(led, true);
    if (ret < 0) {
        shell_error(shell, "Failed to turn on LED %d: %d", led, ret);
        return ret;
    }

    shell_print(shell, "LED %d turned on", led);
    return 0;
}

/* Shell command: Turn LED off */
static int cmd_led_off(const struct shell *shell, size_t argc, char *argv[])
{
    int led;
    int ret;

    if (argc != 2) {
        shell_error(shell, "Usage: led_off <led_number>");
        return -EINVAL;
    }

    led = atoi(argv[1]);
    if (led < 1 || led > 6) {
        shell_error(shell, "LED number must be 1-6");
        return -EINVAL;
    }

    ret = ktd2026_set_led_enable(led, false);
    if (ret < 0) {
        shell_error(shell, "Failed to turn off LED %d: %d", led, ret);
        return ret;
    }

    shell_print(shell, "LED %d turned off", led);
    return 0;
}

/* Shell command: Set LED current */
static int cmd_led_set(const struct shell *shell, size_t argc, char *argv[])
{
    int led, current;
    int ret;

    if (argc != 3) {
        shell_error(shell, "Usage: led_set <led_number> <current>");
        return -EINVAL;
    }

    led = atoi(argv[1]);
    current = atoi(argv[2]);

    if (led < 1 || led > 6) {
        shell_error(shell, "LED number must be 1-6");
        return -EINVAL;
    }

    if (current < 0 || current > 31) {
        shell_error(shell, "Current must be 0-31");
        return -EINVAL;
    }

    ret = ktd2026_set_led_current(led, current);
    if (ret < 0) {
        shell_error(shell, "Failed to set LED %d current: %d", led, ret);
        return ret;
    }

    shell_print(shell, "LED %d current set to %d", led, current);
    return 0;
}

/* Shell command: Set LED flash */
static int cmd_led_flash(const struct shell *shell, size_t argc, char *argv[])
{
    int led, period, duty;
    int ret;

    if (argc != 4) {
        shell_error(shell, "Usage: led_flash <led_number> <period> <duty>");
        return -EINVAL;
    }

    led = atoi(argv[1]);
    period = atoi(argv[2]);
    duty = atoi(argv[3]);

    if (led < 1 || led > 6) {
        shell_error(shell, "LED number must be 1-6");
        return -EINVAL;
    }

    if (period < 0 || period > 31) {
        shell_error(shell, "Period must be 0-31");
        return -EINVAL;
    }

    if (duty < 0 || duty > 7) {
        shell_error(shell, "Duty must be 0-7");
        return -EINVAL;
    }

    /* Set flash period and duty */
    ret = ktd2026_set_flash_period(period);
    if (ret < 0) {
        shell_error(shell, "Failed to set flash period: %d", ret);
        return ret;
    }

    ret = ktd2026_set_flash_duty(duty);
    if (ret < 0) {
        shell_error(shell, "Failed to set flash duty: %d", ret);
        return ret;
    }

    /* Enable timer for flashing */
    ret = ktd2026_set_timer_control(0, true);
    if (ret < 0) {
        shell_error(shell, "Failed to enable timer: %d", ret);
        return ret;
    }

    /* Turn on the LED */
    ret = ktd2026_set_led_enable(led, true);
    if (ret < 0) {
        shell_error(shell, "Failed to turn on LED %d: %d", led, ret);
        return ret;
    }

    shell_print(shell, "LED %d flashing with period %d, duty %d", led, period, duty);
    return 0;
}

/* Shell command: Read register */
static int cmd_led_read(const struct shell *shell, size_t argc, char *argv[])
{
    uint8_t reg, value;
    int ret;

    if (argc != 2) {
        shell_error(shell, "Usage: led_read <register>");
        return -EINVAL;
    }

    reg = strtol(argv[1], NULL, 16);
    ret = ktd2026_read_reg(reg, &value);
    if (ret < 0) {
        shell_error(shell, "Failed to read register 0x%02x: %d", reg, ret);
        return ret;
    }

    shell_print(shell, "Register 0x%02x = 0x%02x (%d)", reg, value, value);
    return 0;
}

/* Shell command: Scan I2C bus */
static int cmd_led_scan(const struct shell *shell, size_t argc, char *argv[])
{
    int ret;
    uint8_t test_data = 0x00;
    int found_devices = 0;

    shell_print(shell, "Scanning I2C bus for devices...");

    /* Get I2C device */
    const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    if (!device_is_ready(i2c_dev)) {
        shell_error(shell, "I2C1 device not ready");
        return -ENODEV;
    }

    shell_print(shell, "I2C1 device is ready");

    /* Scan all possible addresses */
    for (int addr = 0x08; addr <= 0x77; addr++) {
        ret = i2c_write(i2c_dev, &test_data, 1, addr);
        if (ret == 0) {
            shell_print(shell, "Found device at address 0x%02x", addr);
            found_devices++;
        }
    }

    if (found_devices == 0) {
        shell_error(shell, "No I2C devices found");
        return -ENODEV;
    }

    shell_print(shell, "Scan complete. Found %d device(s)", found_devices);
    return 0;
}

/* Shell command: Test I2C communication */
static int cmd_led_test_i2c(const struct shell *shell, size_t argc, char *argv[])
{
    int ret;
    uint8_t test_data = 0x00;

    shell_print(shell, "Testing I2C communication with KTD2026...");

    /* Get I2C device */
    const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    if (!device_is_ready(i2c_dev)) {
        shell_error(shell, "I2C1 device not ready");
        return -ENODEV;
    }

    shell_print(shell, "I2C1 device is ready");

    /* Test write to KTD2026 address */
    ret = i2c_write(i2c_dev, &test_data, 1, KTD2026_I2C_ADDR);
    if (ret < 0) {
        shell_error(shell, "I2C write test failed: %d", ret);
        return ret;
    }

    shell_print(shell, "I2C write test passed");

    /* Test read from KTD2026 address */
    uint8_t read_data;
    ret = i2c_write_read(i2c_dev, KTD2026_I2C_ADDR, &test_data, 1, &read_data, 1);
    if (ret < 0) {
        shell_error(shell, "I2C read test failed: %d", ret);
        return ret;
    }

    shell_print(shell, "I2C read test passed");
    shell_print(shell, "I2C communication with KTD2026 is working");
    return 0;
}

/* Shell command: Check I2C device status */
static int cmd_led_status(const struct shell *shell, size_t argc, char *argv[])
{
    shell_print(shell, "Checking I2C device status...");

    /* Get I2C device */
    const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    
    shell_print(shell, "I2C1 device pointer: %p", i2c_dev);
    
    if (i2c_dev == NULL) {
        shell_error(shell, "I2C1 device pointer is NULL");
        return -ENODEV;
    }

    if (!device_is_ready(i2c_dev)) {
        shell_error(shell, "I2C1 device not ready");
        return -ENODEV;
    }

    shell_print(shell, "I2C1 device is ready");
    shell_print(shell, "Device name: %s", i2c_dev->name);
    
    /* Try to get device tree info */
    const struct device *dt_dev = DEVICE_DT_GET_OR_NULL(DT_NODELABEL(i2c1));
    if (dt_dev == NULL) {
        shell_error(shell, "I2C1 device tree node not found");
        return -ENODEV;
    }

    shell_print(shell, "I2C1 device tree node found");
    return 0;
}

/* Shell command: Demo LED patterns */
static int cmd_led_demo(const struct shell *shell, size_t argc, char *argv[])
{
    int ret;
    int i;

    shell_print(shell, "Starting LED demo...");

    /* Initialize LED controller */
    ret = ktd2026_init();
    if (ret < 0) {
        shell_error(shell, "LED init failed: %d", ret);
        return ret;
    }

    /* Demo 1: Turn on each LED one by one */
    shell_print(shell, "Demo 1: Turning on LEDs one by one");
    for (i = 1; i <= 6; i++) {
        ret = ktd2026_set_led_current(i, 15); /* Medium brightness */
        if (ret < 0) {
            shell_error(shell, "Failed to set LED %d current: %d", i, ret);
            continue;
        }
        
        ret = ktd2026_set_led_enable(i, true);
        if (ret < 0) {
            shell_error(shell, "Failed to turn on LED %d: %d", i, ret);
            continue;
        }
        
        shell_print(shell, "LED %d on", i);
        k_sleep(K_MSEC(500));
        
        ret = ktd2026_set_led_enable(i, false);
        if (ret < 0) {
            shell_error(shell, "Failed to turn off LED %d: %d", i, ret);
        }
    }

    /* Demo 2: Flash pattern */
    shell_print(shell, "Demo 2: Flash pattern");
    ret = ktd2026_set_led_current(1, 20);
    if (ret == 0) {
        ret = ktd2026_set_flash_period(10); /* Medium flash rate */
        if (ret == 0) {
            ret = ktd2026_set_flash_duty(3); /* 50% duty cycle */
            if (ret == 0) {
                ret = ktd2026_set_timer_control(0, true);
                if (ret == 0) {
                    ret = ktd2026_set_led_enable(1, true);
                    if (ret == 0) {
                        shell_print(shell, "LED 1 flashing for 3 seconds");
                        k_sleep(K_MSEC(3000));
                        ktd2026_set_led_enable(1, false);
                        ktd2026_set_timer_control(0, false);
                    }
                }
            }
        }
    }

    /* Demo 3: All LEDs on with different brightness */
    shell_print(shell, "Demo 3: All LEDs with different brightness");
    for (i = 1; i <= 6; i++) {
        ktd2026_set_led_current(i, i * 5); /* Increasing brightness */
        ktd2026_set_led_enable(i, true);
    }
    k_sleep(K_MSEC(2000));
    
    /* Turn all off */
    for (i = 1; i <= 6; i++) {
        ktd2026_set_led_enable(i, false);
    }

    shell_print(shell, "LED demo completed");
    return 0;
}

/* Shell command definitions */
SHELL_STATIC_SUBCMD_SET_CREATE(led_subcmds,
    SHELL_CMD(init, NULL, "Initialize LED controller", cmd_led_init),
    SHELL_CMD(on, NULL, "Turn LED on\nUsage: led_on <led_number>", cmd_led_on),
    SHELL_CMD(off, NULL, "Turn LED off\nUsage: led_off <led_number>", cmd_led_off),
    SHELL_CMD(set, NULL, "Set LED current\nUsage: led_set <led_number> <current>", cmd_led_set),
    SHELL_CMD(flash, NULL, "Set LED flash\nUsage: led_flash <led_number> <period> <duty>", cmd_led_flash),
    SHELL_CMD(read, NULL, "Read register\nUsage: led_read <register>", cmd_led_read),
    SHELL_CMD(scan, NULL, "Scan I2C bus for devices", cmd_led_scan),
    SHELL_CMD(test_i2c, NULL, "Test I2C communication with KTD2026", cmd_led_test_i2c),
    SHELL_CMD(status, NULL, "Check I2C device status", cmd_led_status),
    SHELL_CMD(demo, NULL, "Run LED demo patterns", cmd_led_demo),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(led, &led_subcmds, "LED test commands", NULL);


