/* Revised KTD2026EWE-TR Zephyr Shell Driver */
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

LOG_MODULE_REGISTER(led_shell, LOG_LEVEL_INF);

#define KTD2026_I2C_ADDR 0x30
static const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));

#define KTD2026_EN_RST          0x00
#define KTD2026_FLASH_PERIOD    0x01
#define KTD2026_FLASH_DUTY      0x02
#define KTD2026_LED_EN          0x03
#define KTD2026_TRISE_TFALL     0x04
#define KTD2026_LED1            0x05
#define KTD2026_LED2            0x06
#define KTD2026_LED3            0x07
#define KTD2026_TIMER_CTRL      0x08

#define KTD2026_LED_CURRENT_MAX 0xBF
#define KTD2026_FLASH_PERIOD_MAX 0x1F
#define KTD2026_FLASH_DUTY_MAX   0x07

static uint8_t led_en_state = 0;

static int ktd2026_write_reg(uint8_t reg, uint8_t value)
{
    uint8_t buf[2] = {reg, value};
    for (int i = 0; i < 3; i++) {
        int ret = i2c_write(i2c_dev, buf, sizeof(buf), KTD2026_I2C_ADDR);
        if (ret == 0) {
            LOG_DBG("Wrote reg 0x%02X = 0x%02X, ret=%d", reg, value, ret);
            return 0;
        }
        k_sleep(K_MSEC(5));
    }

    LOG_DBG("Wrote reg 0x%02X = 0x%02X, ret=%d", reg, value, ret);
    return -EIO;
}

static int ktd2026_read_reg(uint8_t reg, uint8_t *value)
{
    return i2c_write_read(i2c_dev, KTD2026_I2C_ADDR, &reg, 1, value, 1);
}

static int ktd2026_set_led_current(uint8_t led, uint8_t current)
{
    if (current > KTD2026_LED_CURRENT_MAX) current = KTD2026_LED_CURRENT_MAX;
    uint8_t reg = (led == 1) ? KTD2026_LED1 : (led == 2) ? KTD2026_LED2 : (led == 3) ? KTD2026_LED3 : 0xFF;
    if (reg == 0xFF) return -EINVAL;
    return ktd2026_write_reg(reg, current);
}

static int ktd2026_set_led_enable(uint8_t led, bool enable)
{
    if (led < 1 || led > 3) return -EINVAL;
    uint8_t bit = BIT(led - 1);
    led_en_state = enable ? (led_en_state | bit) : (led_en_state & ~bit);
    return ktd2026_write_reg(KTD2026_LED_EN, led_en_state);
}

static int ktd2026_set_flash_period(uint8_t period)
{
    if (period > KTD2026_FLASH_PERIOD_MAX) period = KTD2026_FLASH_PERIOD_MAX;
    return ktd2026_write_reg(KTD2026_FLASH_PERIOD, period);
}

static int ktd2026_set_flash_duty(uint8_t duty)
{
    if (duty > KTD2026_FLASH_DUTY_MAX) duty = KTD2026_FLASH_DUTY_MAX;
    return ktd2026_write_reg(KTD2026_FLASH_DUTY, duty);
}

static int ktd2026_set_timer_control(uint8_t timer_sel, bool enable)
{
    uint8_t value;
    if (ktd2026_read_reg(KTD2026_TIMER_CTRL, &value) < 0) return -EIO;
    value &= ~0x06;
    value |= (timer_sel << 1) & 0x06;
    value = enable ? (value | 0x01) : (value & ~0x01);
    return ktd2026_write_reg(KTD2026_TIMER_CTRL, value);
}

static int ktd2026_init(void)
{
    if (!device_is_ready(i2c_dev)) {
        LOG_ERR("I2C device not ready");
        return -ENODEV;
    }
    k_sleep(K_MSEC(1));
    if (ktd2026_write_reg(KTD2026_EN_RST, 0x00) < 0) return -EIO;
    k_sleep(K_MSEC(10));
    if (ktd2026_write_reg(KTD2026_LED_EN, 0x00) < 0) return -EIO;
    for (int i = 1; i <= 3; i++) {
        if (ktd2026_set_led_current(i, 0) < 0) return -EIO;
    }
    if (ktd2026_write_reg(KTD2026_TIMER_CTRL, 0x00) < 0) return -EIO;
    return 0;
}

/* Shell Commands */
static int cmd_led_init(const struct shell *shell, size_t argc, char *argv[]) {
    int ret = ktd2026_init();
    shell_print(shell, ret == 0 ? "LED controller initialized" : "Init failed: %d", ret);
    return ret;
}

static int cmd_led_on(const struct shell *shell, size_t argc, char *argv[]) {
    if (argc != 2) return -EINVAL;
    int led = atoi(argv[1]);
    return ktd2026_set_led_enable(led, true);
}

static int cmd_led_off(const struct shell *shell, size_t argc, char *argv[]) {
    if (argc != 2) return -EINVAL;
    int led = atoi(argv[1]);
    return ktd2026_set_led_enable(led, false);
}

static int cmd_led_set(const struct shell *shell, size_t argc, char *argv[]) {
    if (argc != 3) return -EINVAL;
    int led = atoi(argv[1]);
    int current = atoi(argv[2]);
    return ktd2026_set_led_current(led, current);
}

SHELL_STATIC_SUBCMD_SET_CREATE(led_subcmds,
    SHELL_CMD(init, NULL, "Initialize LED controller", cmd_led_init),
    SHELL_CMD(on, NULL, "Turn LED on", cmd_led_on),
    SHELL_CMD(off, NULL, "Turn LED off", cmd_led_off),
    SHELL_CMD(set, NULL, "Set LED current", cmd_led_set),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(led, &led_subcmds, "KTD2026 LED driver commands", NULL);


static int cmd_dfu_reboot(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    int err = boot_write_img_confirmed();
    if (err != 0) {
        shell_error(shell, "Failed to confirm image: %d", err);
        return err;
    }

    err = boot_set_pending(false);  // false = permanent
    if (err != 0) {
        shell_error(shell, "Failed to set boot pending: %d", err);
        return err;
    }

    shell_print(shell, "Rebooting into MCUboot for DFU...");
    k_sleep(K_MSEC(100)); // allow shell print to flush

    sys_reboot(SYS_REBOOT_COLD);
    return 0; // won't be reached
}

SHELL_CMD_REGISTER(dfu_reboot, NULL, "Reboot into MCUboot DFU mode", cmd_dfu_reboot);