#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>
#include <math.h>
#include "led_driver.h"

//
// ┌────────────────────────────┐
// │ INITIALIZATION             │
// └────────────────────────────┘
//


struct ktd2026_device g_ktd;

int ktd2026_init(struct ktd2026_device *ktd_dev, const struct device *i2c_dev, uint16_t i2c_addr)
{
    if (!ktd_dev || !i2c_dev) {
        return -EINVAL;
    }

    if (!device_is_ready(i2c_dev)) {
        return -ENODEV;
    }

    ktd_dev->i2c_dev = i2c_dev;
    ktd_dev->i2c_addr = i2c_addr;

    return 0;
}

//
// ┌────────────────────────────┐
// │ LOW-LEVEL I2C ACCESS       │
// └────────────────────────────┘
//

static int ktd2026_write_reg(struct ktd2026_device *ktd_dev, uint8_t reg, uint8_t data)
{
    uint8_t buf[2] = { reg, data };
    return i2c_write(ktd_dev->i2c_dev, buf, sizeof(buf), ktd_dev->i2c_addr);
}


//
// ┌────────────────────────────┐
// │ PER-REGISTER WRITE HELPERS │
// └────────────────────────────┘
//

int ktd2026_write_en_rst(struct ktd2026_device *ktd_dev, uint8_t val)     { return ktd2026_write_reg(ktd_dev, KTD2026_REG_EN_RST, val); }
int ktd2026_write_flash_period(struct ktd2026_device *ktd_dev, uint8_t v) { return ktd2026_write_reg(ktd_dev, KTD2026_REG_FLASH_PERIOD, v); }
int ktd2026_write_flash_on1(struct ktd2026_device *ktd_dev, uint8_t val)  { return ktd2026_write_reg(ktd_dev, KTD2026_REG_FLASH_ON1, val); }
int ktd2026_write_flash_on2(struct ktd2026_device *ktd_dev, uint8_t val)  { return ktd2026_write_reg(ktd_dev, KTD2026_REG_FLASH_ON2, val); }
int ktd2026_write_channel_ctrl(struct ktd2026_device *ktd_dev, uint8_t v) { return ktd2026_write_reg(ktd_dev, KTD2026_REG_CH_CTRL, v); }
int ktd2026_write_ramp_rate(struct ktd2026_device *ktd_dev, uint8_t val)  { return ktd2026_write_reg(ktd_dev, KTD2026_REG_RAMP_RATE, val); }
int ktd2026_write_led1_iout(struct ktd2026_device *ktd_dev, uint8_t val)  { return ktd2026_write_reg(ktd_dev, KTD2026_REG_LED1_IOUT, val); }
int ktd2026_write_led2_iout(struct ktd2026_device *ktd_dev, uint8_t val)  { return ktd2026_write_reg(ktd_dev, KTD2026_REG_LED2_IOUT, val); }
int ktd2026_write_led3_iout(struct ktd2026_device *ktd_dev, uint8_t val)  { return ktd2026_write_reg(ktd_dev, KTD2026_REG_LED3_IOUT, val); }


// ─────────────────────────────────────────────
// Period lookup table (Reg1 values → seconds)
// ─────────────────────────────────────────────
static float ktd2026_period_table[128];
static bool period_table_initialized = false;

static void ktd2026_init_period_table(void)
{
    if (period_table_initialized) return;

    for (int i = 0; i <= 126; ++i) {
        ktd2026_period_table[i] = 0.128f + i * 0.128f;
    }

    // One-shot mode: 127
    ktd2026_period_table[127] = -1.0f;
    period_table_initialized = true;
}

// ─────────────────────────────────────────────
// Set Reg1 — Flash Period
// ─────────────────────────────────────────────
int ktd2026_set_flash_period(struct ktd2026_device *ktd_dev, float period_sec, enum ktd2026_ramp_mode ramp_mode)
{
    ktd2026_init_period_table();

    uint8_t best_index = 0;
    float best_diff = 1000.0f;

    for (uint8_t i = 0; i < 127; ++i) {
        float diff = fabsf(period_sec - ktd2026_period_table[i]);
        if (diff < best_diff) {
            best_diff = diff;
            best_index = i;
        }
    }

    // One-shot if long duration
    if (period_sec > 16.3f)
        best_index = 127;

    // Add MSB for ramp mode
    uint8_t reg1_val = best_index & 0x7F;
    if (ramp_mode == KTD2026_RAMP_LOG)
        reg1_val |= 0x80;

    return ktd2026_write_flash_period(ktd_dev, reg1_val);
}

// ─────────────────────────────────────────────
// Set Reg2 — Flash ON Time for timer 1
// ─────────────────────────────────────────────
int ktd2026_set_flash_on1(struct ktd2026_device *ktd_dev, float percent)
{
    if (percent < 0.0f) percent = 0.0f;
    if (percent > 99.6f) percent = 99.6f;

    uint8_t reg_val = (uint8_t)roundf(percent * 255.0f / 100.0f);
    return ktd2026_write_flash_on1(ktd_dev, reg_val);
}

// ─────────────────────────────────────────────
// Set Reg3 — Flash ON Time for timer 2
// ─────────────────────────────────────────────
int ktd2026_set_flash_on2(struct ktd2026_device *ktd_dev, float percent)
{
    if (percent < 0.0f) percent = 0.0f;
    if (percent > 99.6f) percent = 99.6f;

    uint8_t reg_val = (uint8_t)roundf(percent * 255.0f / 100.0f);
    return ktd2026_write_flash_on2(ktd_dev, reg_val);
}

// ─────────────────────────────────────────────
// Set Reg4 — LED ENABLE
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// Set Reg5 - RAMP TIME
// ─────────────────────────────────────────────
int ktd2026_set_ramp_times(struct ktd2026_device *ktd_dev, uint8_t rise_index, uint8_t fall_index)
{
    if (rise_index > 15 || fall_index > 15) {
        return -EINVAL;
    }

    // Reg5 = [7:4] Tfall | [3:0] Trise
    uint8_t reg5 = ((fall_index & GENMASK(3, 0)) << 4) | (rise_index & GENMASK(3, 0));
    return ktd2026_write_ramp_rate(ktd_dev, reg5);
}

// ─────────────────────────────────────────────
// Set Reg6-8 - LED CURRENT
// ─────────────────────────────────────────────
int ktd2026_set_led_current(struct ktd2026_device *ktd_dev, uint8_t led_index, float current_ma)
{
    if (led_index < 1 || led_index > 3) {
        return -EINVAL;
    }

    if (current_ma < 0.125f) {
        current_ma = 0.125f;
    } else if (current_ma > 24.0f) {
        current_ma = 24.0f;
    }

    // Convert mA to register value (0–192) with 0.125mA steps
    uint8_t reg_val = (uint8_t)roundf(current_ma / 0.125f);
    if (reg_val > 255) reg_val = 255;  // Clamp to max (some values > 192 still work as 24mA)

    uint8_t reg_addr = KTD2026_REG_LED1_IOUT + (led_index - 1);

    return ktd2026_write_reg(ktd_dev, reg_addr, reg_val);
}