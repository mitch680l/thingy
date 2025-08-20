#include "heartbeat.h"
#include "config.h"
#include "../drivers/led/led_driver.h"

extern struct ktd2026_device g_ktd;
extern struct ktd2026_device k_ktd;

#define KTD2026_REG_EN_RST        0x00
#define KTD2026_REG_FLASH_PERIOD  0x01
#define KTD2026_REG_FLASH_ON1     0x02
#define KTD2026_REG_FLASH_ON2     0x03
#define KTD2026_REG_CH_CTRL       0x04
#define KTD2026_REG_RAMP_RATE     0x05
#define KTD2026_REG_LED1_IOUT     0x06
#define KTD2026_REG_LED2_IOUT     0x07
#define KTD2026_REG_LED3_IOUT     0x08

#define KTD_CH_MODE_OFF   0x0
#define KTD_CH_MODE_PWM1  0x2
#define KTD_REG4(ch1, ch2, ch3) \
    ((((ch3) & 0x3) << 4) | (((ch2) & 0x3) << 2) | ((ch1) & 0x3))


#define KTD_REG0_FAST_ENABLE  0x7C  

#define IOUT_5MA_CODE  40



static void ktd2026_blink_common_init(struct ktd2026 *dev)
{
    static bool initialized_30 = false;
    static bool initialized_31 = false;
    bool *initialized = (dev->i2c_addr == 0x30) ? &initialized_30 : &initialized_31;

    if (*initialized) return;

    // Enable device
    (void)ktd2026_write_en_rst(dev, KTD_REG0_FAST_ENABLE);

    // Fastest ramp
    (void)ktd2026_write_ramp_rate(dev, 0x00);

    // 1 Hz period (≈1.024s, index 6)
    (void)ktd2026_write_flash_period(dev, 6);

    // 50% duty
    (void)ktd2026_write_flash_on1(dev, 128);

    // Leave Timer2 unused
    (void)ktd2026_write_flash_on2(dev, 0);

    // Default current
    (void)ktd2026_write_led1_iout(dev, IOUT_5MA_CODE);
    (void)ktd2026_write_led2_iout(dev, IOUT_5MA_CODE);
    (void)ktd2026_write_led3_iout(dev, IOUT_5MA_CODE);

    // All channels off initially
    (void)ktd2026_write_channel_ctrl(dev,
        KTD_REG4(KTD_CH_MODE_OFF, KTD_CH_MODE_OFF, KTD_CH_MODE_OFF));

    *initialized = true;
}

/* ============================================================
 *  Core blink programming
 * ============================================================ */
static void ktd2026_program_1hz_pwm1(struct ktd2026 *dev, uint8_t reg4_map)
{
    ktd2026_blink_common_init(dev);
    (void)ktd2026_write_channel_ctrl(dev, reg4_map);
}

/* ============================================================
 *  Helper: generate Reg4 map for RGB mix
 * ============================================================ */
#define CH_ON(x)  ((x) ? KTD_CH_MODE_PWM1 : KTD_CH_MODE_OFF)

static void ktd2026_blink_color(struct ktd2026 *dev,
                                bool r, bool g, bool b)
{
    uint8_t reg4 = KTD_REG4(CH_ON(r), CH_ON(g), CH_ON(b));
    ktd2026_program_1hz_pwm1(dev, reg4);
}

/* ============================================================
 *  Public API for 0x30 device
 * ============================================================ */
void ktd2026_blink_red_1hz_30(void)    { ktd2026_blink_color(&g_ktd_30, true,  false, false); }
void ktd2026_blink_green_1hz_30(void)  { ktd2026_blink_color(&g_ktd_30, false, true,  false); }
void ktd2026_blink_blue_1hz_30(void)   { ktd2026_blink_color(&g_ktd_30, false, false, true ); }

void ktd2026_blink_yellow_1hz_30(void) { ktd2026_blink_color(&g_ktd_30, true,  true,  false); }
void ktd2026_blink_cyan_1hz_30(void)   { ktd2026_blink_color(&g_ktd_30, false, true,  true ); }
void ktd2026_blink_magenta_1hz_30(void){ ktd2026_blink_color(&g_ktd_30, true,  false, true ); }
void ktd2026_blink_white_1hz_30(void)  { ktd2026_blink_color(&g_ktd_30, true,  true,  true ); }

/* ============================================================
 *  Public API for 0x31 device
 * ============================================================ */
void ktd2026_blink_red_1hz_31(void)    { ktd2026_blink_color(&g_ktd_31, true,  false, false); }
void ktd2026_blink_green_1hz_31(void)  { ktd2026_blink_color(&g_ktd_31, false, true,  false); }
void ktd2026_blink_blue_1hz_31(void)   { ktd2026_blink_color(&g_ktd_31, false, false, true ); }

void ktd2026_blink_yellow_1hz_31(void) { ktd2026_blink_color(&g_ktd_31, true,  true,  false); }
void ktd2026_blink_cyan_1hz_31(void)   { ktd2026_blink_color(&g_ktd_31, false, true,  true ); }
void ktd2026_blink_magenta_1hz_31(void){ ktd2026_blink_color(&g_ktd_31, true,  false, true ); }
void ktd2026_blink_white_1hz_31(void)  { ktd2026_blink_color(&g_ktd_31, true,  true,  true ); }