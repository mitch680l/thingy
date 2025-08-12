#include "heartbeat.h"
#include "config.h"
#include "../drivers/led/led_driver.h"

extern struct ktd2026_device g_ktd;


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



static void ktd2026_blink_common_init(void)
{
    static bool initialized;

    if (initialized) return;

    // Enable device, fast ramp scale
    (void)ktd2026_write_en_rst(&g_ktd, KTD_REG0_FAST_ENABLE);

    // Fastest rise/fall (base rate = 0; global scale is in Reg0)
    (void)ktd2026_write_ramp_rate(&g_ktd, 0x00);

    // 1 Hz ≈ 1.024 s → index 6; linear ramp (MSB=0)
    (void)ktd2026_write_flash_period(&g_ktd, 6);

    // 50% duty on Timer1
    (void)ktd2026_write_flash_on1(&g_ktd, 128);

    // Leave Timer2 unused
    (void)ktd2026_write_flash_on2(&g_ktd, 0);

    // Default current for all channels; unused channels can be 0 if you prefer
    (void)ktd2026_write_led1_iout(&g_ktd, IOUT_5MA_CODE);
    (void)ktd2026_write_led2_iout(&g_ktd, IOUT_5MA_CODE);
    (void)ktd2026_write_led3_iout(&g_ktd, IOUT_5MA_CODE);

    // Start with all channels OFF; blink functions will map a single channel to PWM1
    (void)ktd2026_write_channel_ctrl(&g_ktd, KTD_REG4(KTD_CH_MODE_OFF, KTD_CH_MODE_OFF, KTD_CH_MODE_OFF));

    initialized = true;
}


static void ktd2026_program_1hz_pwm1(uint8_t reg4_map)
{
    ktd2026_blink_common_init();
    (void)ktd2026_write_channel_ctrl(&g_ktd, reg4_map);
}

void ktd2026_blink_red_1hz(void)
{
    ktd2026_program_1hz_pwm1(KTD_REG4(KTD_CH_MODE_PWM1, KTD_CH_MODE_OFF,  KTD_CH_MODE_OFF));
}

void ktd2026_blink_green_1hz(void)
{

    ktd2026_program_1hz_pwm1(KTD_REG4(KTD_CH_MODE_OFF,  KTD_CH_MODE_PWM1, KTD_CH_MODE_OFF));
}

void ktd2026_blink_blue_1hz(void)
{
    ktd2026_program_1hz_pwm1(KTD_REG4(KTD_CH_MODE_OFF,  KTD_CH_MODE_OFF,  KTD_CH_MODE_PWM1));
}
