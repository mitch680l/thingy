#include "heartbeat.h"
#include <dk_buttons_and_leds.h>

#define HB_STACK_SIZE   512
#define HB_PRIORITY     10

static struct k_thread hb_thread;
static K_THREAD_STACK_DEFINE(hb_stack, HB_STACK_SIZE);

static volatile bool hb_running;
static uint8_t hb_color;
static uint8_t hb_pulses;
static uint32_t hb_pulse_dur;

/**
 * @brief Helper to set or clear LEDs based on color mask
 */
static inline void set_color(bool on)
{
    if (hb_color & HB_COLOR_RED) {
        dk_set_led(DK_LED1, on);
    }
    if (hb_color & HB_COLOR_GREEN) {
        dk_set_led(DK_LED2, on);
    }
    if (hb_color & HB_COLOR_BLUE) {
        dk_set_led(DK_LED3, on);
    }
}

/**
 * @brief Heartbeat thread: pulses in fixed 1s cycle
 */
static void heartbeat_thread_fn(void *p1, void *p2, void *p3)
{
    uint32_t total_on, off_time;
    
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);
    
    while (hb_running) {
        total_on = hb_pulses * hb_pulse_dur;
        off_time = hb_pulses ? ((1000U - total_on) / hb_pulses) : 1000U;

        for (uint8_t i = 0; i < hb_pulses && hb_running; i++) {
            set_color(true);
            k_msleep(hb_pulse_dur);
            set_color(false);
            k_msleep(off_time);
        }
        if (hb_pulses == 0) {
            k_msleep(1000U);
        }
    }
    set_color(false);
}

/**
 * @brief Configure and start heartbeat with specified parameters
 */
int heartbeat_config(uint8_t color, uint8_t pulses, uint32_t pulse_duration_ms)
{
    int err;
    
    if (!hb_running) {
        err = dk_leds_init();
        if (err) {
            return err;
        }
    } else {
        heartbeat_stop();
    }

    hb_color = color;
    hb_pulses = pulses;
    hb_pulse_dur = pulse_duration_ms;
    hb_running = true;

    k_thread_create(&hb_thread, hb_stack, HB_STACK_SIZE,
                    heartbeat_thread_fn,
                    NULL, NULL, NULL,
                    HB_PRIORITY, 0, K_NO_WAIT);
    return 0;
}

/**
 * @brief Stop the heartbeat and turn off LEDs
 */
void heartbeat_stop(void)
{
    if (!hb_running) {
        return;
    }
    hb_running = false;
    k_thread_join(&hb_thread, K_FOREVER);
    set_color(false);
}
