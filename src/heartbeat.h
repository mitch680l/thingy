/* heartbeat.h */
#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include <dk_buttons_and_leds.h>
#include <zephyr/kernel.h>
#include <sys/types.h>

/* Color bitmask definitions */
#define HB_COLOR_OFF     0
#define HB_COLOR_RED     (1 << 0)
#define HB_COLOR_GREEN   (1 << 1)
#define HB_COLOR_BLUE    (1 << 2)
#define HB_COLOR_YELLOW  (HB_COLOR_RED   | HB_COLOR_GREEN)
#define HB_COLOR_CYAN    (HB_COLOR_GREEN | HB_COLOR_BLUE)
#define HB_COLOR_MAGENTA (HB_COLOR_RED   | HB_COLOR_BLUE)
#define HB_COLOR_WHITE   (HB_COLOR_RED   | HB_COLOR_GREEN | HB_COLOR_BLUE)

/* Configure and start a new heartbeat */
int heartbeat_config(uint8_t color, uint8_t pulses, uint32_t pulse_duration_ms);
/* Stop and dump the current heartbeat */
void heartbeat_stop(void);

#endif /* HEARTBEAT_H */