/* sensor.h - header for sensor.c
 *
 * Example header for workqueue-based sensor JSON collection
 */

#ifndef SENSOR_H_
#define SENSOR_H_

#include <zephyr/kernel.h>



/* --- Public functions --- */

/**
 * @brief Initialize the sensor work item
 *
 * Sets up the delayable work and schedules the first run.
 */
void sensor_init(void);

/**
 * @brief Build JSON string for BMP390 into global buffer.
 */
void build_json_bmp390(void);

/**
 * @brief Build JSON string for IIS2MDC into global buffer.
 */
void build_json_iis2mdc(void);

/**
 * @brief Build JSON string for ICM42688 into global buffer.
 */
void build_json_icm42688(void);

#endif /* SENSOR_H_ */
