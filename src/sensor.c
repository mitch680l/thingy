#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/sys/printk.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "sensor.h"

/* --- Global JSON buffers --- */


/* --- Forward declarations --- */
static void sensor_work_handler(struct k_work *work);

/* --- Delayable work item --- */
K_WORK_DELAYABLE_DEFINE(sensor_work, sensor_work_handler);

/* --- Device handles (from DT) --- */
static const struct device *dev_bmp   = DEVICE_DT_GET(DT_NODELABEL(bmp));
static const struct device *dev_mag   = DEVICE_DT_GET(DT_NODELABEL(mag0));
static const struct device *dev_icm   = DEVICE_DT_GET(DT_NODELABEL(imu));

/* --- Initialization function --- */
void sensor_init(void)
{
    /* Check readiness */
    if (!device_is_ready(dev_bmp)) {
        printk("BMP390 device not ready!\n");
    }
    if (!device_is_ready(dev_mag)) {
        printk("IIS2MDC device not ready!\n");
    }
    if (!device_is_ready(dev_icm)) {
        printk("ICM42688 device not ready!\n");
    }

    /* Schedule first run after 30 seconds */
    k_work_schedule(&sensor_work, K_SECONDS(1));
}

/* --- Periodic workqueue handler --- */
static void sensor_work_handler(struct k_work *work)
{
    ARG_UNUSED(work);

    build_json_bmp390();
    build_json_iis2mdc();
    build_json_icm42688();

    printk("%s\n", json_bmp390);
    printk("%s\n", json_iis2mdc);
    printk("%s\n", json_icm42688);

    /* Re-schedule after 30 seconds */
    k_work_schedule(&sensor_work, K_SECONDS(30));
}

/* --- Helpers: build JSON into global buffers --- */

/* BMP390 (barometer) */
void build_json_bmp390(void)
{
    struct sensor_value press, temp;

    if (sensor_sample_fetch(dev_bmp) == 0) {
        sensor_channel_get(dev_bmp, SENSOR_CHAN_PRESS, &press);
        sensor_channel_get(dev_bmp, SENSOR_CHAN_AMBIENT_TEMP, &temp);

        snprintf(json_bmp390, sizeof(json_bmp390),
                 "{\"sensor\":\"bmp390\",\"pressure\":%d.%06d,\"temperature\":%d.%06d}",
                 press.val1, press.val2, temp.val1, temp.val2);
    } else {
        snprintf(json_bmp390, sizeof(json_bmp390),
                 "{\"sensor\":\"bmp390\",\"error\":\"fetch failed\"}");
    }
}

/* IIS2MDC (magnetometer) */
void build_json_iis2mdc(void)
{
    struct sensor_value mx, my, mz;

    if (sensor_sample_fetch(dev_mag) == 0) {
        sensor_channel_get(dev_mag, SENSOR_CHAN_MAGN_X, &mx);
        sensor_channel_get(dev_mag, SENSOR_CHAN_MAGN_Y, &my);
        sensor_channel_get(dev_mag, SENSOR_CHAN_MAGN_Z, &mz);

        snprintf(json_iis2mdc, sizeof(json_iis2mdc),
                 "{\"sensor\":\"iis2mdc\",\"mx\":%d.%06d,\"my\":%d.%06d,\"mz\":%d.%06d}",
                 mx.val1, mx.val2, my.val1, my.val2, mz.val1, mz.val2);
    } else {
        snprintf(json_iis2mdc, sizeof(json_iis2mdc),
                 "{\"sensor\":\"iis2mdc\",\"error\":\"fetch failed\"}");
    }
}

/* ICM-42688 (accelerometer + gyro) */
void build_json_icm42688(void)
{
    struct sensor_value ax, ay, az;
    struct sensor_value gx, gy, gz;

    if (sensor_sample_fetch(dev_icm) == 0) {
        sensor_channel_get(dev_icm, SENSOR_CHAN_ACCEL_X, &ax);
        sensor_channel_get(dev_icm, SENSOR_CHAN_ACCEL_Y, &ay);
        sensor_channel_get(dev_icm, SENSOR_CHAN_ACCEL_Z, &az);

        sensor_channel_get(dev_icm, SENSOR_CHAN_GYRO_X, &gx);
        sensor_channel_get(dev_icm, SENSOR_CHAN_GYRO_Y, &gy);
        sensor_channel_get(dev_icm, SENSOR_CHAN_GYRO_Z, &gz);

        snprintf(json_icm42688, sizeof(json_icm42688),
                 "{\"sensor\":\"icm42688\",\"ax\":%d.%06d,\"ay\":%d.%06d,\"az\":%d.%06d,"
                 "\"gx\":%d.%06d,\"gy\":%d.%06d,\"gz\":%d.%06d}",
                 ax.val1, ax.val2, ay.val1, ay.val2, az.val1, az.val2,
                 gx.val1, gx.val2, gy.val1, gy.val2, gz.val1, gz.val2);
    } else {
        snprintf(json_icm42688, sizeof(json_icm42688),
                 "{\"sensor\":\"icm42688\",\"error\":\"fetch failed\"}");
    }
}

