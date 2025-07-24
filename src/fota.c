/*
 * Copyright (c) 2019-2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "fota.h"


#ifdef CONFIG_FOTA_USE_HTTPS
#include <nrf_socket.h>
#define TLS_SEC_TAG 42
#define SEC_TAG (TLS_SEC_TAG)
#else
#define SEC_TAG (-1)
#endif

/* Static variables */
enum fota_state current_state = FOTA_IDLE;
fota_callback_t state_callback = NULL;
struct k_work fota_work;

char fota_host[MQTT_MAX_STR_LEN];
size_t fota_host_len = sizeof(fota_host);

LOG_MODULE_REGISTER(fota, LOG_LEVEL_INF);

void set_state(enum fota_state new_state, int error)
{
    if (current_state == new_state) {
        return;
    }

    current_state = new_state;
    
    LOG_INF("FOTA state changed to %d (error: %d)\n", new_state, error);

    if (state_callback) {
        state_callback(new_state, error);
    }
}



void fota_dl_handler(const struct fota_download_evt *evt)
{
    switch (evt->id) {
    case FOTA_DOWNLOAD_EVT_ERROR:
        LOG_INF("FOTA download error\n");
        set_state(FOTA_CONNECTED, -EIO);
        break;
    case FOTA_DOWNLOAD_EVT_FINISHED:
        LOG_INF("FOTA download finished\n");
        secure_memzero(fota_host, sizeof(fota_host));
        set_state(FOTA_READY_TO_APPLY, 0);
        fota_apply_update();
        break;
    case FOTA_DOWNLOAD_EVT_PROGRESS:
        LOG_INF("FOTA download progress: %d%%\n", evt->progress);
        break;
    default:
        break;
    }
}


int download_firmware(void)
{
    int err;


    err = fota_download_init(fota_dl_handler);
    if (err) {
        LOG_INF("fota_download_init() failed, err %d\n", err);
        return err;
    }

    

    
    get_http_host(fota_host, &fota_host_len);
    LOG_INF("Starting firmware download from %s%s\n", fota_host, firmware_filename);

    err = fota_download_start(fota_host, firmware_filename, SEC_TAG, 0, 0);
    if (err) {
        LOG_INF("fota_download_start() failed, err %d\n", err);
        // Clean up before returning
        secure_memzero(fota_host, sizeof(fota_host));
        return err;
    }

    return 0;
}

void fota_work_cb(struct k_work *work)
{
    int err;

    ARG_UNUSED(work);

    switch (current_state) {
    case FOTA_DOWNLOADING:
        err = download_firmware();
        if (err) {
            set_state(FOTA_CONNECTED, err);
        }
        break;
    case FOTA_APPLYING:
        LOG_INF("Applying firmware update - rebooting...\n");
        lte_lc_power_off();
        sys_reboot(SYS_REBOOT_WARM);
        break;
    default:
        break;
    }
}

/* Public API Implementation */

int fota_init(fota_callback_t callback)
{
   
    state_callback = callback;

    boot_write_img_confirmed();

    k_work_init(&fota_work, fota_work_cb);

    return 0;
}

int check_fota_server(void)
{


    switch (current_state) {
    case FOTA_IDLE:
        break;
        
    case FOTA_CONNECTED:
        set_state(FOTA_DOWNLOADING, 0);
        LOG_INF("Checking for FOTA updates...\n");
        k_work_submit(&fota_work);
        break;
        
    case FOTA_DOWNLOADING:
        LOG_INF("FOTA download already in progress\n");
        return -EBUSY;
        
    case FOTA_READY_TO_APPLY:
        LOG_INF("FOTA update ready - call fota_apply_update()\n");
        return 0;
        
    case FOTA_APPLYING:
        LOG_INF("FOTA update being applied\n");
        return -EBUSY;
        
    default:
        return -EINVAL;
    }

    return 0;
}

int fota_apply_update(void)
{
    if (current_state != FOTA_READY_TO_APPLY) {
        return -EPERM;
    }

    set_state(FOTA_APPLYING, 0);
    k_work_submit(&fota_work);

    return 0;
}

enum fota_state fota_get_state(void)
{
    return current_state;
}

int fota_cancel(void)
{
    switch (current_state) {
    case FOTA_DOWNLOADING:
        /* Cancel the download */
        fota_download_cancel();
        set_state(FOTA_CONNECTED, 0);
        break;
    case FOTA_READY_TO_APPLY:
        /* Just reset state, no actual download to cancel */
        set_state(FOTA_CONNECTED, 0);
        break;
    default:
        return -EPERM;
    }

    return 0;
}