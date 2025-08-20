#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <dk_buttons_and_leds.h>
#include <nrf_modem_gnss.h>
#include <nrf_modem_at.h>
#include <zephyr/net/mqtt.h>
#include <modem/modem_info.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include "config.h"
#include "modem_info.h"
LOG_MODULE_REGISTER(lte_packer, LOG_LEVEL_INF);




/* =========================
 *  Operator Lookup Table
 * ========================= */
struct operator_entry {
    const char *mccmnc;
    const char *name;
};

static const struct operator_entry operator_table[] = {
    { "310260", "T-Mobile" },
    { "310410", "AT&T"     },
    { "311480", "Verizon"  },
    { "23415",  "Vodafone UK" },
    /* Add more MCC/MNC codes as needed */
};

const char *lookup_operator_name(const char *mccmnc)
{
    if (mccmnc == NULL || strlen(mccmnc) < 5) {
        return "Invalid Operator Code";
    }

    for (int i = 0; i < ARRAY_SIZE(operator_table); i++) {
        if (strcmp(operator_table[i].mccmnc, mccmnc) == 0) {
            return operator_table[i].name;
        }
    }
    return "Unknown Operator";
}

/* =========================
 *  LTE JSON Packing
 * ========================= */
void pack_lte_data(void)
{
    int ret, len;
    char lte_rsp[LTE_BUF_LEN]     = "unknown";
    char lte_area[LTE_BUF_LEN]    = "unknown";
    char lte_operator[LTE_BUF_LEN]= "unknown";
    char lte_cell_id[LTE_BUF_LEN] = "unknown";
    const char *lte_operator_decoded;

    //LOG_INF("Preparing to pack LTE data");

    ret = modem_info_init();
    if (ret < 0) {
        LOG_ERR("Failed to initialize modem info: %d", ret);
        return;
    }

    ret = modem_info_string_get(MODEM_INFO_RSRP, lte_rsp, sizeof(lte_rsp));
    if (ret < 0) {
        LOG_ERR("Failed to get LTE RSRP: %d", ret);
    }

    ret = modem_info_string_get(MODEM_INFO_AREA_CODE, lte_area, sizeof(lte_area));
    if (ret < 0) {
        LOG_ERR("Failed to get tracking area code: %d", ret);
    }

    ret = modem_info_string_get(MODEM_INFO_OPERATOR, lte_operator, sizeof(lte_operator));
    if (ret < 0) {
        LOG_ERR("Failed to get operator: %d", ret);
    }

    lte_operator_decoded = lookup_operator_name(lte_operator);

    ret = modem_info_string_get(MODEM_INFO_CELLID, lte_cell_id, sizeof(lte_cell_id));
    if (ret < 0) {
        LOG_ERR("Failed to get cell ID: %d", ret);
    }

    len = snprintf(json_payload_lte, sizeof(json_payload_lte),
        "{"
          "\"RSRP\":\"%s\","
          "\"AreaCode\":\"%s\","
          "\"Operator\":\"%s\","
          "\"CellID\":\"%s\""
        "}",
        lte_rsp,
        lte_area,
        lte_operator_decoded,
        lte_cell_id
    );

    if (len < 0) {
        LOG_ERR("Failed to format LTE JSON: %d", len);
        return;
    } else if ((size_t)len >= sizeof(json_payload_lte)) {
        LOG_WRN("LTE JSON truncated (%d bytes needed)", len);
    }

}

/* =========================
 *  Work Queue Setup
 * ========================= */
static struct k_work_delayable lte_work;

static void lte_work_handler(struct k_work *work)
{
    ARG_UNUSED(work);

    /* Collect and pack LTE info */
    pack_lte_data();

    /* Re-schedule itself */
    k_work_reschedule(&lte_work, LTE_DATA_INTERVAL);
}

void lte_data_start(void)
{
    k_work_init_delayable(&lte_work, lte_work_handler);

    /* Start immediately */
    k_work_schedule(&lte_work, K_NO_WAIT);

    LOG_INF("LTE data work started (interval: %d s)",
        k_ticks_to_ms_floor32(LTE_DATA_INTERVAL.ticks) / 1000);
}

