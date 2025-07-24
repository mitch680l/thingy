#include "lte_helper.h"
#include "mqtt_connection.h"
#include "heartbeat.h"
#include "shell_commands.h"
#include "fota.h"
LOG_MODULE_REGISTER(lte, LOG_LEVEL_INF);
bool update_lte_info = false;
char json_payload_lte[512] = "NO LTE";
bool publish_lte_info = false;


K_SEM_DEFINE(lte_connected, 0, 1);
const char *lookup_operator_name(const char *mccmnc)
{
    if (mccmnc == NULL || strlen(mccmnc) < 5)
        return "Invalid Operator Code";

    for (int i = 0; i < sizeof(operator_table) / sizeof(operator_table[0]); i++) {
        if (strcmp(operator_table[i].mccmnc, mccmnc) == 0) {
            return operator_table[i].name;
        }
    }
    return "Uknown Operator";
}

void pack_lte_data(void)
{
    enum modem_info;
    LOG_INF("Preparing to print LTE data");
    int ret;
    char lte_rsp[20] = "uknown";
    char lte_area[20] = "uknown";
    char lte_operator[20] = "uknown";
    char lte_cell_id[20] = "uknown";
    const char *lte_operator_decoded;
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
        LOG_ERR("FAILED TO GET OPERATOR.");
    }
    lte_operator_decoded = lookup_operator_name(lte_operator);
    ret = modem_info_string_get(MODEM_INFO_CELLID, lte_cell_id, sizeof(lte_cell_id));
    if (ret < 0) {
        LOG_ERR("Failed to get cell ID: %d", ret);
    }
    
    int len = snprintf(json_payload_lte, sizeof(json_payload_lte),
        "{"
          "\"RSRP\":\"%s\","
          "\"AreaCode\":\"%s\","
          "\"Operator\":\"%s\","
          "\"CellID\":\"%s\","
        "}",
        lte_rsp,
        lte_area,
        lte_operator_decoded,
        lte_cell_id
    );
    
    if (len < 0) {
        LOG_ERR("Failed to format LTE JSON: %d", len);
        return;
    } else if ((size_t)len >= sizeof(json_payload_lte)) {  // Fixed: proper cast
        LOG_WRN("LTE JSON truncated (%d bytes needed)", len);
    }
}

void lte_handler(const struct lte_lc_evt *const evt) {
    switch (evt->type) {
        case LTE_LC_EVT_NW_REG_STATUS:
            /* Only proceed once registered (home or roaming) */
            if ((evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME) || (evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING)) 
            {
                LOG_INF("Network registration status: %s",
                    evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ?
                    "Connected - home network" :
                    "Connected - roaming");
                k_sem_give(&lte_connected);
                
                if (current_state == FOTA_IDLE) {
                    set_state(FOTA_CONNECTED, 0);
                }
            }
            else 
            {
                if (current_state == FOTA_CONNECTED) {
                    LOG_INF("DISCONNECTED FROM LTE NETWORK WHILE IN FOTA_CONNECTED STATE");
                    set_state(FOTA_IDLE, 0);
                }
            }
            break;
        case LTE_LC_EVT_RRC_UPDATE:
            LOG_INF("RRC mode: %s", evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ? "Connected" : "Idle");
            if (evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED) {
                if (current_state == FOTA_IDLE) {
                    set_state(FOTA_CONNECTED, 0);
                }
                heartbeat_config(HB_COLOR_GREEN, 1, 500);
            } 
            else {
                if (current_state == FOTA_DOWNLOADING) {
                    set_state(FOTA_IDLE, 0);
                }
                heartbeat_config(HB_COLOR_WHITE, 1, 500);
            break;

        case LTE_LC_EVT_CELL_UPDATE:
            LOG_INF("LTE cell changed: Cell ID: %d, Tracking area: %d",
                evt->cell.id,
                evt->cell.tac);
            update_lte_info = true;
            break;

        case LTE_LC_EVT_LTE_MODE_UPDATE:
            switch (evt->lte_mode) {
                case LTE_LC_LTE_MODE_LTEM:
                    LOG_INF("LTE mode updated: LTE-M");
                    break;
                case LTE_LC_LTE_MODE_NBIOT:
                    LOG_INF("LTE mode updated: NB-IoT");
                    break;
                case LTE_LC_LTE_MODE_NONE:
                    LOG_INF("LTE mode updated: None (off)");
                    if (current_state == FOTA_CONNECTED || current_state == FOTA_DOWNLOADING) {
                        set_state(FOTA_IDLE, 0);
                    }
                    heartbeat_config(HB_COLOR_RED, 1, 500);
                    break;
                default:
                    LOG_INF("LTE mode updated: Unknown");
                    break;
                }
        break;

        default:
            break;
    }
}
}

int modem_configure(void)
{
	int err;
	err = nrf_modem_lib_init();
	if (err) {
		LOG_ERR("Failed to initialize the modem library, error: %d", err);
		return err;
	}
    fota_init(set_state);
    if (err) {
        printk("FOTA init failed: %d\n", err);
        return err;
    }
    provision_all_tls_credentials();
    lte_lc_system_mode_set(LTE_LC_SYSTEM_MODE_LTEM, 
                           LTE_LC_SYSTEM_MODE_PREFER_AUTO);

    lte_lc_psm_req(false);
    //lte_lc_edrx_req(false);
    lte_lc_func_mode_set(LTE_LC_FUNC_MODE_NORMAL);
	LOG_INF("Connecting to LTE network");
	err = lte_lc_connect_async(lte_handler);
	if (err) {
		LOG_ERR("Error in lte_lc_connect_async, error: %d", err);
		return err;
	}
    
	k_sem_take(&lte_connected, K_FOREVER);
	LOG_INF("Connected to LTE network");
	
	return 0;
}