#ifndef MODEM_INFO_H_
#define MODEM_INFO_H_

#include <zephyr/kernel.h>

/* =========================
 *  Configurable Interval
 * ========================= */

/**
 * @brief Interval for LTE data reporting work
 *
 * Change this macro to adjust reporting frequency.
 * Default: 60 seconds
 */
#define LTE_DATA_INTERVAL  K_SECONDS(60)

/* =========================
 *  API Prototypes
 * ========================= */

/**
 * @brief Look up operator name by MCC/MNC code
 *
 * @param mccmnc MCC/MNC string (e.g. "310260")
 * @return Operator name string or "Unknown Operator"
 */
const char *lookup_operator_name(const char *mccmnc);

/**
 * @brief Collect LTE modem info and build JSON payload
 *
 * JSON is stored in a static buffer inside the module and logged.
 */
void pack_lte_data(void);

/**
 * @brief Start periodic LTE data work
 *
 * Schedules `pack_lte_data()` as a work queue item that reschedules
 * itself every LTE_DATA_INTERVAL.
 */
void lte_data_start(void);

#endif /* LTE_PACKER_H_ */
