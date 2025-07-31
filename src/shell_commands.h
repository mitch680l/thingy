#ifndef SHELL_MQTT_H
#define SHELL_MQTT_H

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psa/protected_storage.h>
#include <psa/crypto.h>
#include <string.h>
#include <tfm_ns_interface.h>


#define GPS_READ_BUFFER_SIZE 126  
#define GPS_STARTUP_DELAY_MS 2000  
#define GPS_CONFIG_TIMEOUT_MS 500  
#define GPS_MAX_CONFIG_ATTEMPTS 3

#define MQTT_MAX_STR_LEN 128


extern char mqtt_client_id[MQTT_MAX_STR_LEN];               
extern int  mqtt_broker_port;
extern int interval_mqtt;
extern int fota_interval_ms;
extern int gps_target_rate;
extern char firmware_filename[MQTT_MAX_STR_LEN];

const char *get_config(const char *aad);
void secure_memzero(void *v, size_t n);
void test_decrypt_all_config_entries(void);
int open_persistent_key();
void parse_encrypted_blob(void);
int decrypt_config_field_data(const char *encrypted_data, size_t encrypted_len,
                              const char *iv,
                              const char *additional_data, size_t additional_len,
                              char *output_buf, size_t *output_len);


void secure_memzero(void *v, size_t n);
#endif /* SHELL_MQTT_H */