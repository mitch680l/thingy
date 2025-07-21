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


#define MQTT_MAX_STR_LEN 128
#define FOTA_CHECK_INTERVAL_MINUTES 5

extern char mqtt_client_id[MQTT_MAX_STR_LEN];               
extern int  mqtt_broker_port;
extern int interval_mqtt;
extern int interval_gnss;
extern int interval_main;
extern char firmware_filename[MQTT_MAX_STR_LEN];

void secure_memzero(void *v, size_t n);

int open_persistent_key();

int decrypt_config_field_data(const char *encrypted_data, size_t encrypted_len,
                              const char *iv,
                              const char *additional_data, size_t additional_len,
                              char *output_buf, size_t *output_len);
void test_decrypt();
void get_mqtt_username(char *output_buf, size_t *output_len);
void get_password(char *output_buf, size_t *output_len);
void get_http_host(char *output_buf, size_t *output_len);
void get_mqtt_host(char *output_buf, size_t *output_len);

void secure_memzero(void *v, size_t n);
#endif /* SHELL_MQTT_H */