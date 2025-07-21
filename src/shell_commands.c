
#include "shell_commands.h"
char mqtt_client_id[MQTT_MAX_STR_LEN] = "nrid4148";               
char firmware_filename[MQTT_MAX_STR_LEN] = "blinky_2.signed.bin";
int  mqtt_broker_port = 8883;
int interval_mqtt = 1000;
int interval_gnss = 1000;
int interval_main = 1000;
psa_key_id_t my_key_id = 0x00000005;
psa_key_handle_t my_key_handle;
/* call this before you read them */
#define PROVISIONING_SUCCESS            (0)
#define PROVISIONING_ERROR_CRYPTO_INIT  (-100)
#define PROVISIONING_ERROR_KEY_IMPORT   (-101)
#define PROVISIONING_ERROR_KEY_OPEN     (-102)
#define PROVISIONING_ERROR_ENCRYPT      (-103)
#define PROVISIONING_ERROR_DECRYPT      (-104)
#define PROVISIONING_ERROR_IV_GEN       (-105)
#define PROVISIONING_ERROR_VERIFICATION (-106)
#define PROVISIONING_ERROR_KEY_DESTROY  (-107)
#define PROVISIONING_ERROR_BUFFER_SIZE  (-108)
#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE (100)
#define NRF_CRYPTO_EXAMPLE_AES_BLOCK_SIZE (16)
#define NRF_CRYPTO_EXAMPLE_AES_IV_SIZE (12)
#define NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE (35)
#define NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH (16)
#define AES_KEY_SIZE (32)  // 256-bit key

LOG_MODULE_REGISTER(aes_gcm, LOG_LEVEL_DBG);
/*Hostname(MQTT)*/
static uint8_t config_iv_1[12] = {0x97, 0xd4, 0xbf, 0x13, 0x8c, 0x0c, 0x04, 0x72, 0x86, 0xeb, 0xb9, 0xb4};

static uint8_t encrypted_config_1[57] = {0xcd, 0x6a, 0x92, 0xb4, 0xbe, 0xe9, 0xd1, 0x8d, 0x94, 0x38, 0x26, 0xbc, 0x8d, 0x51, 0x71, 0x1a, 0x92, 0x1f, 0x0a, 0x1a, 0xb1, 0x3a, 0xcb, 
0x7c, 0xb5, 0x37, 0x92, 0x4b, 0x40, 0x32, 0x7c, 0x38, 0x5d, 0x02, 0xb0, 0x30, 0x82, 0x5a, 0x4a, 0xfd, 0x7b, 0x1f, 0xac, 0x22, 0xee, 0x3a, 0x8c, 0xe9, 0x29, 0xbe, 0x72, 0x45, 0x77, 0x40, 0x28, 0x4b, 0xaa};

static uint8_t additional_auth_data_1[19] = {0x46, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x71, 0x74, 0x74, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65};

/*Hostname(HTTP)*/
static uint8_t config_iv_2[12] = {0x77, 0xb8, 0xdf, 0xb6, 0xc2, 0x75, 0xdb, 0xbb, 0x37, 0x0b, 0x2d, 0x40};

static uint8_t encrypted_config_2[29] = {0x4b, 0xe6, 0xd0, 0x29, 0x89, 0x4e, 0x76, 0x82, 0x20, 0xf5, 0x1c, 0x10, 0xec, 0x9a, 0xc1, 0xb5, 0x78, 0xc9, 0xdb, 0x67, 0x98, 0x56, 0xf0, 
0x48, 0x0d, 0x77, 0x56, 0x6c, 0x4b};

static uint8_t additional_auth_data_2[14] = {0x46, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65};

/*password*/
static uint8_t config_iv_3[12] = {0x09, 0x24, 0xc2, 0x18, 0xae, 0x73, 0xd3, 0x60, 0x80, 0x60, 0x2b, 0x65};

static uint8_t encrypted_config_3[27] = {0x4b, 0xc3, 0x23, 0x95, 0x58, 0x07, 0x57, 0x8c, 0x94, 0x9f, 0xb6, 0x3b, 0xe8, 0xe1, 0x96, 0xe5, 0xc9, 0x08, 0xe2, 0xd0, 0x05, 0x43, 0xf2, 
0x01, 0xfa, 0x48, 0x2a};

static uint8_t additional_auth_data_3[14] = {0x46, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};


/*Username*/
static uint8_t config_iv_4[12] = {0x2d, 0xca, 0x77, 0xc8, 0x9b, 0xfa, 0x67, 0x8f, 0xc9, 0x73, 0xcf, 0x70};

static uint8_t encrypted_config_4[21] = {0xfe, 0x66, 0xa7, 0x80, 0x0c, 0xfe, 0x28, 0xf3, 0xbf, 0xee, 0x2c, 0x73, 0x2e, 0x14, 0xa0, 0xbb, 0x37, 0x6f, 0xba, 0xe0, 0x78};

static uint8_t additional_auth_data_4[14] = {0x46, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65};

void secure_memzero(void *v, size_t n)
{
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

int open_persistent_key()
{
    psa_status_t status;

    status = psa_open_key(my_key_id, &my_key_handle);
    if (status != PSA_SUCCESS) {
        LOG_ERR("psa_open_key(0x%08x) failed: %d", my_key_id, status);
        return status;
    }

    LOG_INF("Persistent key 0x%08x opened successfully", my_key_id);
    return status;
}

int decrypt_config_field_data(const char *encrypted_data, size_t encrypted_len,
                              const char *iv,
                              const char *additional_data, size_t additional_len,
                              char *output_buf, size_t *output_len)
{
    if (!encrypted_data || !iv || !additional_data || !output_buf || !output_len) {
        LOG_ERR("Invalid input to decrypt_config_field_data");
        return PROVISIONING_ERROR_BUFFER_SIZE;
    }

    psa_status_t status;

    LOG_INF("Decrypting config field...");

    status = psa_aead_decrypt(my_key_id,
                              PSA_ALG_GCM,
                              iv, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE,
                              additional_data, additional_len,
                              encrypted_data, encrypted_len,
                              output_buf, NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE,
                              output_len);

    if (status != PSA_SUCCESS) {
        LOG_ERR("Field decryption failed (psa_status: %d)", status);
        return PROVISIONING_ERROR_DECRYPT;
    }

    LOG_INF("Field decryption successful (length: %u)", *output_len);
    return PROVISIONING_SUCCESS;
}


void get_mqtt_host(char *output_buf, size_t *output_len) {

   

    int ret = decrypt_config_field_data(encrypted_config_1, sizeof(encrypted_config_1),
                                        config_iv_1, additional_auth_data_1, sizeof(additional_auth_data_1),
                                        output_buf, &output_len);
    
    if (ret == PROVISIONING_SUCCESS) {
        LOG_INF("Decrypted MQTT Host: %.*s", (int)output_len, output_buf);
    } else {
        LOG_ERR("Failed to decrypt MQTT Host: %d", ret);
    }
}

void get_http_host(char  *output_buf, size_t *output_len) {

    int ret = decrypt_config_field_data(encrypted_config_2, sizeof(encrypted_config_2),
                                        config_iv_2, additional_auth_data_2, sizeof(additional_auth_data_2),
                                        output_buf, &output_len);
   
    if (ret == PROVISIONING_SUCCESS) {
        LOG_INF("Decrypted http host: %.*s", (int)output_len, output_buf); 
    } else {
        LOG_ERR("Failed to decrypt http host: %d", ret);
    }

}

void get_password(char  *output_buf, size_t *output_len) {

    int ret = decrypt_config_field_data(encrypted_config_3, sizeof(encrypted_config_3),
                                        config_iv_3, additional_auth_data_3, sizeof(additional_auth_data_3),
                                        output_buf, &output_len);
    if (ret == PROVISIONING_SUCCESS) {
        LOG_INF("Decrypted password: %.*s", (int)output_len, output_buf);
    } else {
        LOG_ERR("Failed to decrypt password: %d", ret);
    }

}

void get_mqtt_username(char  *output_buf, size_t *output_len) {
    int ret = decrypt_config_field_data(encrypted_config_4, sizeof(encrypted_config_4),
                                        config_iv_4, additional_auth_data_4, sizeof(additional_auth_data_4),
                                        output_buf, &output_len);
    if (ret == PROVISIONING_SUCCESS) {
        LOG_INF("Decrypted username: %.*s", (int)output_len, output_buf);
    } else {
        LOG_ERR("Failed to decrypt username: %d", ret);
    }
}
