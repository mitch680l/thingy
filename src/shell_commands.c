
#include "shell_commands.h"
#include "encrypted_config.h"
char mqtt_client_id[MQTT_MAX_STR_LEN] = "nrid4148";               
char firmware_filename[MQTT_MAX_STR_LEN] = "blinky_2.signed.bin";
int  mqtt_broker_port = 8883;
int interval_mqtt = 40;
int interval_gnss = 40;
int interval_main = 40;
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




#define MAX_ENTRIES         16
#define MAX_IV_LEN          16
#define MAX_AAD_LEN         64
#define MAX_CIPHERTEXT_LEN  256

extern const uint8_t ENCRYPTED_BLOB_ADDR[];
#define ENCRYPTED_BLOB_SIZE 2048

typedef struct {
    uint8_t iv[MAX_IV_LEN];
    uint8_t iv_len;
    uint8_t aad[MAX_AAD_LEN];
    uint16_t aad_len;
    uint8_t ciphertext[MAX_CIPHERTEXT_LEN];
    uint16_t ciphertext_len;
} ConfigEntry;

static ConfigEntry entries[MAX_ENTRIES];
static int num_entries = 0;

void parse_encrypted_blob(void)
{
    const uint8_t *ptr = ENCRYPTED_BLOB_ADDR;
    const uint8_t *end = ENCRYPTED_BLOB_ADDR + ENCRYPTED_BLOB_SIZE;

    // Check for magic header
    if (memcmp(ptr, (uint8_t[]){0xAB, 0xCD, 0xEF, 0x12}, 4) != 0) {
        LOG_INF("Invalid blob magic header\n");
        return;
    }

    ptr += 4;

    // Read number of entries
    uint16_t entry_count = ptr[0] | (ptr[1] << 8);
    ptr += 2;

    printk("🔍 Parsing %d encrypted entries\n", entry_count);

    for (int i = 0; i < entry_count && ptr < end && num_entries < MAX_ENTRIES; i++) {
        ConfigEntry *e = &entries[num_entries];
        k_sleep(MSEC(10));
        // 1. IV length
        if (ptr + 1 > end) break;
        e->iv_len = *ptr++;
        if (e->iv_len > MAX_IV_LEN || ptr + e->iv_len > end) break;
        memcpy(e->iv, ptr, e->iv_len);
        ptr += e->iv_len;
        k_sleep(MSEC(10));
        // 2. AAD length (2 bytes)
        if (ptr + 2 > end) break;
        e->aad_len = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        if (e->aad_len > MAX_AAD_LEN || ptr + e->aad_len > end) break;
        memcpy(e->aad, ptr, e->aad_len);
        ptr += e->aad_len;
        k_sleep(MSEC(10));
        // 3. Ciphertext + tag length (2 bytes)
        if (ptr + 2 > end) break;
        e->ciphertext_len = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        if (e->ciphertext_len > MAX_CIPHERTEXT_LEN || ptr + e->ciphertext_len > end) break;
        memcpy(e->ciphertext, ptr, e->ciphertext_len);
        ptr += e->ciphertext_len;

        LOG_INF("Parsed entry %d: IV len=%d, AAD len=%d, Cipher len=%d\n",
               num_entries, e->iv_len, e->aad_len, e->ciphertext_len);

        num_entries++;
    }

    LOG_INF("Total entries parsed: %d\n", num_entries);
}

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
