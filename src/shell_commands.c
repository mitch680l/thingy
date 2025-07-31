#include "shell_commands.h"
#include "encrypted_config.h"
#include <zephyr/sys/crc.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/shell/shell.h>
#include <zephyr/random/random.h>

char mqtt_client_id[MQTT_MAX_STR_LEN] = "nrid4148";               
char firmware_filename[MQTT_MAX_STR_LEN] = "blinky_2.signed.bin";
int  mqtt_broker_port = 8883;
int interval_mqtt = 100;
int fota_interval_ms = 10 * 60 * 1000;
int gps_target_rate = 25;
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
#define AES_KEY_SIZE (32) 
#define DECRYPTED_OUTPUT_MAX 256

LOG_MODULE_REGISTER(aes_gcm, LOG_LEVEL_DBG);

#define MAX_INPUT_LEN 256
#define BLOB_HEADER_SIZE 0
#define ENTRY_SIZE 128

#define MAX_ENTRIES         16
#define MAX_IV_LEN          16
#define MAX_AAD_LEN         64
#define MAX_CIPHERTEXT_LEN  256
#define FLASH_PAGE_SIZE  4096 
#define ENTRIES_PER_PAGE (FLASH_PAGE_SIZE / ENTRY_SIZE)
#define CONFIG_PAGE_COUNT 2  
#define TOTAL_ENTRIES     (CONFIG_PAGE_COUNT * ENTRIES_PER_PAGE) 
#define ENCRYPTED_BLOB_ADDR ((const uint8_t *)0xfb000)
#define ENCRYPTED_BLOB_SIZE 8192 
#define FLASH_CRC_PAGE_OFFSET (CONFIG_PAGE_COUNT * FLASH_PAGE_SIZE)
#define FLASH_PAGE_CRC_SIZE  (ENCRYPTED_BLOB_SIZE - FLASH_CRC_PAGE_OFFSET)
#define CRC_LOCATION_OFFSET (ENCRYPTED_BLOB_SIZE - 4)

typedef struct {
    uint8_t iv[MAX_IV_LEN];
    uint8_t iv_len;
    uint8_t aad[MAX_AAD_LEN];
    uint16_t aad_len;
    uint8_t ciphertext[MAX_CIPHERTEXT_LEN];
    uint16_t ciphertext_len;
    uint32_t mem_offset;
} ConfigEntry;

static ConfigEntry entries[MAX_ENTRIES];
static int num_entries = 0;

uint32_t manual_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    LOG_INF("Starting manual CRC-32 over %u bytes", (unsigned int)len);

    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        crc ^= byte;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    crc ^= 0xFFFFFFFF;

    LOG_INF("Final manual CRC-32: 0x%08X", crc);
    return crc;
}

void parse_encrypted_blob(void)
{
    const uint8_t *start = ENCRYPTED_BLOB_ADDR;
    const uint8_t *end = ENCRYPTED_BLOB_ADDR + ENCRYPTED_BLOB_SIZE;
    const size_t entry_span = ENTRY_SIZE;
    const size_t max_offset = CRC_LOCATION_OFFSET;

    LOG_INF("Begin blob parsing at address %p, total size: %d", (void *)start, ENCRYPTED_BLOB_SIZE);

    uint32_t computed_crc = manual_crc32(start, ENCRYPTED_BLOB_SIZE - 4);
    uint32_t stored_crc = *(uint32_t *)(start + CRC_LOCATION_OFFSET);
    if (computed_crc != stored_crc) {
        LOG_WRN("CRC mismatch: computed=0x%08X, stored=0x%08X", computed_crc, stored_crc);
    } else {
        LOG_INF("CRC check passed: 0x%08X", computed_crc);
    }

    num_entries = 0;

    for (uintptr_t offset = 0; offset + entry_span <= max_offset && num_entries < MAX_ENTRIES; offset += entry_span) {
        const uint8_t *ptr = start + offset;

        if (ptr[0] == 0xFF) {
            continue;
        }

        ConfigEntry *e = &entries[num_entries];
        e->mem_offset = offset;

        e->iv_len = *ptr++;
        if (e->iv_len > MAX_IV_LEN || ptr + e->iv_len > end) {
            LOG_ERR("Invalid or oversized IV length: %d at entry %d", e->iv_len, num_entries);
            continue;
        }
        memcpy(e->iv, ptr, e->iv_len);
        ptr += e->iv_len;

        if (ptr + 2 > end) continue;
        e->aad_len = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        if (e->aad_len > MAX_AAD_LEN || ptr + e->aad_len > end) {
            LOG_ERR("Invalid or oversized AAD length: %d at entry %d", e->aad_len, num_entries);
            continue;
        }
        memcpy(e->aad, ptr, e->aad_len);
        ptr += e->aad_len;

        if (ptr + 2 > end) continue;
        e->ciphertext_len = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        if (e->ciphertext_len > MAX_CIPHERTEXT_LEN || ptr + e->ciphertext_len > end) {
            LOG_ERR("Invalid or oversized ciphertext length: %d at entry %d", e->ciphertext_len, num_entries);
            continue;
        }
        memcpy(e->ciphertext, ptr, e->ciphertext_len);
        ptr += e->ciphertext_len;

        LOG_INF("Parsed entry %d @ offset 0x%04X: IV=%d, AAD=%d, Cipher+Tag=%d",
                num_entries, (int)offset, e->iv_len, e->aad_len, e->ciphertext_len);

        num_entries++;
    }

    LOG_INF("Total parsed entries: %d", num_entries);
}

static int cmd_parse_blob(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    shell_print(shell, "Parsing encrypted blob...");
    parse_encrypted_blob();
    shell_print(shell, "Done parsing.");
    return 0;
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

int encrypt_config_field_data(const char *plaintext_data, size_t plaintext_len,
                              char *iv_out,
                              const char *additional_data, size_t additional_len,
                              char *encrypted_out, size_t *encrypted_len)
{
    if (!plaintext_data || !iv_out || !additional_data || !encrypted_out || !encrypted_len) {
        LOG_ERR("Invalid input to encrypt_config_field_data");
        return PROVISIONING_ERROR_BUFFER_SIZE;
    }

    psa_status_t status;

    status = psa_generate_random((uint8_t*)iv_out, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    if (status != PSA_SUCCESS) {
        LOG_ERR("IV generation failed (psa_status: %d)", status);
        return PROVISIONING_ERROR_IV_GEN;
    }

    LOG_INF("Encrypting config field...");

    status = psa_aead_encrypt(my_key_id,
                              PSA_ALG_GCM,
                              iv_out, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE,
                              additional_data, additional_len,
                              plaintext_data, plaintext_len,
                              encrypted_out, MAX_CIPHERTEXT_LEN,
                              encrypted_len);

    if (status != PSA_SUCCESS) {
        LOG_ERR("Field encryption failed (psa_status: %d)", status);
        return PROVISIONING_ERROR_ENCRYPT;
    }

    LOG_INF("Field encryption successful (length: %u)", *encrypted_len);
    return PROVISIONING_SUCCESS;
}

void test_decrypt_all_config_entries(void)
{
    char decrypted[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
    size_t decrypted_len;

    LOG_INF("Starting config entry decryption test...");

    for (int i = 0; i < num_entries; i++) {
        const ConfigEntry *e = &entries[i];
        k_sleep(K_MSEC(100));
        LOG_INF("Decrypting entry %d: AAD length=%d, Ciphertext length=%d", 
                i, e->aad_len, e->ciphertext_len);

        int ret = decrypt_config_field_data(
            (const char *)e->ciphertext, e->ciphertext_len,
            (const char *)e->iv,
            (const char *)e->aad, e->aad_len,
            decrypted, &decrypted_len
        );

        if (ret != PROVISIONING_SUCCESS) {
            LOG_ERR("Failed to decrypt entry %d", i);
            continue;
        }

        // Ensure null-termination for printing (if it's a string)
        if (decrypted_len < sizeof(decrypted)) {
            decrypted[decrypted_len] = '\0';
        } else {
            decrypted[sizeof(decrypted) - 1] = '\0';
        }

        LOG_INF("Decrypted entry %d: %s", i, decrypted);
    }

    LOG_INF("Config entry decryption test complete.");
}





static int update_crc(void)
{
    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open for CRC failed: %d", err);
        return err;
    }

    uint32_t new_crc = manual_crc32(ENCRYPTED_BLOB_ADDR, ENCRYPTED_BLOB_SIZE - 4);
    uint32_t crc_offset = CRC_LOCATION_OFFSET;
    uint32_t page_start = (crc_offset / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;

    static uint8_t page_buf[FLASH_PAGE_SIZE]; // 🔥 Fix: moved off stack

    err = flash_area_read(fa, page_start, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_read for CRC page failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    uint32_t crc_offset_in_page = crc_offset - page_start;
    memcpy(&page_buf[crc_offset_in_page], &new_crc, 4);

    err = flash_area_erase(fa, page_start, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase CRC page failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    err = flash_area_write(fa, page_start, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("CRC write failed: %d", err);
    } else {
        LOG_INF("CRC updated: 0x%08X at offset 0x%x", new_crc, crc_offset);
    }

    flash_area_close(fa);
    return err;
}

static int cmd_crc_update(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "update") != 0) {
        shell_error(shell, "Usage: crc update");
        return -EINVAL;
    }

    int ret = update_crc();
    if (ret == 0) {
        shell_print(shell, "CRC update completed successfully.");
    } else {
        shell_error(shell, "CRC update failed: %d", ret);
    }

    return ret;
}


int create_encrypted_entry_with_aad(const char *plaintext_aad, const char *plaintext, uint8_t *entry_buf)
{
    if (!plaintext || !entry_buf || !plaintext_aad) return -EINVAL;

    char iv[NRF_CRYPTO_EXAMPLE_AES_IV_SIZE];
    static char encrypted[MAX_CIPHERTEXT_LEN];
    size_t encrypted_len;
    size_t plaintext_len = strlen(plaintext);
    size_t aad_len = strlen(plaintext_aad);

    int ret = encrypt_config_field_data(plaintext, plaintext_len,
                                        iv, plaintext_aad, aad_len,
                                        encrypted, &encrypted_len);
    if (ret != PROVISIONING_SUCCESS) {
        LOG_ERR("Encryption failed: %d", ret);
        return ret;
    }

    uint8_t *ptr = entry_buf;

    *ptr++ = NRF_CRYPTO_EXAMPLE_AES_IV_SIZE;
    memcpy(ptr, iv, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    ptr += NRF_CRYPTO_EXAMPLE_AES_IV_SIZE;

    *ptr++ = aad_len & 0xFF;
    *ptr++ = (aad_len >> 8) & 0xFF;
    memcpy(ptr, plaintext_aad, aad_len);
    ptr += aad_len;

    *ptr++ = encrypted_len & 0xFF;
    *ptr++ = (encrypted_len >> 8) & 0xFF;
    memcpy(ptr, encrypted, encrypted_len);
    ptr += encrypted_len;

    size_t used = ptr - entry_buf;
    if (used < ENTRY_SIZE) {
        memset(ptr, 0x00, ENTRY_SIZE - used);
    }

    LOG_INF("Created encrypted entry: AAD=\"%s\", len=%zu, plaintext_len=%zu, total_used=%zu",
            plaintext_aad, aad_len, plaintext_len, used);

    return 0;
}

static int update_single_entry(int index, const uint8_t *new_data, size_t data_len)
{
    if (index < 0 || index >= TOTAL_ENTRIES) {
        LOG_ERR("Invalid entry index %d (max: %d)", index, TOTAL_ENTRIES - 1);
        return -EINVAL;
    }
    
    size_t entry_offset = index * ENTRY_SIZE;
    
    if (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET) {
        LOG_ERR("Entry %d would overwrite CRC location", index);
        return -EINVAL;
    }

    int page_index = index / ENTRIES_PER_PAGE;
    int entry_in_page = index % ENTRIES_PER_PAGE;
    
    size_t page_offset = page_index * FLASH_PAGE_SIZE;
    uint8_t page_buf[FLASH_PAGE_SIZE];

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open failed: %d", err);
        return err;
    }

    err = flash_area_read(fa, page_offset, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_read failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    size_t entry_offset_in_page = entry_in_page * ENTRY_SIZE;
    memcpy(&page_buf[entry_offset_in_page], new_data, ENTRY_SIZE);

    err = flash_area_erase(fa, page_offset, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase failed: %d (offset: 0x%x)", err, (unsigned int)page_offset);
        flash_area_close(fa);
        return err;
    }

    err = flash_area_write(fa, page_offset, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_write failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    flash_area_close(fa);
    LOG_INF("Updated entry %d in page %d (4KB-aligned)", index, page_index);
    return update_crc();
}

static int overwrite_config_page(int page_index, const uint8_t *page_data)
{
    if (page_index < 1 || page_index > CONFIG_PAGE_COUNT) {
        LOG_ERR("Invalid page index %d (valid: 1-%d)", page_index, CONFIG_PAGE_COUNT);
        return -EINVAL;
    }

    size_t page_offset = (page_index - 1) * FLASH_PAGE_SIZE;

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open failed: %d", err);
        return err;
    }

    err = flash_area_erase(fa, page_offset, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase failed: %d (offset: 0x%x)", err, (unsigned int)page_offset);
        flash_area_close(fa);
        return err;
    }

    err = flash_area_write(fa, page_offset, page_data, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_write failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    flash_area_close(fa);
    LOG_INF("Overwrote page %d at offset 0x%x", page_index, (unsigned int)page_offset);
    return update_crc();
}

const char *get_config(const char *aad)
{
    static char decrypted[DECRYPTED_OUTPUT_MAX]; // persistent output
    size_t decrypted_len = 0;

    for (int i = 0; i < num_entries; i++) {
        ConfigEntry *e = &entries[i];

        if (e->aad_len == strlen(aad) &&
            memcmp(e->aad, aad, e->aad_len) == 0) {

            int ret = decrypt_config_field_data(
                (const char *)e->ciphertext, e->ciphertext_len,
                (const char *)e->iv,
                (const char *)e->aad, e->aad_len,
                decrypted, &decrypted_len
            );

            if (ret != 0) {
                LOG_ERR("Decryption failed for AAD: %s", aad);
                return NULL;
            }

            decrypted[decrypted_len] = '\0'; // null-terminate
            return decrypted;
        }
    }

    LOG_WRN("AAD not found: %s", aad);
    return "NULL";
}

static int cmd_get_config(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: get_config <aad>");
        return -EINVAL;
    }

    const char *aad = argv[1];
    const char *value = get_config(aad);

    if (!value) {
        shell_error(shell, "No entry found or decryption failed for AAD: %s", aad);
        return -ENOENT;
    }

    shell_print(shell, "%s = %s", aad, value);
    return 0;
}




static int cmd_set_page(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2) {
        shell_error(shell, "Usage: set_page <page:1-2> [aad1 data1] [aad2 data2] ...");
        return -EINVAL;
    }

    int page = atoi(argv[1]);
    if (page < 1 || page > CONFIG_PAGE_COUNT) {
        shell_error(shell, "Invalid page index %d", page);
        return -EINVAL;
    }

    uint8_t page_buf[FLASH_PAGE_SIZE];
    memset(page_buf, 0xFF, FLASH_PAGE_SIZE);

    int entry_index = 0;
    int arg_index = 2;

    while (entry_index < ENTRIES_PER_PAGE && (arg_index + 1) < argc) {
        size_t entry_offset = ((page - 1) * FLASH_PAGE_SIZE) + (entry_index * ENTRY_SIZE);

        bool overlaps_crc = (entry_offset < CRC_LOCATION_OFFSET) &&
                            (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET);

        const char *aad = argv[arg_index];
        const char *data = argv[arg_index + 1];
        arg_index += 2;

        if (overlaps_crc || strlen(aad) == 0 || strlen(data) == 0) {
            memset(&page_buf[entry_index * ENTRY_SIZE], 0xFF, ENTRY_SIZE);
            entry_index++;
            continue;
        }

        uint8_t encrypted_entry[ENTRY_SIZE];
        int ret = create_encrypted_entry_with_aad(aad, data, encrypted_entry);
        if (ret != 0) {
            shell_error(shell, "Failed to encrypt entry %d: %d", entry_index, ret);
            return ret;
        }

        memcpy(&page_buf[entry_index * ENTRY_SIZE], encrypted_entry, ENTRY_SIZE);
        entry_index++;
    }

    // Fill remaining entries with 0xFF
    while (entry_index < ENTRIES_PER_PAGE) {
        memset(&page_buf[entry_index * ENTRY_SIZE], 0xFF, ENTRY_SIZE);
        entry_index++;
    }

    shell_print(shell, "Writing page %d with %d entries", page, ENTRIES_PER_PAGE);
    return overwrite_config_page(page, page_buf);
}


static int cmd_set_entry(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(shell, "Usage: set <aad> <data>");
        return -EINVAL;
    }

    const char *aad = argv[1];
    const char *data = argv[2];

    uint8_t encrypted_entry[ENTRY_SIZE];
    int ret = create_encrypted_entry_with_aad(aad, data, encrypted_entry);
    if (ret != 0) {
        shell_error(shell, "Failed to create encrypted entry: %d", ret);
        return ret;
    }

    // Search for existing AAD or first free slot
    int selected_index = -1;
    for (int i = 0; i < TOTAL_ENTRIES; i++) {
        size_t entry_offset = i * ENTRY_SIZE;

        if (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET)
            continue;

        const uint8_t *entry_ptr = ENCRYPTED_BLOB_ADDR + entry_offset;
        if (entry_ptr[0] == 0xFF) {
            if (selected_index == -1)
                selected_index = i;
            continue;
        }

        uint8_t iv_len = entry_ptr[0];
        const uint8_t *aad_len_ptr = entry_ptr + 1 + iv_len;
        uint16_t existing_aad_len = aad_len_ptr[0] | (aad_len_ptr[1] << 8);
        const char *existing_aad = (const char *)(aad_len_ptr + 2);

        if (existing_aad_len == strlen(aad) && memcmp(existing_aad, aad, existing_aad_len) == 0) {
            selected_index = i;
            break;
        }
    }

    if (selected_index == -1) {
        shell_error(shell, "No free slot and no matching AAD to override");
        return -ENOSPC;
    }

    shell_print(shell, "Writing entry at index %d (AAD: \"%s\")...", selected_index, aad);
    return update_single_entry(selected_index, encrypted_entry, ENTRY_SIZE);
}




static int cmd_get_entry_hex(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: get_hex <index>");
        return -EINVAL;
    }

    int index = atoi(argv[1]);
    if (index < 0 || index >= TOTAL_ENTRIES) {
        shell_error(shell, "Invalid index %d (max: %d)", index, TOTAL_ENTRIES - 1);
        return -EINVAL;
    }

    const uint8_t *entry = ENCRYPTED_BLOB_ADDR + index * ENTRY_SIZE;
    shell_print(shell, "Entry %d (hex):", index);
    for (int i = 0; i < ENTRY_SIZE; i++) {
        shell_fprintf(shell, SHELL_NORMAL, "%02X ", entry[i]);
        if ((i + 1) % 16 == 0) {
            shell_print(shell, "");
            k_sleep(K_MSEC(10));
        }
    }
    return 0;
}

static int cmd_get_page_hex(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: get_page_hex <page_index:1-2>");
        return -EINVAL;
    }

    int page_index = atoi(argv[1]);
    if (page_index < 1 || page_index > CONFIG_PAGE_COUNT) {
        shell_error(shell, "Invalid page index %d (valid: 1-%d)", page_index, CONFIG_PAGE_COUNT);
        return -EINVAL;
    }

    const uint8_t *page = ENCRYPTED_BLOB_ADDR + (page_index - 1) * FLASH_PAGE_SIZE;
    shell_print(shell, "Page %d (hex):", page_index);
    for (int i = 0; i < FLASH_PAGE_SIZE; i++) {
        shell_fprintf(shell, SHELL_NORMAL, "%02X ", page[i]);
        if ((i + 1) % 16 == 0) {
            shell_print(shell, "");
            k_sleep(K_MSEC(5));
        }
    }
    return 0;
}

static int cmd_get_blob_hex(const struct shell *shell, size_t argc, char **argv)
{
    shell_print(shell, "Full blob (size: %d, CRC at offset 0x%x):", ENCRYPTED_BLOB_SIZE, CRC_LOCATION_OFFSET);
    for (int i = 0; i < ENCRYPTED_BLOB_SIZE; i++) {
        shell_fprintf(shell, SHELL_NORMAL, "%02X ", ENCRYPTED_BLOB_ADDR[i]);
        if ((i + 1) % 16 == 0) {
            shell_print(shell, "");
            k_sleep(K_MSEC(5));
        }
    }
    return 0;
}

static int cmd_get_crc_info(const struct shell *shell, size_t argc, char **argv)
{
    uint32_t computed_crc = manual_crc32(ENCRYPTED_BLOB_ADDR, ENCRYPTED_BLOB_SIZE - 4);
    uint32_t stored_crc = *(uint32_t *)(ENCRYPTED_BLOB_ADDR + CRC_LOCATION_OFFSET);
    
    shell_print(shell, "CRC Information:");
    shell_print(shell, "  Location: 0x%x (last 4 bytes)", CRC_LOCATION_OFFSET);
    shell_print(shell, "  Computed: 0x%08X", computed_crc);
    shell_print(shell, "  Stored:   0x%08X", stored_crc);
    shell_print(shell, "  Status:   %s", (computed_crc == stored_crc) ? "VALID" : "INVALID");
    
    return 0;
}

static int cmd_show_layout(const struct shell *shell, size_t argc, char **argv)
{
    shell_print(shell, "Encrypted Blob Layout:");
    shell_print(shell, "  Base Address:     0x%x", (unsigned int)ENCRYPTED_BLOB_ADDR);
    shell_print(shell, "  Total Size:       %d bytes (8KB)", ENCRYPTED_BLOB_SIZE);
    shell_print(shell, "  Header Size:      %d bytes", BLOB_HEADER_SIZE);
    shell_print(shell, "  Entry Size:       %d bytes", ENTRY_SIZE);
    shell_print(shell, "  Page Size:        %d bytes (4KB)", FLASH_PAGE_SIZE);
    shell_print(shell, "  Entries per Page: %d", ENTRIES_PER_PAGE);
    shell_print(shell, "  Config Pages:     %d", CONFIG_PAGE_COUNT);
    shell_print(shell, "  Total Entries:    %d", TOTAL_ENTRIES);
    shell_print(shell, "  CRC Location:     0x%x (offset %d)", 
                (unsigned int)(ENCRYPTED_BLOB_ADDR + CRC_LOCATION_OFFSET), CRC_LOCATION_OFFSET);
    
    shell_print(shell, "\nPage Layout:");
    for (int i = 1; i <= CONFIG_PAGE_COUNT; i++) {
        size_t page_offset = (i - 1) * FLASH_PAGE_SIZE;
        int start_entry = (i - 1) * ENTRIES_PER_PAGE;
        int end_entry = start_entry + ENTRIES_PER_PAGE - 1;
        shell_print(shell, "  Page %d: offset 0x%x, entries %d-%d", 
                    i, (unsigned int)page_offset, start_entry, end_entry);
    }
    
    return 0;
}



static int cmd_erase_page(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 3 || strcmp(argv[1], "page") != 0) {
        shell_error(shell, "Usage: erase page <1|2>");
        return -EINVAL;
    }

    int page = atoi(argv[2]);
    if (page != 1 && page != 2) {
        shell_error(shell, "Invalid page number: %d. Must be 1 or 2.", page);
        return -EINVAL;
    }

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        shell_error(shell, "flash_area_open failed: %d", err);
        return err;
    }

    off_t offset = (page - 1) * FLASH_PAGE_SIZE;

    err = flash_area_erase(fa, offset, FLASH_PAGE_SIZE);
    if (err) {
        shell_error(shell, "Failed to erase page %d: %d", page, err);
    } else {
        shell_print(shell, "Erased page %d at offset 0x%08x", page, (uint32_t)offset);
    }

    flash_area_close(fa);
    return err;
}

/*
These are functions that deal with interfaceing the storage system
Note: if you use set or get it may not effect the actual ram storage identity of the config
    actually setting this config options requires either reset or using "parse" command.
*/
SHELL_CMD_ARG_REGISTER(erase, NULL, "Erase page <1|2> from main encrypted blob", cmd_erase_page, 3, 0);
SHELL_CMD_ARG_REGISTER(crc, NULL, "CRC command group: crc update", cmd_crc_update, 2, 0);
SHELL_CMD_REGISTER(get_hex, NULL, "Get entry in hex: get_hex <index>", cmd_get_entry_hex);
SHELL_CMD_REGISTER(get_page_hex, NULL, "Get page in hex: get_page_hex <1-2>", cmd_get_page_hex);
SHELL_CMD_REGISTER(get_blob_hex, NULL, "Dump entire encrypted blob in hex", cmd_get_blob_hex);
SHELL_CMD_REGISTER(get_crc, NULL, "Show CRC information", cmd_get_crc_info);
SHELL_CMD_REGISTER(show_layout, NULL, "Show blob memory layout", cmd_show_layout);

SHELL_CMD_ARG_REGISTER(set, NULL,"Set or override entry. Usage: set <aad> <data>",cmd_set_entry, 3, 0);
SHELL_CMD_ARG_REGISTER(set_page, NULL,"Set page with AAD/data pairs. Usage: set_page <1|2> [aad data] [...]", cmd_set_page, 3, ENTRIES_PER_PAGE  * 2);
SHELL_CMD_ARG_REGISTER(get_config, NULL,"Retrieve and decrypt a config value by AAD. Usage: get_config <aad>",cmd_get_config, 2, 0);


SHELL_CMD_REGISTER(parse, NULL, "Parse encrypted config blob", cmd_parse_blob);