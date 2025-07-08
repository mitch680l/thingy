#ifndef GNSS_H
#define GNSS_H

#define I2C_NODE DT_NODELABEL(i2c2)
#define M10S_ADDR 0x42

#define QWIIC_EN_NODE DT_ALIAS(qwiic_en)
#define GPIO0_NODE DT_NODELABEL(gpio0)

extern const struct device *i2c_dev;
extern const struct device *gpio0;
#define NAV_PVT_LEN 92

struct __attribute__((packed)) ubx_nav_pvt_t {
    uint32_t iTOW;
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t min;
    uint8_t sec;
    uint8_t valid;
    uint32_t tAcc;
    int32_t nano;
    uint8_t fixType;
    uint8_t flags;
    uint8_t flags2;
    uint8_t numSV;
    int32_t lon;
    int32_t lat;
    int32_t height;
    int32_t hMSL;
    uint32_t hAcc;
    uint32_t vAcc;
    int32_t velN;
    int32_t velE;
    int32_t velD;
    int32_t gSpeed;
    int32_t heading;
    uint32_t sAcc;
    uint32_t headingAcc;
    uint16_t pDOP;
    uint8_t reserved[6];
    int32_t headVeh;
    int16_t magDec;
    uint16_t magAcc;
};


static void ubx_checksum(const uint8_t *data, size_t len, uint8_t *ck_a, uint8_t *ck_b);

static void print_nav_pvt_json(const struct ubx_nav_pvt_t *pvt);

static bool parse_nav_pvt(const uint8_t *buf, size_t len, struct ubx_nav_pvt_t *out);

static bool parse_ack(const uint8_t *buf, size_t len, uint8_t cls, uint8_t id);

static bool send_ubx_message(uint8_t *msg, size_t len, const char *desc);

static bool configure_gps_10hz(void);

void gnss_main_loop();
void gnss_int();


extern char json_payload[512];
extern struct k_mutex json_mutex;
#endif