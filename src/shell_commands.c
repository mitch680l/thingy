// src/shell_commands.c

#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>      /* Settings API */
#include <string.h>                 /* strcmp(), strcpy(), strlen() */
#include <stdlib.h>                 /* atoi() */
#include <stdio.h>                  /* snprintk() */

#include "shell_commands.h"

LOG_MODULE_REGISTER(shell_cmds);

#define MQTT_MAX_STR_LEN 128

/* In-RAM settings, seeded from CONFIG_ macros */
char mqtt_client_id[MQTT_MAX_STR_LEN]  = CONFIG_MQTT_CLIENT_ID;
char mqtt_subscribe_topic[MQTT_MAX_STR_LEN] = CONFIG_MQTT_SUB_TOPIC;
char mqtt_broker_host[MQTT_MAX_STR_LEN]     = CONFIG_MQTT_BROKER_HOSTNAME;
int  mqtt_broker_port                  = CONFIG_MQTT_BROKER_PORT;
int  mqtt_publish_interval             = CONFIG_MQTT_PUBLISH_INTERVAL;
int  mqtt_keepalive                    = CONFIG_MQTT_KEEPALIVE;
/* Called by settings_load() for each “mqtt/<key>” entry */
static int mqtt_settings_set(const char *name, size_t len_rd,
                             settings_read_cb read_cb, void *cb_arg)
{
    char buf[MQTT_MAX_STR_LEN];

    if (strcmp(name, "device-id") == 0 && len_rd < sizeof(mqtt_client_id)) {
        read_cb(cb_arg, mqtt_client_id, len_rd);
        mqtt_client_id[len_rd] = '\0';

    } else if (strcmp(name, "subscribe-topic") == 0 && len_rd < sizeof(mqtt_subscribe_topic)) {
        read_cb(cb_arg, mqtt_subscribe_topic, len_rd);
        mqtt_subscribe_topic[len_rd] = '\0';

    } else if (strcmp(name, "broker-host") == 0 && len_rd < sizeof(mqtt_broker_host)) {
        read_cb(cb_arg, mqtt_broker_host, len_rd);
        mqtt_broker_host[len_rd] = '\0';

    } else if (strcmp(name, "broker-port") == 0 && len_rd < sizeof(buf)) {
        read_cb(cb_arg, buf, len_rd);
        buf[len_rd] = '\0';
        mqtt_broker_port = atoi(buf);

    } else if (strcmp(name, "publish-interval") == 0 && len_rd < sizeof(buf)) {
        read_cb(cb_arg, buf, len_rd);
        buf[len_rd] = '\0';
        mqtt_publish_interval = atoi(buf);

    } else if (strcmp(name, "keepalive") == 0 && len_rd < sizeof(buf)) {
        read_cb(cb_arg, buf, len_rd);
        buf[len_rd] = '\0';
        mqtt_keepalive = atoi(buf);
    }else {
        return -ENOENT;
    }
    return 0;
}

static struct settings_handler mqtt_sh = {
    .name  = "mqtt",
    .h_set = mqtt_settings_set,
};

/* Persist a single key under "mqtt/<key>" */
static int save_mqtt_kv(const char *key, const void *data, size_t len)
{
    char fullkey[32];
    int  rv = snprintk(fullkey, sizeof(fullkey), "mqtt/%s", key);
    if (rv < 0 || rv >= (int)sizeof(fullkey)) {
        return -ENOMEM;
    }
    return settings_save_one(fullkey, data, len);
}

/* mqtt set <key> <value> */
static int cmd_mqtt_set(const struct shell *sh, size_t argc, char **argv)
{
    const char *key   = argv[1];
    const char *value = argv[2];
    int          rc   = 0;

    if (!strcmp(key, "device-id")) {
        if (strlen(value) >= sizeof(mqtt_client_id)) {
            shell_error(sh, "Value too long");
            return -EINVAL;
        }
        strcpy(mqtt_client_id, value);
        rc = save_mqtt_kv(key, mqtt_client_id, strlen(mqtt_client_id));

    }

    else if (!strcmp(key, "subscribe-topic")) {
        if (strlen(value) >= sizeof(mqtt_subscribe_topic)) {
            shell_error(sh, "Value too long");
            return -EINVAL;
        }
        strcpy(mqtt_subscribe_topic, value);
        rc = save_mqtt_kv(key, mqtt_subscribe_topic, strlen(mqtt_subscribe_topic));

    } else if (!strcmp(key, "broker-host")) {
        if (strlen(value) >= sizeof(mqtt_broker_host)) {
            shell_error(sh, "Value too long");
            return -EINVAL;
        }
        strcpy(mqtt_broker_host, value);
        rc = save_mqtt_kv(key, mqtt_broker_host, strlen(mqtt_broker_host));

    } else if (!strcmp(key, "broker-port")) {
        mqtt_broker_port = atoi(value);
        char buf[16];
        int  len = snprintk(buf, sizeof(buf), "%d", mqtt_broker_port);
        rc = save_mqtt_kv(key, buf, len);

    } else if (!strcmp(key, "publish-interval")) {
        mqtt_publish_interval = atoi(value);
        char buf[16];
        int  len = snprintk(buf, sizeof(buf), "%d", mqtt_publish_interval);
        rc = save_mqtt_kv(key, buf, len);

    } else if (!strcmp(key, "keepalive")) {
        mqtt_keepalive = atoi(value);
        char buf[16];
        int  len = snprintk(buf, sizeof(buf), "%d", mqtt_keepalive);
        rc = save_mqtt_kv(key, buf, len);

    } else {
        shell_error(sh, "Unknown key '%s'", key);
        return -EINVAL;
    }

    if (rc) {
        shell_error(sh, "Failed to save '%s' (%d)", key, rc);
    } else {
        shell_print(sh, "%s = %s", key, value);
    }
    return rc;
}

/* mqtt get <key> */
static int cmd_mqtt_get(const struct shell *sh, size_t argc, char **argv)
{
    const char *key = argv[1];

    if (!strcmp(key, "device-id")) {
        shell_print(sh, "%s", mqtt_client_id);
    } else if (!strcmp(key, "subscribe-topic")) {
        shell_print(sh, "%s", mqtt_subscribe_topic);
    } else if (!strcmp(key, "broker-host")) {
        shell_print(sh, "%s", mqtt_broker_host);
    } else if (!strcmp(key, "broker-port")) {
        shell_print(sh, "%d", mqtt_broker_port);
    } else if (!strcmp(key, "publish-interval")) {
        shell_print(sh, "%d", mqtt_publish_interval);
    } else if (!strcmp(key, "keepalive")) {
        shell_print(sh, "%d", mqtt_keepalive);
    } else {
        shell_error(sh, "Unknown key '%s'", key);
        return -EINVAL;
    }

    return 0;
}

/* mqtt factory-default */
static int cmd_mqtt_factory(const struct shell *sh, size_t argc, char **argv)
{
    int rc = 0;
    char buf[16];
    int  len;

    /* 1) Reset RAM vars to CONFIG_ defaults */
    strcpy(mqtt_client_id,   CONFIG_MQTT_CLIENT_ID);
    strcpy(mqtt_subscribe_topic, CONFIG_MQTT_SUB_TOPIC);
    strcpy(mqtt_broker_host,     CONFIG_MQTT_BROKER_HOSTNAME);
    mqtt_broker_port      = CONFIG_MQTT_BROKER_PORT;
    mqtt_publish_interval = CONFIG_MQTT_PUBLISH_INTERVAL;
    mqtt_keepalive        = CONFIG_MQTT_KEEPALIVE;

    /* 2) Persist each back to flash */
    rc |= save_mqtt_kv("device-id",   mqtt_client_id,   strlen(mqtt_client_id));
    rc |= save_mqtt_kv("subscribe-topic", mqtt_subscribe_topic, strlen(mqtt_subscribe_topic));
    rc |= save_mqtt_kv("broker-host",     mqtt_broker_host,     strlen(mqtt_broker_host));

    len = snprintk(buf, sizeof(buf), "%d", mqtt_broker_port);
    rc |= save_mqtt_kv("broker-port", buf, len);

    len = snprintk(buf, sizeof(buf), "%d", mqtt_publish_interval);
    rc |= save_mqtt_kv("publish-interval", buf, len);

    len = snprintk(buf, sizeof(buf), "%d", mqtt_keepalive);
    rc |= save_mqtt_kv("keepalive", buf, len);

    if (rc) {
        shell_error(sh, "Failed to restore defaults (%d)", rc);
        return rc;
    }
    shell_print(sh, "All MQTT settings reset to factory defaults");
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(mqtt_cmds,
    SHELL_CMD_ARG(set, NULL,
                  "mqtt set <device-id|subscribe-topic|broker-host|broker-port|publish-interval|keepalive> <value>",
                  cmd_mqtt_set, 3, 0),
    SHELL_CMD_ARG(get, NULL,
                  "mqtt get <device-id|subscribe-topic|broker-host|broker-port|publish-interval|keepalive>",
                  cmd_mqtt_get, 2, 0),
    SHELL_CMD_ARG(factory-default, NULL,
                  "mqtt factory-default: restore all keys to CONFIG_ defaults",
                  cmd_mqtt_factory, 1, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(mqtt, &mqtt_cmds,
                   "MQTT configuration (persisted in flash)", NULL);

/* Call this from main() before shell starts */
void shell_mqtt_init(void)
{
    settings_subsys_init();
    settings_register(&mqtt_sh);
    settings_load();   /* load all mqtt keys into RAM */
}
