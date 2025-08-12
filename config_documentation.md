# Configuration Parameters Documentation

This document describes all configuration parameters used in the system, their lookup keys, default values, and purposes.

## Configuration Parameters

| Parameter | Lookup Key | Default | Macro | Type | Description |
|-----------|------------|---------|-------|------|-------------|
| `mqtt_client_id` | `mqtt_client_id` | *Empty* | - | String | Unique identifier for MQTT client |
| `firmware_filename` | `firmware_filename` | *Empty* | - | String | Firmware file for FOTA updates |
| `topic_gps` | `topic_gps` | *Empty* | - | String | MQTT topic for GPS data |
| `topic_sensor` | `topic_sensor` | *Empty* | - | String | MQTT topic for sensor data |
| `topic_lte` | `topic_lte` | *Empty* | - | String | MQTT topic for LTE status |
| `mqtt_broker_host` | `mqtt_broker_host` | `18.234.99.151` | `DEFAULT_BROKER_HOST` | String | MQTT broker hostname/IP |
| `fota_host` | `fota_host` | `18.234.99.151` | `DEFAULT_FOTA_HOST` | String | FOTA server hostname/IP |
| `mqtt_broker_port` | `mqtt_broker_port` | `8883` | `DEFAULT_MQTT_BROKER_PORT` | Int | MQTT broker port (TLS) |
| `interval_mqtt` | `interval_mqtt` | `100` | `DEFAULT_INTERVAL_MQTT` | Int | MQTT interval (ms) |
| `fota_interval_ms` | `fota_interval_ms` | `60000000` | `DEFAULT_FOTA_INTERVAL_MS` | Int | FOTA check interval (ms) |
| `gps_target_rate` | `gps_target_rate` | `25` | `DEFAULT_GPS_TARGET_RATE` | Int | GPS update rate (Hz) |
| `enable_iridium` | `enable_iridium` | `false` | `DEFAULT_ENABLE_IRIDIUM` | Bool | Enable Iridium satellite |

## Configuration File Format

The system expects configuration values in a comma-separated text file with the format: `field,value`

### Example Configuration File (config.txt)
```
mqtt_broker_host,my.broker.com
mqtt_broker_port,1883
mqtt_client_id,device_12345
enable_iridium,true
interval_mqtt,500
fota_interval_ms,3600000
gps_target_rate,10
topic_gps,sensors/gps/data
topic_sensor,sensors/environmental
topic_lte,network/lte/status
firmware_filename,firmware_v2.1.bin
fota_host,fota.myserver.com
```

## Configuration Value Format

**String Parameters**: Stored as plain text values. Empty lines or "NULL" values are treated as not configured.

**Integer Parameters**: Stored as numeric strings (e.g., "1883", "500"). Invalid strings will convert to 0 using `atoi()`.

**Boolean Parameters**: Stored as text strings. Only `"true"` and `"1"` evaluate to true; everything else evaluates to false (case-sensitive).

## System Behavior

When the system starts, `config_init()` reads each parameter from storage using the lookup key. If a parameter is not found or contains "NULL":

- **Parameters with defaults**: The system uses the predefined default value and logs a warning
- **Parameters without defaults**: The system sets the parameter to an empty string and logs a warning

All configuration loading is logged with INFO messages for found values and WARNING messages for missing values.

## Important Notes

- **FOTA Interval**: Default 60,000,000 ms equals approximately 16.7 hours
- **MQTT Port**: Default 8883 is the standard port for MQTT over TLS/SSL
- **GPS Rate**: Default 25 Hz is a common GPS update frequency
- **Topic Names**: Empty topic names may cause MQTT publishing failures
- **IP Addresses**: Both broker and FOTA services currently use the same default IP
- **File Format**: No spaces around commas in the config file
- **Boolean Values**: Must be exactly "true" or "1" for true; case-sensitive

## Troubleshooting

Check system logs for configuration warnings:
- `"[parameter] not found, using default"` indicates missing configuration with fallback
- `"[parameter] not found, will be empty"` indicates missing configuration without default
- Verify boolean parameters use correct string values ("true"/"1")
- Ensure numeric parameters contain valid integer strings
- Confirm config file uses exact comma-separated format without extra spaces