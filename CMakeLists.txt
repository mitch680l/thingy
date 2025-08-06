cmake_minimum_required(VERSION 3.20.0)


find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(yes)

# NORDIC SDK APP START
target_sources(app PRIVATE src/mqtt_connection.c)
#target_sources(app PRIVATE src/heartbeat.c)
target_sources(app PRIVATE src/shell_commands.c)
target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/gnss.c)
target_sources(app PRIVATE src/lte_helper.c)
target_sources(app PRIVATE src/fota.c)
target_sources(app PRIVATE src/encrypted_config.c)
#target_sources(app PRIVATE src/additional_shell.c)
# NORDIC SDK APP END