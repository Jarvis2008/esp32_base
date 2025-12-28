idf_component_register(SRCS "esp32_base.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_http_server json
                    PRIV_REQUIRES esp_ringbuf esp_timer esp_event esp_netif lwip)
