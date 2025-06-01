idf_component_register(
    SRCS "main.cpp"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        esp_timer
        bt
        esp_http_client
        nvs_flash
        esp_http_server
        mbedtls
)