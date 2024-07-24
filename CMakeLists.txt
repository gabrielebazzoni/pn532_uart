idf_component_register(SRCS "pn532_uart.c"
                    INCLUDE_DIRS "include"
                    REQUIRES driver
                    REQUIRES esp_event)
