#include <string.h>
#include "pn532.h"
#include "driver/uart.h"
#include "esp_mac.h"

#define RXMS 10 / portTICK_PERIOD_MS
// #define PN532DEBUG

ESP_EVENT_DEFINE_BASE(PN532_EVENTS);

static bool uart_preamble(int ms);
static bool pn532_sendCommandGetAck(uint8_t cmd, uint8_t *data, int len);
static esp_err_t pn532_rx(uint8_t **data, int *len, int timout);
static bool pn532_mifareclassic_IsTrailerBlock(uint32_t uiBlock);
static int uart_tx(uint8_t *buf, uint16_t len);
static int uart_rx(uint8_t *buf, uint16_t len, TickType_t tick);
static void uart_event_task(void *pvParameters);

static SemaphoreHandle_t rxsem;

static int8_t uart;
static esp_event_loop_handle_t event_loop;
static QueueHandle_t uart_queue;

/*!
    @brief Initialize pn532 module
*/
void pn532_init()
{
    rxsem = xSemaphoreCreateMutex();
    uart = UART_NUM_2;
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(uart, &uart_config));
    // gpio_reset_pin(TX_PIN);
    // gpio_reset_pin(RX_PIN);
    ESP_ERROR_CHECK(uart_set_pin(uart, TX_PIN, RX_PIN, -1, -1));
    if (!uart_is_driver_installed(uart))
    {
        printf("Installing UART driver %d", uart);
        ESP_ERROR_CHECK(uart_driver_install(uart, 240, UART_FIFO_LEN + 1, 20, &uart_queue, 0));
    }
    // gpio_set_drive_capability(TX_PIN, GPIO_DRIVE_CAP_3); // Oomph?
    uint8_t buf[20] = {0};
    int e = sizeof(buf);
    buf[--e] = 0x55; // Idle
    buf[--e] = 0x55;
    buf[--e] = 0x55;
    ESP_ERROR_CHECK(uart_flush_input(uart));
    uart_write_bytes(uart, buf, sizeof(buf));
    uart_wait_tx_done(uart, 100 / portTICK_PERIOD_MS);
    pn532_SAMConfig();
    pn532_getFirmwareVersion();
}

/*!
    @brief  Configures the SAM (Secure Access Module)
*/
bool pn532_SAMConfig()
{
    uint8_t buf[] = {0x01};
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_SAMCONFIGURATION, buf, 1);
    esp_err_t rx = pn532_rx(NULL, NULL, 0);
    if (!tx || rx)
    {
        ESP_ERROR_CHECK_WITHOUT_ABORT(rx); // Again
        vTaskDelay(50 / portTICK_PERIOD_MS);
        // SAMConfiguration
        tx = pn532_sendCommandGetAck(PN532_COMMAND_SAMCONFIGURATION, buf, 1);
        rx = pn532_rx(NULL, NULL, 0);
        if (!tx || rx)
        {
            ESP_ERROR_CHECK_WITHOUT_ABORT(rx);
            return false;
        }
    }
    return true;
}

/*!
    @brief  Checks the firmware version of the PN5xx chip
    @returns  1 if everything executed properly, 0 for an error
*/
bool pn532_getFirmwareVersion()
{
    uint8_t *buf;
    int len;
    printf("\n");
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_GETFIRMWAREVERSION, NULL, 0);
    esp_err_t rx = pn532_rx(&buf, &len, 0);
    if (tx && !rx)
    {
        printf("PN532 Firmware found: ");
        printh(buf, 4);
        return true;
    }
    printf("FIRMWARE ERRROR %d\n", tx);
    ESP_ERROR_CHECK_WITHOUT_ABORT(rx);
    return false;
}

/*!
    @brief Sets the MxRtyPassiveActivation uint8_t of the RFConfiguration register
    @param  maxRetries    0xFF to wait forever, 0x00..0xFE to timeout after mxRetries
    @returns 1 if everything executed properly, 0 for an error
*/
bool pn532_setPassiveActivationRetries(uint8_t maxRetries)
{
    uint8_t buff[] = {
        5,    // Config item 5 (MaxRetries)
        0xFF, // MxRtyATR (default = 0xFF)
        0x01, // MxRtyPSL (default = 0x01)
        maxRetries};
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_RFCONFIGURATION, buff, sizeof(buff));
    esp_err_t rx = pn532_rx(NULL, NULL, 0);
    if (tx && !rx)
        return true;
    ESP_ERROR_CHECK(rx);
    return false;
}

/*!
    @brief for an ISO14443A target to enter the field
    @param  uid           Pointer to the array that will be populated with the card's UID (4 bytes)
    @param  timeout       Time to wait for the response
    @returns 1 if everything executed properly, 0 for an error
*/
bool pn532_readPassiveTargetID(uint8_t *uid, uint16_t timeout)
{
    uint8_t buff[] = {
        1,
        PN532_MIFARE_ISO14443A};
    uint8_t *rxdata;
    int len;
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_INLISTPASSIVETARGET, buff, sizeof(buff));
    esp_err_t rx = pn532_rx(&rxdata, &len, timeout);
    if (!tx || rx || rxdata[1] != 1)
    {
        return 0;
    }
    memcpy(uid, rxdata + 6, 4);
    return 1;
}

/*!
    @brief whether the specified block number is the sector trailer
*/
static bool pn532_mifareclassic_IsTrailerBlock(uint32_t uiBlock)
{
    // Test if we are in the small or big sectors
    if (uiBlock < 128)
        return ((uiBlock + 1) % 4 == 0);
    else
        return ((uiBlock + 1) % 16 == 0);
}

/*!
    @brief Tries to authenticate a block of memory on a MIFARE card using the
           INDATAEXCHANGE command.  See section 7.3.8 of the PN532 User Manual
           for more information on sending MIFARE and other commands.
    @param  uid           Pointer to a uint8_t array containing the card UID
    @param  blockNumber   The block number to authenticate.
    @param  keyData       Pointer to a uint8_t array containing the 6 uint8_t key value
    @returns 1 if everything executed properly, 0 for an error
*/
bool pn532_mifareclassic_AuthenticateBlock(uint8_t *uid, uint32_t blockNumber, uint8_t *keyData)
{
    uint8_t *rxdata;
    int len;
    uint8_t buff[13] = {0};
    buff[0] = 1; // Max card numbers
    buff[1] = MIFARE_CMD_AUTH_A;
    buff[2] = blockNumber; // Block Number (1K = 0..63, 4K = 0..255
    memcpy(buff + 3, keyData, 6);
    memcpy(buff + 9, uid, 4);
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_INDATAEXCHANGE, buff, sizeof(buff));
    esp_err_t rx = pn532_rx(&rxdata, &len, 200);
    if (tx && !rx && rxdata[0] == 0x00)
        return 1;
    ESP_ERROR_CHECK_WITHOUT_ABORT(rx);
    if (rxdata)
        printf("ERROR AUTH CODE:%2X\n", rxdata[0]);
    return 0;
}

/*!
    @brief Tries to read an entire 16-uint8_t data block at the specified block address.
    @param  blockNumber   The block number to authenticate.
    @param  data          Pointer to the uint8_t array that will hold the retrieved data (if any)
    @returns 1 if everything executed properly, 0 for an error
*/
bool pn532_mifareclassic_ReadDataBlock(uint8_t blockNumber, uint8_t *data)
{
    if (pn532_mifareclassic_IsTrailerBlock(blockNumber) || !data)
        return 0;
    uint8_t *rxdata;
    int len;
    uint8_t buff[] = {
        1,               // Card number
        MIFARE_CMD_READ, // Mifare Read command = 0x30
        blockNumber      // Block Number (0..63 for 1K, 0..255 for 4K)
    };
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_INDATAEXCHANGE, buff, sizeof(buff));
    esp_err_t rx = pn532_rx(&rxdata, &len, 100);
    if (!tx || rx || rxdata[0] != 0x00)
    {
        ESP_ERROR_CHECK_WITHOUT_ABORT(rx);
        // if (rxdata)
        //   printf("ERROR READ CODE:%2X\n", rxdata[0]);
        return 0;
    }
    memcpy(data, rxdata + 1, 16);
    return 1;
}

/*!
    @brief Tries to write an entire 16-uint8_t data block at the specified block
           address.
    @param  blockNumber   The block number to authenticate.
    @param  data          The uint8_t array that contains the data to write.
    @returns 1 if everything executed properly, 0 for an error
*/
bool pn532_mifareclassic_WriteDataBlock(uint8_t blockNumber, uint8_t *data)
{
    if (pn532_mifareclassic_IsTrailerBlock(blockNumber) || !data)
        return false;
    uint8_t *rxdata;
    int len;
    uint8_t buff[19] = {0};
    buff[0] = 1;                // Card number
    buff[1] = MIFARE_CMD_WRITE; // Mifare Write command = 0xA0
    buff[2] = blockNumber;      // Block Number (0..63 for 1K, 0..255 for 4K)
    size_t size = sizeof(data);
    memcpy(buff + 3, data, size); // Data Payload
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_INDATAEXCHANGE, buff, sizeof(buff));
    esp_err_t rx = pn532_rx(&rxdata, &len, 100);
    if (tx && !rx && rxdata[0] == 0x00)
        return 1;
    ESP_ERROR_CHECK_WITHOUT_ABORT(rx);
    return 1;
}

/*!
    @brief Tries to change the sector key of the chosen block
    @param blockNumber  Number of the block
    @param newKey The new key of the sector
    @returns 1 if everything executed properly, 0 for an error
*/
bool pn532_mifareclassic_ChangeKey(uint8_t blockNumber, uint8_t *newKey)
{
    int sectorNumber = ((blockNumber / 4) + 1) * 4 - 1;
    uint8_t *rxdata;
    int len;
    uint8_t buff[19] = {
        1,
        MIFARE_CMD_WRITE,
        sectorNumber};
    memcpy(buff + 3, newKey, 6);
    buff[9] = 0xFF;
    buff[10] = 0x07;
    buff[11] = 0x80;
    buff[12] = 0x69;
    memcpy(buff + 13, newKey, 6);
    bool tx = pn532_sendCommandGetAck(PN532_COMMAND_INDATAEXCHANGE, buff, sizeof(buff));
    esp_err_t rx = pn532_rx(&rxdata, &len, 100);
    if (tx && !rx && rxdata[0] == 0x00)
        return 1;
    ESP_ERROR_CHECK(rx);
    return 0;
}

/*!
    @brief Send a message to the pn532 to start the target search
*/
void pn532_startPassiveTarget()
{
    uint8_t tx[] = {1, PN532_MIFARE_ISO14443A};
    pn532_sendCommandGetAck(PN532_COMMAND_INLISTPASSIVETARGET, tx, 2);
}

/*!
    @brief Create the events in order to listen to the uart interface and receive the event when a target is readed.
        Implement "void pn532_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)" to receive the event
    @param semaphore  A pointer to the semaphore used to block the listening
*/
void pn532_startPassiveEvent(SemaphoreHandle_t *semaphore)
{
    esp_event_loop_args_t event_loop_args = {
        .queue_size = 5,
        .task_name = "loop_task", // task will be created
        .task_priority = uxTaskPriorityGet(NULL),
        .task_stack_size = 3072,
        .task_core_id = tskNO_AFFINITY};
    ESP_ERROR_CHECK(esp_event_loop_create(&event_loop_args, &event_loop));
    ESP_ERROR_CHECK(esp_event_handler_instance_register_with(event_loop, PN532_EVENTS, PN532_TARGET_FOUND_EVENT, pn532_event_handler, event_loop, NULL));
    pn532_startPassiveTarget();
    xTaskCreatePinnedToCore(uart_event_task, "uart_event_task", 3072, semaphore, 12, NULL, !xPortGetCoreID());
}

/*!
    @brief Send a command to the pn532 module and waits for ACK
    @param cmd The command code
    @param data Pointer to the data array
    @param len The length of the data array
    @returns 1 if everything executed properly, 0 for an error
*/
static bool pn532_sendCommandGetAck(uint8_t cmd, uint8_t *data, int len)
{ // Send data to PN532
    if (!xSemaphoreTake(rxsem, portMAX_DELAY))
        return 0;
    uint8_t buf[20], *b = buf;
    *b++ = 0x55;
    *b++ = 0x55;
    *b++ = 0x55;
    *b++ = 0x00; // Preamble
    *b++ = 0x00; // Start 1
    *b++ = 0xFF; // Start 2
    int l = len + 2;
    if (l >= 0x100)
    {
        *b++ = 0xFF; // Extended len
        *b++ = 0xFF;
        *b++ = (l >> 8); // len
        *b++ = (l & 0xFF);
        *b++ = -(l >> 8) - (l & 0xFF); // Checksum
    }
    else
    {
        *b++ = l;  // Len
        *b++ = -l; // Checksum
    }
    *b++ = 0xD4; // Direction (host to PN532)
    *b++ = cmd;
    uint8_t sum = 0xD4 + cmd;
    for (l = 0; l < len; l++)
        sum += data[l];
    uart_flush_input(uart);
    uart_tx(buf, b - buf);
    if (len)
        uart_tx(data, len);
    buf[0] = -sum; // Checksum
    buf[1] = 0x00; // Postamble
    uart_tx(buf, 2);
    uart_wait_tx_done(uart, 1000 / portTICK_PERIOD_MS);
    // Get ACK and check it
    if (uart_preamble(20 / portTICK_PERIOD_MS) && uart_rx(buf, 3, RXMS) == 3 &&
        buf[0] == 0x00 && buf[1] == 0xFF && buf[2] == 0x00)
    {
        xSemaphoreGive(rxsem);
        return 1;
    }
    xSemaphoreGive(rxsem);
    return 0;
}

/*!
    @brief Try to receive from pn532 module
    @param data  Pointer to the pointer of the data array
    @param len The length of the data
    @param timout Time to wait for the response
    @returns ESP_OK if received correctly
*/
static esp_err_t pn532_rx(uint8_t **data, int *len, int timout)
{
    if (!xSemaphoreTake(rxsem, portMAX_DELAY))
        return 0;
    // Recv data from PN532
    if (timout < 15)
        timout = 15;
    xSemaphoreGive(rxsem);
    if (!uart_preamble(timout / portTICK_PERIOD_MS))
        return ESP_ERR_TIMEOUT;
    uint8_t buf[4];
    if (uart_rx(buf, 4, RXMS) < 4)
        return ESP_ERR_INVALID_SIZE;
    int l = 0;
    if (buf[0] == 0xFF && buf[1] == 0xFF)
    { // Extended
        if (uart_rx(buf + 4, 3, RXMS) < 3)
            return ESP_ERR_INVALID_SIZE;
        if ((uint8_t)(buf[2] + buf[3] + buf[4]))
            return ESP_ERR_INVALID_CRC;
        l = (buf[2] << 8) + buf[3];
        if (buf[5] != 0xD5)
            return ESP_ERR_INVALID_STATE;
    }
    else
    { // Normal
        if ((uint8_t)(buf[0] + buf[1]))
            return ESP_ERR_INVALID_CRC;
        l = buf[0];
        if (buf[2] != 0xD5)
            return ESP_ERR_INVALID_STATE;
    }
    if (l < 2)
        return ESP_ERR_INVALID_SIZE;
    l -= 2;
    int sum = 0xD5 + buf[3];
    if (l)
    {
        if (data)
        {
            *len = l;
            *data = malloc(l);
            if (uart_rx(*data, l, RXMS) < l)
                return ESP_ERR_INVALID_SIZE;
            while (l)
                sum += data[0][--l];
        }
        else
            return ESP_ERR_INVALID_ARG;
    }

    if (uart_rx(buf, 2, RXMS) < 2)
        return ESP_ERR_INVALID_SIZE;
    // printh(buf,2);
    if ((uint8_t)(buf[0] + sum))
        return ESP_ERR_INVALID_CRC;
    if (buf[1])
        return ESP_ERR_INVALID_ARG;
    return ESP_OK;
}

/*!
    @brief Tries to find a preamble from the uart interface
    @param tick  Number of tick to wait
    @returns 1 if everything executed properly, 0 for an error
*/
static bool uart_preamble(int tick)
{ // Wait for preamble
    uint8_t last = 0xFF;
    while (1)
    {
        uint8_t c;
        int l = uart_read_bytes(uart, &c, 1, tick);
        if (l < 1)
            return false;
        if (last == 0x00 && c == 0xFF)
            return true;
        last = c;
    }
}

static int uart_rx(uint8_t *buf, uint16_t len, TickType_t ticks)
{
    int rx = uart_read_bytes(uart, buf, len, ticks);
#ifdef PN532DEBUG
    if (rx > 0)
    {
        printf("RX: ");
        printh(buf, len);
    }
#endif
    return rx;
}

static int uart_tx(uint8_t *buf, uint16_t len)
{
    int tx = uart_write_bytes(uart, buf, len);
#ifdef PN532DEBUG
    if (tx > 0)
    {
        printf("TX: ");
        printh(buf, len);
    }
#endif
    return tx;
}

static void uart_event_task(void *pvParameters)
{
    SemaphoreHandle_t *sem = pvParameters;
    uart_event_t event;
    for (;;)
    {
        if (xQueueReceive(uart_queue, (void *)&event, (TickType_t)portMAX_DELAY))
        {
            if (xSemaphoreTake(*sem, 25 / portTICK_PERIOD_MS))
            {
                xSemaphoreGive(*sem);
                if (event.type == UART_DATA)
                {
                    uint8_t *data;
                    int len;
                    esp_err_t rx = pn532_rx(&data, &len, 20);
                    if (!rx && data[0] == 1){
                        xQueueReset(uart_queue);
                        esp_event_post_to(event_loop, PN532_EVENTS, PN532_TARGET_FOUND_EVENT, data + 6, 4, 0);
                        }
                }
            }else{xQueueReset(uart_queue);}
        }
    }
    vTaskDelete(NULL);
}

/*!
    @brief Print an array of uint8_t formatted in hexadecimal
    @param data  Array to print
*/
void printh(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02hhX ", data[i]);
    printf("\n");
    return;
}
