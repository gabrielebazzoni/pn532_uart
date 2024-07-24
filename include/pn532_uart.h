#include "esp_event.h"

#define __PN532_H__

// PN532 Commands
#define PN532_COMMAND_DIAGNOSE (0x00)
#define PN532_COMMAND_GETFIRMWAREVERSION (0x02)
#define PN532_COMMAND_GETGENERALSTATUS (0x04)
#define PN532_COMMAND_READREGISTER (0x06)
#define PN532_COMMAND_WRITEREGISTER (0x08)
#define PN532_COMMAND_READGPIO (0x0C)
#define PN532_COMMAND_WRITEGPIO (0x0E)
#define PN532_COMMAND_SETSERIALBAUDRATE (0x10)
#define PN532_COMMAND_SETPARAMETERS (0x12)
#define PN532_COMMAND_SAMCONFIGURATION (0x14)
#define PN532_COMMAND_POWERDOWN (0x16)
#define PN532_COMMAND_RFCONFIGURATION (0x32)
#define PN532_COMMAND_RFREGULATIONTEST (0x58)
#define PN532_COMMAND_INJUMPFORDEP (0x56)
#define PN532_COMMAND_INJUMPFORPSL (0x46)
#define PN532_COMMAND_INLISTPASSIVETARGET (0x4A)
#define PN532_COMMAND_INATR (0x50)
#define PN532_COMMAND_INPSL (0x4E)
#define PN532_COMMAND_INDATAEXCHANGE (0x40)
#define PN532_COMMAND_INCOMMUNICATETHRU (0x42)
#define PN532_COMMAND_INDESELECT (0x44)
#define PN532_COMMAND_INRELEASE (0x52)
#define PN532_COMMAND_INSELECT (0x54)
#define PN532_COMMAND_INAUTOPOLL (0x60)
#define PN532_COMMAND_TGINITASTARGET (0x8C)
#define PN532_COMMAND_TGSETGENERALBYTES (0x92)
#define PN532_COMMAND_TGGETDATA (0x86)
#define PN532_COMMAND_TGSETDATA (0x8E)
#define PN532_COMMAND_TGSETMETADATA (0x94)
#define PN532_COMMAND_TGGETINITIATORCOMMAND (0x88)
#define PN532_COMMAND_TGRESPONSETOINITIATOR (0x90)
#define PN532_COMMAND_TGGETTARGETSTATUS (0x8A)

#define PN532_MIFARE_ISO14443A (0x00)

// Mifare Commands
#define MIFARE_CMD_AUTH_A (0x60)
#define MIFARE_CMD_READ (0x30)
#define MIFARE_CMD_WRITE (0xA0)

#define TX_PIN 17
#define RX_PIN 16

#define PN532_TARGET_FOUND_EVENT 0

ESP_EVENT_DECLARE_BASE(PN532_EVENTS);

void pn532_init();
bool pn532_getFirmwareVersion();
bool pn532_SAMConfig();
bool pn532_readPassiveTargetID(uint8_t *uid, uint16_t timeout);
bool pn532_setPassiveActivationRetries(uint8_t maxRetries);
bool pn532_mifareclassic_AuthenticateBlock(uint8_t *uid, uint32_t blockNumber, uint8_t *keyData);
bool pn532_mifareclassic_ReadDataBlock(uint8_t blockNumber, uint8_t *data);
bool pn532_mifareclassic_WriteDataBlock(uint8_t blockNumber, uint8_t *data);
bool pn532_mifareclassic_ChangeKey(uint8_t blockNumber, uint8_t *newKey);
void printh(uint8_t *data, int len);
void pn532_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data);
void pn532_startPassiveEvent(SemaphoreHandle_t *s);
void pn532_startPassiveTarget();