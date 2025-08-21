#ifndef KLUTSHNIK_BLE_H
#define KLUTSHNIK_BLE_H

#include "klutshnik.h"

int ble_init(CFG *cfg);
void reset_ble(void);
int send_plaintext(const uint8_t *msg, const size_t len);

#endif // KLUTSHNIK_BLE_H
