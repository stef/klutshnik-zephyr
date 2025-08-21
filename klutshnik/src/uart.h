#ifndef KLUTSHNIK_UART_H
#define KLUTSHNIK_UART_H

#include "klutshnik.h"

int uart_init(CFG *cfg);
int is_connected(void);
int read_raw(const size_t size);

#endif // KLUTSHNIK_UART_H
