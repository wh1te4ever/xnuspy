#ifndef UTILS
#define UTILS

#include <stdbool.h>
#include <stdint.h>

#include <xnuspy/xnuspy_structs.h>

__attribute__ ((naked)) uint64_t current_thread(void);
struct _vm_map *current_map(void);
bool is_14_5_and_above(void);
void ipc_port_release_send_wrapper(void *);

#endif
