#ifndef ASB_NVIDIA_H
#define ASB_NVIDIA_H

#include <windows.h>
#include <stddef.h>

BOOL nvidia_initialize(void);
BOOL nvidia_get_icd_path(wchar_t *path, size_t capacity);
BOOL nvidia_map_adapter_luid(LUID *luid);
BOOL nvidia_map_guest_luid(LUID *luid);

#endif
