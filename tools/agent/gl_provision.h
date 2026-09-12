#ifndef GL_PROVISION_H
#define GL_PROVISION_H

#include <windows.h>

BOOL gl_uses_system_runtime(void);
BOOL gl_provision_runtime(const wchar_t *dir, const wchar_t *native_dir,
                          const wchar_t *sys, BOOL *native_runtime);

#endif
