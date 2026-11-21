#pragma once

#include <stddef.h>

#ifdef _WIN32
#define STASIVYN_API __declspec(dllexport)
#define STASIVYN_CALL __cdecl
#else
#define STASIVYN_API
#define STASIVYN_CALL
#endif

/* status: 0=unknown/clean-no-match, 1=known hash, 2=YARA match, negative=error */
extern "C" {
STASIVYN_API int STASIVYN_CALL stasivyn_initialize(const wchar_t* hash_database, const wchar_t* rules_directory);
STASIVYN_API int STASIVYN_CALL stasivyn_scan_file(const wchar_t* file_path, int* status,
                                                   wchar_t* message, size_t message_capacity);
STASIVYN_API void STASIVYN_CALL stasivyn_cleanup(void);
}
