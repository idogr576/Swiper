#pragma once

#define PRINT printf

#define LOG_INFO(fmt, ...) PRINT("[INFO] " fmt, ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) PRINT("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) // Becomes nothing in regular compilation

#endif