// The Tor built into the app (tor/src/lib.rs, Arti), for iOS. Swift: import KaspaChatTor.
#pragma once
#include <stdint.h>

// Connects to Tor (state and cache under dir) and opens a SOCKS5 port on 127.0.0.1 that only reaches the hosts given
// (comma-separated). Blocks until Tor is ready: call it off the main thread. Returns the port, or -1 on failure.
int32_t kc_tor_start(const char *dir, const char *hosts);

// Why the last start failed.
const char *kc_tor_error(void);
