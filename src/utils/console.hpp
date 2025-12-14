#pragma once

#include <cstdio>
#include <utils/platform.hpp>

namespace utils {
  inline void show_console() {
#ifdef CHARON_WINDOWS
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONIN$", "r", stdin);
#else
    setvbuf(stdout, nullptr, _IOLBF, 0);
#endif
  }
} // namespace utils
