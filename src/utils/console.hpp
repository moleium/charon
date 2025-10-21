#pragma once

#include <Windows.h>
#include <cstdio>

namespace utils {
  inline void show_console() {
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONIN$", "r", stdin);
  }
} // namespace utils
