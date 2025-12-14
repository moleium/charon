//clang-format off
#include <network/tcp.hpp>
#include <thread>
#include <utils/console.hpp>
#include <utils/logger.hpp>
#include <utils/patcher.hpp>
#include <utils/platform.hpp>

#ifdef CHARON_WINDOWS
#include <winsock2.h>
#include <Windows.h>
#endif

import zydis;
// clang-format on

namespace {
  void main_thread() {
    utils::show_console();

    if (!zydis::init(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, ZYDIS_FORMATTER_STYLE_INTEL)) {
      utils::log("failed to initialize zydis");
      return;
    }

    utils::log(
      "charon initialized on {}",
#ifdef CHARON_WINDOWS
      "windows"
#else
      "linux"
#endif
    );

    if (auto result = patcher::apply_patch(); result.has_value()) {
      utils::log("patch applied successfully");
      if (auto proxy_result = proxy::run_proxy(); !proxy_result.has_value()) {
        utils::log("proxy failed to start: {}", proxy_result.error());
      }
    } else {
      utils::log("patch failed: {}", result.error());
    }
  }
} // namespace

#ifdef CHARON_WINDOWS
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    std::jthread patch_thread(main_thread);
    patch_thread.detach();
  }
  return TRUE;
}
#else
__attribute__((constructor)) void linux_main() {
  std::jthread patch_thread(main_thread);
  patch_thread.detach();
}
#endif
