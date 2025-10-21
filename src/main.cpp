#include <Windows.h>
#include <cstdint>
#include <expected>
#include <print>
#include <ranges>
#include <string_view>
#include <thread>
#include <vector>
#include "utils/console.hpp"
#include "utils/pattern.hpp"

import zydis;

namespace patcher {
  std::expected<void, const char*> apply_patch() {
    constexpr std::string_view call_pattern = "E8 ?? ?? ?? ?? 0F B6 44 24 ?? 89 C1 C1 E9 ?? 48 8D 3D";

    auto find_result = utils::pattern::find(call_pattern);
    if (!find_result) {
      return std::unexpected("failed to find call pattern");
    }

    const auto target_addr = static_cast<std::uintptr_t>(*find_result);
    std::println("pattern found at: {:#x}", target_addr);

    using namespace zydis::assembler;
    code_block patch_block;

    patch_block << instruction(ZYDIS_MNEMONIC_XOR, registers::eax, registers::eax);
    patch_block << mov(qword_ptr(registers::rdx, 0), registers::rax);
    patch_block << mov(qword_ptr(registers::rdx, 8), registers::rax);

    auto patch_bytes = patch_block.encode();
    std::span<const std::byte> patch_bytes(
      reinterpret_cast<const std::byte*>(patch_bytes.data()), patch_bytes.size()
    );

    size_t overwritten_length = 0;
    for (int i = 0; i < 2; ++i) {
      auto instr = zydis::disassemble(reinterpret_cast<uint8_t*>(target_addr + overwritten_length));
      if (!instr) {
        return std::unexpected("failed to disassemble original code");
      }
      overwritten_length += instr->decoded.length;
    }

    if (overwritten_length < patch_bytes.size()) {
      return std::unexpected("patch size mismatch");
    }

    DWORD old_protection = 0;
    if (!VirtualProtect(
          reinterpret_cast<void*>(target_addr), patch_bytes.size(), PAGE_EXECUTE_READWRITE, &old_protection
        )) {
      return std::unexpected("failed to change memory protection");
    }

    std::ranges::copy(patch_bytes, reinterpret_cast<std::byte*>(target_addr));

    VirtualProtect(reinterpret_cast<void*>(target_addr), patch_bytes.size(), old_protection, &old_protection);

    return {};
  }

  void main_thread() {
    utils::show_console();

    if (!zydis::init(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, ZYDIS_FORMATTER_STYLE_INTEL)) {
      std::println("failed to initialize zydis");
      return;
    }

    if (auto result = apply_patch(); result.has_value()) {
      std::println("patch applied successfully");
    } else {
      std::println("patch failed: {}", result.error());
    }
  }

} // namespace patcher

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    std::jthread patch_thread(patcher::main_thread);
    patch_thread.detach();
  }
  return TRUE;
}
