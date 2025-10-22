#pragma once

// clang-format off
#include <winsock2.h>
#include <Windows.h>
#include <cstdint>
#include <expected>
#include <ranges>
#include <vector>

#include <utils/logger.hpp>
#include <utils/pattern.hpp>

import zydis;
import address;
// clang-format on

using namespace zydis::assembler;

namespace patcher {
  inline std::expected<void, const char*> apply_patch() {
    auto patch_site_exp = utils::pattern::find("E8 ? ? ? ? 0F B6 44 24 ? 89 C1 C1 E9");
    if (!patch_site_exp) {
      return std::unexpected("pattern not found");
    }
    utils::address patch_site = *patch_site_exp;
    utils::log("pattern found at: {:#x}", patch_site);

    auto* payload_mem = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!payload_mem) {
      return std::unexpected("failed to allocate memory");
    }

    code_block payload;
    payload << mov(registers::rax, 0x0101010101010101);
    payload << mov(qword_ptr(registers::rdx, 0), registers::rax);
    payload << mov(qword_ptr(registers::rdx, 8), registers::rax);
    payload << ret();

    auto encoded_payload = payload.encode();
    std::ranges::copy(encoded_payload, static_cast<uint8_t*>(payload_mem));

    code_block trampoline;
    trampoline << mov(registers::rax, reinterpret_cast<uintptr_t>(payload_mem));
    trampoline << instruction(ZYDIS_MNEMONIC_CALL, registers::rax);

    auto trampoline_bytes = trampoline.encode();

    size_t overwritten_len = 0;
    while (overwritten_len < trampoline_bytes.size()) {
      auto instr = zydis::disassemble(static_cast<const uint8_t*>(patch_site) + overwritten_len);
      if (!instr) {
        VirtualFree(payload_mem, 0, MEM_RELEASE);
        return std::unexpected("failed to disassemble original code");
      }
      overwritten_len += instr->decoded.length;
    }

    std::vector<uint8_t> final_patch = trampoline_bytes;
    final_patch.resize(overwritten_len, nop().encode()[0]);

    DWORD old_prot = 0;
    if (!VirtualProtect(patch_site, final_patch.size(), PAGE_EXECUTE_READWRITE, &old_prot)) {
      VirtualFree(payload_mem, 0, MEM_RELEASE);
      return std::unexpected("failed to change memory protection");
    }

    std::ranges::copy(final_patch, static_cast<uint8_t*>(patch_site));
    VirtualProtect(patch_site, final_patch.size(), old_prot, &old_prot);

    return {};
  }
}

