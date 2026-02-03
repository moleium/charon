#pragma once

#include <cstring>
#include <expected>
#include <ranges>
#include <vector>

#include <utils/logger.hpp>
#include <utils/platform.hpp>
#include <utils/process.hpp>

import zydis;
import address;

using namespace zydis::assembler;

namespace patcher {
  inline std::expected<void, std::string> apply_patch() {
    const auto anchor = "session_key_evp";

    auto patch_site_exp = utils::process::find_call(anchor);
    if (!patch_site_exp) {
      return std::unexpected(patch_site_exp.error());
    }

    utils::address patch_site = *patch_site_exp;
    utils::log("target call found at: {:#x}", patch_site);

    const size_t alloc_size = 4096;
    auto* mem = utils::platform::allocate_exec_trampoline(alloc_size);
    if (!mem)
      return std::unexpected("failed to allocate memory for payload");

    uint8_t* mem_byte = static_cast<uint8_t*>(mem);

    uint8_t* static_buffer = mem_byte + 2048;
    std::memset(static_buffer, 0x01, 256);

    code_block trampoline;
    trampoline << mov(registers::rax, reinterpret_cast<uintptr_t>(mem));
    trampoline << instruction(ZYDIS_MNEMONIC_CALL, registers::rax);

    auto trampoline_bytes = trampoline.encode();

    size_t overwritten_len = 0;
    std::vector<uint8_t> stolen_bytes;
    bool first_instr = true;

    while (overwritten_len < trampoline_bytes.size()) {
      auto instr = zydis::disassemble(static_cast<const uint8_t*>(patch_site) + overwritten_len);
      if (!instr)
        return std::unexpected("failed to disassemble during overwrite calculation");

      if (first_instr) {
        first_instr = false;
      } else {
        const uint8_t* p = static_cast<const uint8_t*>(patch_site) + overwritten_len;
        stolen_bytes.insert(stolen_bytes.end(), p, p + instr->decoded.length);
      }

      overwritten_len += instr->decoded.length;
    }

    code_block payload;

#ifdef CHARON_WINDOWS
    payload << mov(registers::rax, 0x0101010101010101);
    payload << mov(qword_ptr(registers::rdx, 0), registers::rax);
    payload << mov(qword_ptr(registers::rdx, 8), registers::rax);
#else
    payload << mov(registers::rax, 0x0101010101010101);
    payload << mov(qword_ptr(registers::rdi, 0), registers::rax);
    payload << mov(qword_ptr(registers::rdi, 8), registers::rax);
#endif

    auto encoded_payload = payload.encode();

    encoded_payload.insert(encoded_payload.end(), stolen_bytes.begin(), stolen_bytes.end());

    code_block ret_block;
    ret_block << ret();
    auto ret_bytes = ret_block.encode();
    encoded_payload.insert(encoded_payload.end(), ret_bytes.begin(), ret_bytes.end());

    std::memcpy(mem_byte, encoded_payload.data(), encoded_payload.size());

    std::vector<uint8_t> final_patch = trampoline_bytes;
    while (final_patch.size() < overwritten_len) {
      final_patch.push_back(0x90); // nop
    }

    {
      utils::platform::protection_guard guard(patch_site, final_patch.size(), true);
      std::memcpy(patch_site, final_patch.data(), final_patch.size());
    }

    utils::log("patch applied successfully, overwrote {} bytes", overwritten_len);
    return {};
  }
} // namespace patcher
