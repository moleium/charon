#pragma once

#include <algorithm>
#include <expected>
#include <optional>
#include <ranges>
#include <string>
#include <utils/logger.hpp>
#include <utils/platform.hpp>
#include <vector>

import zydis;
import address;

namespace utils::process {

  struct module_info {
    platform::byte_span full_image;
    platform::byte_span text_section;
    uintptr_t base_address;
  };

  inline std::optional<module_info> get_main_module() {
#ifdef CHARON_WINDOWS
    HMODULE hMod = GetModuleHandle(nullptr);
    if (!hMod)
      return std::nullopt;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
      return std::nullopt;

    auto base = reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll);
    return module_info{
      .full_image = {base, mi.SizeOfImage},
      .text_section = {base, mi.SizeOfImage},
      .base_address = reinterpret_cast<uintptr_t>(base)
    };

#else
    struct iter_data {
      uintptr_t base = 0;
      platform::byte_span image{};
      platform::byte_span text{};
    } data;

    dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t, void* ptr) -> int {
        auto* d = static_cast<iter_data*>(ptr);
        // an empty name indicates the main executable
        if (info->dlpi_name && info->dlpi_name[0] != '\0')
          return 0;

        d->base = info->dlpi_addr;

        uintptr_t min_addr = -1;
        uintptr_t max_addr = 0;

        for (int i = 0; i < info->dlpi_phnum; ++i) {
          const auto& ph = info->dlpi_phdr[i];
          if (ph.p_type == PT_LOAD) {
            uintptr_t start = info->dlpi_addr + ph.p_vaddr;
            uintptr_t end = start + ph.p_memsz;
            if (start < min_addr)
              min_addr = start;
            if (end > max_addr)
              max_addr = end;

            if (ph.p_flags & PF_X) {
              d->text = {reinterpret_cast<const uint8_t*>(start), ph.p_memsz};
            }
          }
        }

        if (max_addr > min_addr) {
          d->image = {reinterpret_cast<const uint8_t*>(min_addr), static_cast<size_t>(max_addr - min_addr)};
        }
        return 1;
      },
      &data
    );

    if (data.image.empty())
      return std::nullopt;
    if (data.text.empty())
      data.text = data.image;

    return module_info{data.image, data.text, data.base};
#endif
  }

  inline std::optional<uintptr_t> find_bytes(platform::byte_span range, std::string_view needle) {
    auto it = std::search(range.begin(), range.end(), needle.begin(), needle.end());
    if (it == range.end())
      return std::nullopt;
    return reinterpret_cast<uintptr_t>(&*it);
  }

  inline std::expected<utils::address, std::string> find_call(std::string_view data_string) {
    auto mod_opt = get_main_module();
    if (!mod_opt)
      return std::unexpected("failed to get main module info");

    auto& mod = *mod_opt;

    auto string_addr_opt = find_bytes(mod.full_image, data_string);
    if (!string_addr_opt)
      return std::unexpected("target string not found in module");

    uintptr_t target_data_addr = *string_addr_opt;
    utils::log("found anchor string at {:#x}", target_data_addr);

    const uint8_t* ref_site = nullptr;
    {
      const uint8_t* p = mod.text_section.data();
      const uint8_t* end = p + mod.text_section.size();
      while (p < end) {
        auto instr_opt = zydis::disassemble(p);
        if (!instr_opt) {
          p++;
          continue;
        }
        const auto& instr = *instr_opt;
        bool found_ref = false;
        if (instr.is_relative()) {
          if (auto abs_opt = instr.get_absolute_address(reinterpret_cast<uintptr_t>(p));
              abs_opt && *abs_opt == target_data_addr) {
            found_ref = true;
          }
        }
        if (!found_ref) {
          for (int i = 0; i < instr.decoded.operand_count_visible; ++i) {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.value.u == target_data_addr) {
              found_ref = true;
              break;
            }
          }
        }
        if (found_ref) {
          ref_site = p;
          break;
        }
        p += instr.decoded.length;
      }
    }

    if (!ref_site) {
      return std::unexpected("reference to string not found in text section");
    }
    utils::log("found reference to string at {:#x}", reinterpret_cast<uintptr_t>(ref_site));

    constexpr size_t search_window_size = 2048;
    const uint8_t* window_start = (ref_site > mod.text_section.data() + search_window_size)
                                    ? ref_site - search_window_size
                                    : mod.text_section.data();

    const uint8_t* p = window_start;
    const uint8_t* end = ref_site;
    const uint8_t* last_setup_inst = nullptr;
    const uint8_t* candidate_call = nullptr;

    while (p < end) {
      auto instr_opt = zydis::disassemble(p);
      if (!instr_opt) {
        p++;
        continue;
      }
      const auto& instr = *instr_opt;

      // mov reg, 0x10
      // windows: mov r8d, 0x10 (or r8) - 3rd argument
      // linux: mov ESI, 0x10 (or rsi) - 2nd argument
      if (instr.decoded.mnemonic == ZYDIS_MNEMONIC_MOV && instr.decoded.operand_count_visible >= 2 &&
          instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instr.operands[1].imm.value.u == 0x10) {

        auto reg = instr.operands[0].reg.value;
        bool is_setup = false;

#ifdef CHARON_WINDOWS
        if (reg == ZYDIS_REGISTER_R8D || reg == ZYDIS_REGISTER_R8)
          is_setup = true;
#else
        if (reg == ZYDIS_REGISTER_ESI || reg == ZYDIS_REGISTER_SI)
          is_setup = true;
#endif

        if (is_setup) {
          last_setup_inst = p;
        }
      }

      if (instr.decoded.mnemonic == ZYDIS_MNEMONIC_CALL && last_setup_inst) {
        if ((p - last_setup_inst) < 64) {
          candidate_call = p;
          utils::log(
            "found probable call at {:#x} after size setup at {:#x}", reinterpret_cast<uintptr_t>(p),
            reinterpret_cast<uintptr_t>(last_setup_inst)
          );
        }
      }
      p += instr.decoded.length;
    }

    if (candidate_call) {
      return utils::address{const_cast<uint8_t*>(candidate_call)};
    }

    return std::unexpected("could not find call signature near string reference");
  }

} // namespace utils::process
