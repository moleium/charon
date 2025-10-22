#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <Psapi.h>

import zydis;
import address;

namespace utils::pattern {

  enum class error {
    malformed_pattern,
    memory_region_not_found,
    pattern_not_found,
    disassembly_failed,
    rip_relative_operand_not_found,
  };

  namespace detail {
    std::expected<std::vector<std::optional<std::uint8_t>>, error> parse_pattern(std::string_view pattern_str) {
      std::vector<std::optional<std::uint8_t>> result;
      result.reserve(pattern_str.length() / 3);

      for (auto it = pattern_str.begin(); it != pattern_str.end(); ++it) {
        if (*it == ' ') {
          continue;
        }

        if (*it == '?') {
          if (const auto next = std::next(it); next != pattern_str.end() && *next == '?') {
            ++it;
          }
          result.emplace_back(std::nullopt);
          continue;
        }

        if (std::next(it) == pattern_str.end()) {
          return std::unexpected(error::malformed_pattern);
        }

        std::uint8_t byte{};
        if (std::from_chars(&*it, &*(it + 2), byte, 16).ec != std::errc()) {
          return std::unexpected(error::malformed_pattern);
        }

        result.emplace_back(byte);
        ++it;
      }

      return result;
    }
  } // namespace detail

  std::optional<std::span<const std::uint8_t>> get_mem() {
    const HMODULE module_handle = GetModuleHandle(nullptr);
    if (!module_handle) {
      return std::nullopt;
    }

    MODULEINFO module_info{};
    if (!GetModuleInformation(GetCurrentProcess(), module_handle, &module_info, sizeof(module_info))) {
      return std::nullopt;
    }

    const auto start_addr = static_cast<const std::uint8_t*>(module_info.lpBaseOfDll);
    const std::size_t size = module_info.SizeOfImage;
    return std::span{start_addr, size};
  }

  std::expected<address, error> find(std::span<const std::uint8_t> memory, std::string_view pattern) {
    auto parsed_pattern_exp = detail::parse_pattern(pattern);
    if (!parsed_pattern_exp) {
      return std::unexpected(parsed_pattern_exp.error());
    }
    const auto& parsed_pattern = *parsed_pattern_exp;

    const std::size_t pattern_len = parsed_pattern.size();
    if (memory.size() < pattern_len || pattern_len == 0) {
      return std::unexpected(error::pattern_not_found);
    }

    std::array<std::size_t, 256> bad_char_shift{};
    bad_char_shift.fill(pattern_len);

    for (std::size_t i = 0; i < pattern_len - 1; ++i) {
      if (const auto& byte_opt = parsed_pattern[i]; byte_opt.has_value()) {
        bad_char_shift[*byte_opt] = pattern_len - 1 - i;
      }
    }

    std::size_t pos = 0;
    while (pos <= memory.size() - pattern_len) {
      int j = pattern_len - 1;
      while (j >= 0 && (!parsed_pattern[j].has_value() || parsed_pattern[j].value() == memory[pos + j])) {
        --j;
      }

      if (j < 0) {
        return address{memory.data() + pos};
      }

      pos += bad_char_shift[memory[pos + pattern_len - 1]];
    }

    return std::unexpected(error::pattern_not_found);
  }

  std::expected<address, error> find(std::string_view pattern) {
    auto memory_region = get_mem();
    if (!memory_region) {
      return std::unexpected(error::memory_region_not_found);
    }
    return find(*memory_region, pattern);
  }

  std::expected<address, error> find_rva(std::span<const std::uint8_t> memory, std::string_view pattern) {
    auto pattern_addr_exp = find(memory, pattern);
    if (!pattern_addr_exp) {
      return std::unexpected(pattern_addr_exp.error());
    }
    const address pattern_addr = *pattern_addr_exp;

    auto instruction_opt = zydis::disassemble(static_cast<const std::uint8_t*>(pattern_addr));
    if (!instruction_opt) {
      return std::unexpected(error::disassembly_failed);
    }

    auto absolute_addr_opt = instruction_opt->get_absolute_address(pattern_addr);
    if (!absolute_addr_opt) {
      return std::unexpected(error::rip_relative_operand_not_found);
    }

    return *absolute_addr_opt;
  }

  std::expected<address, error> find_rva(std::string_view pattern) {
    auto memory_region = get_mem();
    if (!memory_region) {
      return std::unexpected(error::memory_region_not_found);
    }
    return find_rva(*memory_region, pattern);
  }

} // namespace utils::pattern
