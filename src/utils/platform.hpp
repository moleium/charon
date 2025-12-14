#pragma once

#if defined(_WIN32)
#define CHARON_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Psapi.h>
#include <Windows.h>
#elif defined(__linux__)
#define CHARON_LINUX
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#else
#error "Unsupported platform"
#endif

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace utils::platform {
  using byte_span = std::span<const std::uint8_t>;
  using mut_byte_span = std::span<std::uint8_t>;

  inline std::size_t page_size() {
#ifdef CHARON_WINDOWS
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
  }

  class protection_guard {
public:
    protection_guard(void* address, std::size_t size, bool executable = true) : address_(address), size_(size) {
#ifdef CHARON_WINDOWS
      DWORD new_prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
      VirtualProtect(address_, size_, new_prot, &old_prot_win_);
#else
      auto page = reinterpret_cast<uintptr_t>(address_) & ~(page_size() - 1);
      auto len = (reinterpret_cast<uintptr_t>(address_) + size_ - page + page_size() - 1) & ~(page_size() - 1);
      aligned_addr_ = reinterpret_cast<void*>(page);
      aligned_size_ = len;

      int prot = PROT_READ | PROT_WRITE | (executable ? PROT_EXEC : 0);
      mprotect(aligned_addr_, aligned_size_, prot);
#endif
    }

    ~protection_guard() {
#ifdef CHARON_WINDOWS
      DWORD dummy;
      VirtualProtect(address_, size_, old_prot_win_, &dummy);
#else
      mprotect(aligned_addr_, aligned_size_, PROT_READ | PROT_EXEC);
#endif
    }

private:
    void* address_;
    std::size_t size_;
#ifdef CHARON_WINDOWS
    DWORD old_prot_win_ = 0;
#else
    void* aligned_addr_ = nullptr;
    std::size_t aligned_size_ = 0;
#endif
  };

  inline void* allocate_exec_trampoline(std::size_t size) {
#ifdef CHARON_WINDOWS
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return ptr == MAP_FAILED ? nullptr : ptr;
#endif
  }
} // namespace utils::platform
