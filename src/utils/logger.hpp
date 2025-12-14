#pragma once

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <print>

#include <utils/platform.hpp>

namespace utils {

  class logger {
public:
    static logger& instance() {
      static logger instance;
      return instance;
    }

    template <typename... Args>
    void println(std::format_string<Args...> fmt, Args&&... args) {
      std::lock_guard lock(mutex_);
      auto msg = std::format(fmt, std::forward<Args>(args)...);
      std::println("{}", msg);

      if (log_file_.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_str = std::format("{:%Y-%m-%d %H:%M:%S}", now);
        std::println(log_file_, "[{}] {}", time_str, msg);
        log_file_.flush();
      }
    }

    ~logger() {
      if (log_file_.is_open())
        log_file_.close();
    }

private:
    logger() {
      auto now = std::chrono::system_clock::now();

#ifdef CHARON_WINDOWS
      auto path = std::format("C:\\temp\\charclient_{:%Y%m%d_%H%M%S}.log", now);
      std::filesystem::create_directories("C:\\temp");
#else
      auto path = std::format("/tmp/charclient_{:%Y%m%d_%H%M%S}.log", now);
#endif

      log_file_.open(path, std::ios::out | std::ios::app);
    }

    std::ofstream log_file_;
    std::mutex mutex_;
  };

  template <typename... Args>
  inline void log(std::format_string<Args...> fmt, Args&&... args) {
    logger::instance().println(fmt, std::forward<Args>(args)...);
  }

} // namespace utils
