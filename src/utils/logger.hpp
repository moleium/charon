#pragma once

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <print>
#include <syncstream>

namespace utils {

class logger {
public:
  static logger& instance() {
    static logger instance;
    return instance;
  }

  template<typename... Args>
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

  template<typename... Args>
  void print(std::format_string<Args...> fmt, Args&&... args) {
    std::lock_guard lock(mutex_);

    auto msg = std::format(fmt, std::forward<Args>(args)...);

    std::print("{}", msg);

    if (log_file_.is_open()) {
      std::print(log_file_, "{}", msg);
      log_file_.flush();
    }
  }

  ~logger() {
    if (log_file_.is_open()) {
      log_file_.close();
    }
  }

private:
  logger() {
    auto now = std::chrono::system_clock::now();
    auto filename = std::format("D:\\charclient_{:%Y%m%d_%H%M%S}.log", now);

    log_file_.open(filename, std::ios::out | std::ios::app);
    if (log_file_.is_open()) {
      log_file_.flush();
    }
  }

  logger(const logger&) = delete;
  logger& operator=(const logger&) = delete;

  std::ofstream log_file_;
  std::mutex mutex_;
};

template<typename... Args>
inline void log(std::format_string<Args...> fmt, Args&&... args) {
  logger::instance().println(fmt, std::forward<Args>(args)...);
}

} // namespace utils

