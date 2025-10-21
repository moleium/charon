#include "sockpp/tcp_acceptor.h"
#include "sockpp/tcp_connector.h"
#include "sockpp/version.h"

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

#pragma comment(lib, "Ws2_32.lib")

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

    std::ranges::copy(patch_bytes, reinterpret_cast<unsigned char*>(target_addr));

    VirtualProtect(reinterpret_cast<void*>(target_addr), patch_bytes.size(), old_protection, &old_protection);
    return {};
  }
} // namespace patcher

namespace proxy {
  constexpr uint16_t local_port = 7853;
  constexpr std::string_view remote_host = "78.138.44.207";

  void relay_data(sockpp::tcp_socket source, sockpp::tcp_socket destination, std::string_view direction) {
    std::vector<char> buffer(4096);

    while (true) {
      auto read_result = source.read(buffer.data(), buffer.size());
      if (!read_result) {
        std::println("[{}] connection closed or read error: {}", direction, read_result.error_message());
        break;
      }

      size_t bytes_read = read_result.value();
      if (bytes_read == 0) {
        std::println("[{}] connection gracefully closed.", direction);
        break;
      }

      std::println("[{}] relaying {} bytes", direction, bytes_read);

      auto write_result = destination.write_n(buffer.data(), bytes_read);
      if (!write_result) {
        std::println("[{}] write error: {}", direction, write_result.error_message());
        break;
      }
    }
    destination.shutdown();
  }

  [[nodiscard]] std::expected<void, const char*> run_proxy() {
    sockpp::initialize();

    sockpp::tcp_acceptor acceptor(local_port);
    if (!acceptor) {
      return std::unexpected("failed to create tcp acceptor");
    }
    std::println("proxy listening on port {}", acceptor.address().port());

    auto accept_result = acceptor.accept();
    if (!accept_result) {
      return std::unexpected("failed to accept client connection");
    }

    sockpp::tcp_socket client_socket = accept_result.release();
    std::println("client connected from {}", client_socket.peer_address().to_string());

    sockpp::tcp_connector remote_socket;
    if (!remote_socket.connect({remote_host.data(), local_port})) {
      return std::unexpected("failed to connect to remote server");
    }
    std::println("successfully connected to remote server {}", remote_socket.address().to_string());

    auto remote_clone_res = remote_socket.clone();
    if (!remote_clone_res) {
      return std::unexpected("failed to clone remote socket");
    }

    auto client_clone_res = client_socket.clone();
    if (!client_clone_res) {
      return std::unexpected("failed to clone client socket");
    }

    std::jthread client_server(relay_data, std::move(client_socket), remote_clone_res.release(), "CLIENT -> SERVER");
    std::jthread server_client(relay_data, std::move(remote_socket), client_clone_res.release(), "SERVER -> CLIENT");

    client_server.detach();
    server_client.detach();

    return {};
  }
} // namespace proxy

namespace patcher {
  void main_thread() {
    utils::show_console();
    if (!zydis::init(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, ZYDIS_FORMATTER_STYLE_INTEL)) {
      std::println("failed to initialize zydis");
      return;
    }

    if (auto result = apply_patch(); result.has_value()) {
      std::println("patch applied successfully");
      if (auto proxy_result = proxy::run_proxy(); !proxy_result.has_value()) {
        std::println("proxy failed to start: {}", proxy_result.error());
      }
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
