// clang-format off
#include "sockpp/tcp_acceptor.h"
#include "sockpp/tcp_connector.h"
#include "sockpp/udp_socket.h"
#include "sockpp/version.h"

#include <Windows.h>
#include <cstdint>
#include <exception>
#include <expected>
#include <print>
#include <ranges>
#include <string_view>
#include <thread>
#include <vector>

#include "utils/console.hpp"
#include "utils/logger.hpp"
#include "utils/packet.hpp"
#include "utils/pattern.hpp"

import zydis;
import address;
// clang-format on

#pragma comment(lib, "Ws2_32.lib")

namespace patcher {
  std::expected<void, const char*> apply_patch() {
    auto patch_site_exp = utils::pattern::find("E8 ?? ?? ?? ?? 0F B6 44 24 ?? 89 C1 C1 E9 ?? 48 8D 3D");
    if (!patch_site_exp) {
      return std::unexpected("pattern not found");
    }
    utils::address patch_site = *patch_site_exp;
    utils::log("pattern found at: {:#x}", patch_site);

    auto* payload_mem = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!payload_mem) {
      return std::unexpected("failed to allocate memory");
    }

    using namespace zydis::assembler;
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
    final_patch.resize(overwritten_len, 0x90);

    DWORD old_prot = 0;
    if (!VirtualProtect(patch_site, final_patch.size(), PAGE_EXECUTE_READWRITE, &old_prot)) {
      VirtualFree(payload_mem, 0, MEM_RELEASE);
      return std::unexpected("failed to change memory protection");
    }

    std::ranges::copy(final_patch, static_cast<uint8_t*>(patch_site));
    VirtualProtect(patch_site, final_patch.size(), old_prot, &old_prot);

    return {};
  }
} // namespace patcher

namespace proxy {
  constexpr uint16_t local_port = 7853;
  constexpr std::string_view remote_host = "78.138.44.207";

  void run_udp_proxy(const std::string& remote_ip, uint16_t game_port, const std::string& room_key_str) {
    utils::log("starting udp proxy for remote {}:{}", remote_ip, game_port);
    sockpp::udp_socket local_socket(game_port);
    if (!local_socket) {
      utils::log("failed to create udp socket on port {}", game_port);
      return;
    }
    utils::log("udp proxy listening on port {}", game_port);

    std::vector<char> buffer(4096);
    sockpp::inet_address client_addr;
    sockpp::inet_address remote_addr(remote_ip, game_port);
    bool client_addr_known = false;

    while (true) {
      sockpp::inet_address src_addr;
      auto read_res = local_socket.recv_from(buffer.data(), buffer.size(), &src_addr);
      if (!read_res || read_res.value() <= 0)
        continue;

      ssize_t n = read_res.value();

      bool is_from_client = src_addr.port() != remote_addr.port();
      if (is_from_client && !client_addr_known) {
        client_addr = src_addr;
        client_addr_known = true;
        utils::log("udp client registered from {}", client_addr.to_string());
      }

      if (is_from_client) {
        utils::log("udp c->s: forwarding {} bytes to remote {}", n, remote_addr.to_string());
        local_socket.send_to(buffer.data(), n, remote_addr);
      } else if (client_addr_known) {
        utils::log("udp s->c: forwarding {} bytes to client {}", n, client_addr.to_string());
        local_socket.send_to(buffer.data(), n, client_addr);
      }
    }
  }

  void relay_tcp(sockpp::tcp_socket source, sockpp::tcp_socket destination, std::string_view direction) {
    utils::log("starting relay: {}", direction);
    bool is_client_to_server = (direction == "CLIENT -> SERVER");

    try {
      if (is_client_to_server) {
        std::vector<char> header(5);
        if (auto read_result = source.read_n(header.data(), 5); !read_result || read_result.value() != 5)
          return;

        int32_t len;
        memcpy(&len, header.data() + 1, 4);
        std::vector<char> body(len - 5);

        if (auto read_result = source.read_n(body.data(), body.size());
            !read_result || read_result.value() != body.size())
          return;

        utils::log("[{}] relayed initial plaintext auth packet, size: {}", direction, len);
        destination.write_n(header.data(), 5);
        destination.write_n(body.data(), body.size());
      }

      while (true) {
        packet::tcp::header header;
        if (auto read_result = source.read_n(&header, sizeof(header));
            !read_result || read_result.value() != sizeof(header))
          break;

        utils::log(
          "[{}] read header: enc_len={}, dec_len={}", direction, header.encrypted_length, header.decompressed_length
        );

        std::vector<uint8_t> encrypted_data(header.encrypted_length);
        if (auto read_result = source.read_n(encrypted_data.data(), header.encrypted_length);
            !read_result || read_result.value() != header.encrypted_length)
          break;

        auto processed = packet::tcp::process(header, encrypted_data);
        if (processed) {
          std::string name = "unknown";
          if (processed->content.contains("data") && processed->content["data"].contains("name")) {
            name = processed->content["data"]["name"];
          }
          utils::log("[{}] packet: {}", direction, name);

          utils::log("[{}] packet body:\n{}", direction, processed->content.dump(2));

          if (direction == "SERVER -> CLIENT" && name == "mrooms.join_room") {
            packet::tcp::handle_join(processed->content, "127.0.0.1", [](auto ip, auto port, auto key) {
              std::thread(run_udp_proxy, ip, port, key).detach();
            });
            auto rebuilt = packet::tcp::rebuild(processed->content, processed->original_unk_byte, processed->iv);
            destination.write_n(&rebuilt.new_header, sizeof(rebuilt.new_header));
            destination.write_n(rebuilt.new_encrypted_data.data(), rebuilt.new_encrypted_data.size());
            continue;
          }
        } else {
          utils::log("[{}] failed to process packet, forwarding raw data", direction);
        }

        destination.write_n(&header, sizeof(header));
        destination.write_n(encrypted_data.data(), encrypted_data.size());
      }
    } catch (const std::exception& e) {
      utils::log("exception in relay {}: {}", direction, e.what());
    } catch (...) {
      utils::log("unknown exception in relay {}", direction);
    }

    utils::log("relay {} shutting down", direction);
    destination.shutdown();
  }

  void handle_conn(sockpp::tcp_socket client_socket) {
    utils::log("client connected from {}", client_socket.peer_address().to_string());
    sockpp::tcp_connector remote_socket;

    if (!remote_socket.connect({std::string(remote_host), local_port})) {
      utils::log("failed to connect to remote host {}", remote_host);
      return;
    }
    utils::log("connected to remote {}", remote_socket.peer_address().to_string());

    auto remote_clone_res = remote_socket.clone();
    auto client_clone_res = client_socket.clone();
    if (!remote_clone_res || !client_clone_res) {
      utils::log("failed to clone sockets for threading");
      return;
    }

    std::thread(relay_tcp, std::move(client_socket), remote_clone_res.release(), "CLIENT -> SERVER").detach();
    std::thread(relay_tcp, std::move(remote_socket), client_clone_res.release(), "SERVER -> CLIENT").detach();
  }

  [[nodiscard]] std::expected<void, const char*> run_proxy() {
    sockpp::initialize();
    sockpp::tcp_acceptor acceptor(local_port);
    if (!acceptor) {
      return std::unexpected("failed to create tcp acceptor on port 7853");
    }
    utils::log("proxy listening on port {}", acceptor.address().port());

    while (true) {
      if (auto accept_result = acceptor.accept()) {
        std::thread(handle_conn, accept_result.release()).detach();
      } else {
        utils::log("accept error: {}", accept_result.error_message());
      }
    }
    return {};
  }
} // namespace proxy

namespace patcher {
  void main_thread() {
    utils::show_console();
    if (!zydis::init(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, ZYDIS_FORMATTER_STYLE_INTEL)) {
      utils::log("failed to initialize zydis");
      return;
    }

    if (auto result = apply_patch(); result.has_value()) {
      utils::log("patch applied successfully");
      if (auto proxy_result = proxy::run_proxy(); !proxy_result.has_value()) {
        utils::log("proxy failed to start: {}", proxy_result.error());
      }
    } else {
      utils::log("patch failed: {}", result.error());
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
