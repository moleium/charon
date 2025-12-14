#pragma once

#include "sockpp/inet_address.h"
#include "sockpp/tcp_acceptor.h"
#include "sockpp/tcp_connector.h"
#include "sockpp/tcp_socket.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <network/packet.hpp>
#include <network/udp.hpp>
#include <utils/logger.hpp>

namespace proxy {
  constexpr uint16_t local_listen_port = 7853;
  constexpr uint16_t remote_connect_port = 7853;
  constexpr std::array<std::string_view, 4> remote_hosts = {
    "78.138.44.128", "78.138.44.222", "78.138.44.207", "78.138.44.239"
  };

  inline void relay_tcp(sockpp::tcp_socket source, sockpp::tcp_socket destination, std::string_view direction) {
    utils::log("starting relay: {}", direction);
    bool is_client_to_server = (direction == "CLIENT -> SERVER");

    try {
      while (true) {
        packet::tcp::header header{};
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

          /*
          // TODO: add back in when we have a working udp proxy (reencryption)
          if (direction == "SERVER -> CLIENT" && name == "mrooms.join_room") {
            packet::tcp::handle_join(processed->content, "127.0.0.1", [](auto ip, auto port, auto key) {
              std::thread(run_udp, ip, port, key).detach();
            });
            auto rebuilt = packet::tcp::rebuild(processed->content, processed->original_unk_byte, processed->iv);
            destination.write_n(&rebuilt.new_header, sizeof(rebuilt.new_header));
            destination.write_n(rebuilt.new_encrypted_data.data(), rebuilt.new_encrypted_data.size());
            continue;
          }
          */
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

  inline void handle_conn(sockpp::tcp_socket client_socket) {
    utils::log("client connected from {}", client_socket.peer_address().to_string());
    sockpp::tcp_connector remote_socket;
    bool connected = false;

    for (const auto& host : remote_hosts) {
      utils::log("attempting to connect to remote host {}", host);
      if (remote_socket.connect({std::string(host), remote_connect_port})) {
        connected = true;
        break;
      }
      utils::log("... connection to {} failed", host);
    }

    if (!connected) {
      utils::log("failed to connect to any remote host");
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

  inline std::expected<void, const char*> run_proxy() {
    sockpp::initialize();
    sockpp::tcp_acceptor acceptor(local_listen_port);
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
