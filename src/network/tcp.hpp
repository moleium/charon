#pragma once

#include "sockpp/inet_address.h"
#include "sockpp/tcp_acceptor.h"
#include "sockpp/tcp_connector.h"
#include "sockpp/tcp_socket.h"

#include <algorithm>
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
        // peek first byte to determine packet type
        uint8_t first_byte = 0;
        if (auto read_result = source.read_n(&first_byte, 1); !read_result || read_result.value() != 1)
          break;

        bool is_encrypted = (first_byte != 1);

        if (is_encrypted) {
          // read rest of encrypted header (already read 4 bytes as first_byte was int32 start)
          packet::tcp::encrypted_header enc_hdr{};
          std::memcpy(&enc_hdr.encrypted_len, &first_byte, 1);

          // read remaining 15 bytes of encrypted header
          if (auto read_result = source.read_n(((uint8_t*)&enc_hdr) + 1, sizeof(enc_hdr) - 1);
              !read_result || read_result.value() != sizeof(enc_hdr) - 1)
            break;

          utils::log(
            "[{}] encrypted packet: enc_len={}, dec_len={}", direction, enc_hdr.encrypted_len, enc_hdr.decrypted_len
          );

          if (enc_hdr.encrypted_len <= 0 || enc_hdr.encrypted_len > 1000000) {
            utils::log("[{}] bogus encrypted_len, breaking", direction);
            break;
          }

          std::vector<uint8_t> encrypted_data(enc_hdr.encrypted_len);
          if (auto read_result = source.read_n(encrypted_data.data(), enc_hdr.encrypted_len);
              !read_result || read_result.value() != enc_hdr.encrypted_len)
            break;

          std::vector<uint8_t> full_packet(sizeof(enc_hdr) + enc_hdr.encrypted_len);
          std::memcpy(full_packet.data(), &enc_hdr, sizeof(enc_hdr));
          std::memcpy(full_packet.data() + sizeof(enc_hdr), encrypted_data.data(), enc_hdr.encrypted_len);

          auto processed = packet::tcp::process_encrypted(full_packet, packet::evp_key);
          if (processed) {
            std::string name = "unknown";
            if (processed->content.contains("data") && processed->content["data"].contains("name")) {
              name = processed->content["data"]["name"];
            }
            utils::log("[{}] encrypted packet: {}", direction, name);
            utils::log("[{}] encrypted packet body:\n{}", direction, processed->content.dump(2));
          } else {
            utils::log("[{}] failed to decrypt packet", direction);
          }

          // forward encrypted packet as-is
          destination.write_n(full_packet.data(), full_packet.size());

        } else {
          // unencrypted packet - read full header (already got first byte)
          packet::tcp::header header{};
          header.type = first_byte;

          if (auto read_result = source.read_n(((uint8_t*)&header) + 1, sizeof(header) - 1);
              !read_result || read_result.value() != sizeof(header) - 1)
            break;

          utils::log(
            "[{}] unencrypted header: type={}, comp_len={}, dec_len={}", direction, (int)header.type,
            header.compressed_len, header.decompressed_len
          );

          if (header.compressed_len > 1000000 || header.compressed_len < (int)sizeof(header)) {
            utils::log("[{}] received bogus header size, breaking connection.", direction);
            break;
          }

          size_t payload_size = header.compressed_len - sizeof(header);
          std::vector<uint8_t> payload_data(payload_size);

          if (payload_size > 0) {
            if (auto read_result = source.read_n(payload_data.data(), payload_size);
                !read_result || read_result.value() != payload_size)
              break;
          }

          auto processed = packet::tcp::process(header, payload_data);
          if (processed) {
            std::string name = "unknown";
            if (processed->content.contains("data") && processed->content["data"].contains("name")) {
              name = processed->content["data"]["name"];
            }
            utils::log("[{}] unencrypted packet: {}", direction, name);
            utils::log("[{}] unencrypted packet body:\n{}", direction, processed->content.dump(2));

          } else {
            utils::log("[{}] failed to process packet, forwarding raw data", direction);
          }

          destination.write_n(&header, sizeof(header));
          if (payload_size > 0) {
            destination.write_n(payload_data.data(), payload_data.size());
          }
        }
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
