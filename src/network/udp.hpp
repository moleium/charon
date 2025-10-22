#pragma once

#include "sockpp/inet_address.h"
#include "sockpp/udp_socket.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <utils/logger.hpp>

namespace proxy {
  inline void run_udp(const std::string& remote_ip, uint16_t game_port, const std::string& room_key_str) {
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
}
