#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <immintrin.h>
#include <lz4.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include "utils/logger.hpp"

extern "C" {
#define AES_CBC 1
#include "aes.h"
}

namespace proxy::packet {
  inline constexpr std::array<uint8_t, 16> evp_key = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  namespace crypto {
    void add_pkcs7_padding(std::vector<uint8_t>& data, size_t block_size = 16) {
      size_t padding_len = block_size - (data.size() % block_size);
      data.insert(data.end(), padding_len, static_cast<uint8_t>(padding_len));
    }

    bool remove_pkcs7_padding(std::vector<uint8_t>& data) {
      if (data.empty())
        return false;
      uint8_t padding_len = data.back();
      if (padding_len == 0 || padding_len > 16 || padding_len > data.size()) {
        return false;
      }
      for (size_t i = 0; i < padding_len; ++i) {
        if (data[data.size() - 1 - i] != padding_len)
          return false;
      }
      data.resize(data.size() - padding_len);
      return true;
    }

    std::vector<uint8_t> aes_128_cbc_encrypt(
      std::vector<uint8_t> plaintext, const std::array<uint8_t, 16>& key, const std::array<uint8_t, 16>& iv
    ) {
      add_pkcs7_padding(plaintext);
      AES_ctx ctx;
      AES_init_ctx_iv(&ctx, key.data(), iv.data());
      AES_CBC_encrypt_buffer(&ctx, plaintext.data(), plaintext.size());
      return plaintext;
    }

    std::optional<std::vector<uint8_t>> aes_128_cbc_decrypt(
      std::vector<uint8_t> ciphertext, const std::array<uint8_t, 16>& key, const std::array<uint8_t, 16>& iv
    ) {
      AES_ctx ctx;
      AES_init_ctx_iv(&ctx, key.data(), iv.data());
      AES_CBC_decrypt_buffer(&ctx, ciphertext.data(), ciphertext.size());
      if (!remove_pkcs7_padding(ciphertext)) {
        return std::nullopt;
      }
      return ciphertext;
    }
  } // namespace crypto

  namespace tcp {
    // clang-format off
    #pragma pack(push, 1)
    struct header {
      uint8_t type;            // should be 1 for unencrypted/LZ4 packets
      int32_t compressed_len;  // includes the size of this header (9 bytes)
      int32_t decompressed_len;
    };

    struct encrypted_header {
      int32_t encrypted_len;
      int32_t decrypted_len;
      int32_t unk2; // same as decrypted_len
      int32_t unk3; // same as decrypted_len
    };
    #pragma pack(pop)
    // clang-format on

    struct parsed_packet {
      nlohmann::json content;
      uint8_t original_unk_byte; // payload prefix byte
      std::array<uint8_t, 16> iv;
    };

    struct rebuilt_packet {
      header new_header;
      std::vector<uint8_t> new_encrypted_data;
    };

    std::optional<parsed_packet> process(const header& hdr, const std::vector<uint8_t>& payload_data) {
      // unencrypted LZ4 compressed
      if (hdr.type == 1) {
        if (hdr.decompressed_len <= 0) {
          return std::nullopt;
        }

        std::vector<char> decompressed(hdr.decompressed_len);

        int decompressed_size = LZ4_decompress_safe(
          (const char*)payload_data.data(), decompressed.data(), payload_data.size(), hdr.decompressed_len
        );

        if (decompressed_size <= 1) { // Needs at least 1 byte for prefix
          utils::log("lz4 decompression failed or empty. ret: {}", decompressed_size);
          return std::nullopt;
        }

        uint8_t prefix_byte = (uint8_t)decompressed[0];

        try {
          nlohmann::json json_content = nlohmann::json::parse(decompressed.begin() + 1, decompressed.end());

          return parsed_packet{std::move(json_content), prefix_byte, {0}};
        } catch (const nlohmann::json::parse_error& e) {
          utils::log("json parsing failed: {}", e.what());
          return std::nullopt;
        }
      }

      utils::log("Unknown packet type: {}", hdr.type);
      return std::nullopt;
    }

    std::optional<parsed_packet>
    process_encrypted(const std::vector<uint8_t>& full_packet_data, const std::array<uint8_t, 16>& key) {
      if (full_packet_data.size() < sizeof(encrypted_header)) {
        utils::log("encrypted packet too small");
        return std::nullopt;
      }

      encrypted_header enc_hdr;
      std::memcpy(&enc_hdr, full_packet_data.data(), sizeof(encrypted_header));

      if (enc_hdr.encrypted_len <= 0 || enc_hdr.encrypted_len > 1000000) {
        utils::log("invalid encrypted_len: {}", enc_hdr.encrypted_len);
        return std::nullopt;
      }

      if (full_packet_data.size() < sizeof(encrypted_header) + enc_hdr.encrypted_len) {
        utils::log("encrypted packet data incomplete");
        return std::nullopt;
      }

      // construct iv as [0, decrypted_len, decrypted_len, decrypted_len]
      std::array<uint8_t, 16> iv;
      std::memset(iv.data(), 0, 4);
      std::memcpy(iv.data() + 4, &enc_hdr.decrypted_len, 4);
      std::memcpy(iv.data() + 8, &enc_hdr.decrypted_len, 4);
      std::memcpy(iv.data() + 12, &enc_hdr.decrypted_len, 4);

      std::vector<uint8_t> encrypted_data(
        full_packet_data.begin() + sizeof(encrypted_header),
        full_packet_data.begin() + sizeof(encrypted_header) + enc_hdr.encrypted_len
      );

      auto decrypted_opt = crypto::aes_128_cbc_decrypt(encrypted_data, key, iv);
      if (!decrypted_opt) {
        utils::log("aes decryption failed");
        return std::nullopt;
      }

      auto& decrypted = *decrypted_opt;

      if (decrypted.size() < sizeof(header)) {
        utils::log("decrypted data too small for header");
        return std::nullopt;
      }

      header inner_hdr;
      std::memcpy(&inner_hdr, decrypted.data(), sizeof(header));

      size_t payload_size = inner_hdr.compressed_len - sizeof(header);
      if (sizeof(header) + payload_size > decrypted.size()) {
        utils::log("decrypted payload size mismatch");
        return std::nullopt;
      }

      std::vector<uint8_t> payload(
        decrypted.begin() + sizeof(header), decrypted.begin() + sizeof(header) + payload_size
      );

      auto result = process(inner_hdr, payload);
      if (result) {
        result->iv = iv;
      }
      return result;
    }

    rebuilt_packet rebuild(const nlohmann::json& content, uint8_t unk_byte, const std::array<uint8_t, 16>& iv) {
      std::string json_str = content.dump();

      std::vector<uint8_t> raw_payload(1 + json_str.size());
      raw_payload[0] = unk_byte;
      memcpy(raw_payload.data() + 1, json_str.data(), json_str.size());

      std::vector<uint8_t> compressed_payload(LZ4_compressBound(raw_payload.size()));
      int compressed_size = LZ4_compress_default(
        (const char*)raw_payload.data(), (char*)compressed_payload.data(), raw_payload.size(),
        LZ4_compressBound(raw_payload.size())
      );

      compressed_payload.resize(compressed_size);

      header new_hdr = {1, (int32_t)(compressed_size + sizeof(header)), (int32_t)raw_payload.size()};

      return rebuilt_packet{new_hdr, compressed_payload};
    }

    std::vector<uint8_t> rebuild_encrypted(const nlohmann::json& content, uint8_t unk_byte) {
      auto unencrypted = rebuild(content, unk_byte, {0});

      std::vector<uint8_t> packet_to_encrypt(sizeof(header) + unencrypted.new_encrypted_data.size());
      std::memcpy(packet_to_encrypt.data(), &unencrypted.new_header, sizeof(header));
      std::memcpy(
        packet_to_encrypt.data() + sizeof(header), unencrypted.new_encrypted_data.data(),
        unencrypted.new_encrypted_data.size()
      );

      int32_t decompressed_len = unencrypted.new_header.decompressed_len;

      // construct iv as [0, decompressed_len, decompressed_len, decompressed_len]
      std::array<uint8_t, 16> iv;
      std::memset(iv.data(), 0, 4);
      std::memcpy(iv.data() + 4, &decompressed_len, 4);
      std::memcpy(iv.data() + 8, &decompressed_len, 4);
      std::memcpy(iv.data() + 12, &decompressed_len, 4);

      auto encrypted = crypto::aes_128_cbc_encrypt(packet_to_encrypt, evp_key, iv);

      encrypted_header enc_hdr{
        static_cast<int32_t>(encrypted.size()), decompressed_len, decompressed_len, decompressed_len
      };

      std::vector<uint8_t> final_packet(sizeof(encrypted_header) + encrypted.size());
      std::memcpy(final_packet.data(), &enc_hdr, sizeof(encrypted_header));
      std::memcpy(final_packet.data() + sizeof(encrypted_header), encrypted.data(), encrypted.size());

      return final_packet;
    }

    void handle_join(
      nlohmann::json& content, const std::string& new_ip,
      const std::function<void(std::string, uint16_t, std::string)>& udp_proxy_starter
    ) {
      try {
        auto& host = content["data"]["data"]["members"][0];
        std::string remote_ip = host["public"]["ip_str"];
        uint16_t game_port = host["public"]["port"];
        std::string room_key = content["data"]["data"]["public"]["room_key"];

        utils::log("mrooms.join_room");
        utils::log("original ip: {}, port: {}, room key: {}", remote_ip, game_port, room_key);

        host["public"]["ip_str"] = new_ip;
        utils::log("modified ip to: {}", new_ip);

        udp_proxy_starter(remote_ip, game_port, room_key.substr(0, 16));
      } catch (const std::exception& e) {
        utils::log("error processing join_room packet: {}", e.what());
      }
    }
  } // namespace tcp

  namespace udp {
    std::vector<uint8_t> generate_iv(uint8_t first_byte, int packet_length) {
      return std::vector<uint8_t>(16, 0);
    }
  } // namespace udp
} // namespace proxy::packet
