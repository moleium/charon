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
      int32_t encrypted_length;
      int32_t decompressed_length;
      int32_t decompressed_length_dup1;
      int32_t decompressed_length_dup2;
    };

    struct decrypted_payload_header {
      uint8_t unk;
      int32_t compressed_length;
      int32_t decompressed_length;
    };
    #pragma pack(pop)
    // clang-format on

    struct parsed_packet {
      nlohmann::json content;
      uint8_t original_unk_byte;
      std::array<uint8_t, 16> iv;
    };

    struct rebuilt_packet {
      header new_header;
      std::vector<uint8_t> new_encrypted_data;
    };

    std::optional<parsed_packet> process(const header& hdr, const std::vector<uint8_t>& encrypted_data) {
      std::array<uint8_t, 16> iv{};
      memcpy(iv.data() + 4, &hdr.decompressed_length, 4);
      memcpy(iv.data() + 8, &hdr.decompressed_length_dup1, 4);
      memcpy(iv.data() + 12, &hdr.decompressed_length_dup2, 4);

      auto decrypted_opt = crypto::aes_128_cbc_decrypt(encrypted_data, evp_key, iv);
      if (!decrypted_opt) {
        utils::log("aes decryption failed probably incorrect key or iv");
        return std::nullopt;
      }

      auto& decrypted = *decrypted_opt;
      if (decrypted.size() < sizeof(decrypted_payload_header)) {
        utils::log("decrypted data is too small to be a valid packet");
        return std::nullopt;
      }

      auto* dec_hdr = reinterpret_cast<decrypted_payload_header*>(decrypted.data());
      if (dec_hdr->decompressed_length <= 0) {
        utils::log("packet has no data to decompress, skipping");
        return std::nullopt;
      }

      std::vector<char> decompressed(dec_hdr->decompressed_length);

      int actual_compressed_size = decrypted.size() - sizeof(decrypted_payload_header);

      int decompressed_size = LZ4_decompress_safe(
        (const char*)decrypted.data() + sizeof(decrypted_payload_header), decompressed.data(), actual_compressed_size,
        dec_hdr->decompressed_length
      );

      if (decompressed_size <= 1) {
        utils::log("lz4 decompression failed or resulted in empty data. size: {}", decompressed_size);
        return std::nullopt;
      }

      try {
        nlohmann::json json_content =
          nlohmann::json::parse(decompressed.begin() + 1, decompressed.begin() + decompressed_size);
        return parsed_packet{std::move(json_content), dec_hdr->unk, iv};
      } catch (const nlohmann::json::parse_error& e) {
        utils::log("json parsing failed: {}", e.what());
        return std::nullopt;
      }
    }

    rebuilt_packet rebuild(const nlohmann::json& content, uint8_t unk_byte, const std::array<uint8_t, 16>& iv) {
      std::string json_str = content.dump();
      std::vector<uint8_t> modified_payload(1 + json_str.size());
      modified_payload[0] = unk_byte;
      memcpy(modified_payload.data() + 1, json_str.c_str(), json_str.size());

      std::vector<uint8_t> compressed_payload(
        sizeof(decrypted_payload_header) + LZ4_compressBound(modified_payload.size())
      );
      int compressed_size = LZ4_compress_default(
        (const char*)modified_payload.data(), (char*)compressed_payload.data() + sizeof(decrypted_payload_header),
        modified_payload.size(), LZ4_compressBound(modified_payload.size())
      );

      decrypted_payload_header new_dec_hdr = {unk_byte, compressed_size, (int32_t)modified_payload.size()};
      memcpy(compressed_payload.data(), &new_dec_hdr, sizeof(decrypted_payload_header));
      compressed_payload.resize(sizeof(decrypted_payload_header) + compressed_size);

      auto reencrypted = crypto::aes_128_cbc_encrypt(compressed_payload, evp_key, iv);
      int32_t new_decomp_len = modified_payload.size();
      header new_hdr = {(int32_t)reencrypted.size(), new_decomp_len, new_decomp_len, new_decomp_len};

      return rebuilt_packet{new_hdr, reencrypted};
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
    const __m128i key1 = _mm_set_epi32(2146121005, 2146121005, 2146121005, 2146121005);
    const __m128i key2 = _mm_set_epi32(-2073254261, -2073254261, -2073254261, -2073254261);

    //[[gnu::target("sse4.1")]]
    std::vector<uint8_t> generate_iv(uint8_t first_byte, int packet_length) {
      /*
      // TODO: add back in when we have a working udp proxy (reencryption)

      int v0 = ((packet_length - 1) << 16) | (first_byte << 8);
      __m128i vec = _mm_set_epi32(v0 + 3, v0 + 2, v0 + 1, v0);
      __m128i iv = _mm_xor_si128(vec, _mm_set1_epi32(packet_length - 1));
      iv = _mm_mullo_epi32(iv, key1);
      iv = _mm_xor_si128(iv, _mm_srli_epi32(iv, 15));
      iv = _mm_mullo_epi32(iv, key2);
      iv = _mm_xor_si128(iv, _mm_srli_epi32(iv, 16));
      std::vector<uint8_t> result(16);
      _mm_storeu_si128(reinterpret_cast<__m128i*>(result.data()), iv);
      return result;
      */
      return std::vector<uint8_t>(16, 0);
    }
  } // namespace udp
} // namespace proxy::packet
