#pragma once

#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <cstdint>
#include <secp256k1.h>

// Definir uint128_t
using uint128_t = unsigned __int128;

class BitcoinChecker {
public:
    BitcoinChecker(const std::string& from_hex, const std::string& to_hex, const std::string& target_address);
    ~BitcoinChecker();
    
    void main();
    
private:
    static constexpr const char* FOUND_FILE = "found.txt";
    static constexpr uint64_t SECONDS_LOG = 10;
    static constexpr uint64_t BLOCK_SIZE = 100000;
    
    uint128_t from_num;
    uint128_t to_num;
    uint128_t range_size;
    std::string target_address;
    std::atomic<size_t> checked_addresses{0};
    std::atomic<bool> found{false};
    secp256k1_context* secp_ctx;
    
private:
    // Convertir array de bytes a dirección Bitcoin
    std::string bytes_to_bitcoin_address(const uint8_t* key_bytes);
    
    // Codificar a WIF (Wallet Import Format)
    std::string to_wif(const uint8_t* key_bytes);
    
    // Convertir bytes a hex string
    static std::string bytes_to_hex(const uint8_t* data, size_t length);
    void run();
    void log_found_address(const uint8_t* private_key, const std::string& wif, const std::string& address);
};
