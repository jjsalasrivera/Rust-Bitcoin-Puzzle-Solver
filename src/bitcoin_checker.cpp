#include "bitcoin_checker.h"
#include <iostream>
#include <fstream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <thread>
#include <random>
#include <iomanip>
#include <chrono>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

// Definir uint128_t globalmente
using uint128_t = unsigned __int128;

// Funciones auxiliares
std::string uint128_to_hex(uint128_t n) {
    if (n == 0) return "0";
    
    std::string result;
    while (n > 0) {
        int digit = n % 16;
        result = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10) + result;
        n /= 16;
    }
    return result;
}

uint128_t hex_to_uint128(const std::string& hex_str) {
    uint128_t result = 0;
    for (char c : hex_str) {
        result *= 16;
        if (c >= '0' && c <= '9') {
            result += c - '0';
        } else if (c >= 'a' && c <= 'f') {
            result += c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            result += c - 'A' + 10;
        }
    }
    return result;
}

std::string bytes_to_hex_helper(const uint8_t* data, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Función RIPEMD160 usando OpenSSL EVP
std::vector<uint8_t> ripemd160(const uint8_t* data, size_t length) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_ripemd160();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, data, length);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    return std::vector<uint8_t>(md_value, md_value + md_len);
}

// Funciones helper globales
uint128_t convert_hex_to_uint128(const std::string& hex_str) {
    return hex_to_uint128(hex_str);
}

BitcoinChecker::BitcoinChecker(const std::string& from_hex, const std::string& to_hex, const std::string& target_address)
    : from_num(convert_hex_to_uint128(from_hex)), 
      to_num(convert_hex_to_uint128(to_hex)),
      range_size(to_num - from_num),
      target_address(target_address) {
    
    secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!secp_ctx) {
        throw std::runtime_error("Failed to create secp256k1 context");
    }
}

BitcoinChecker::~BitcoinChecker() {
    if (secp_ctx) {
        secp256k1_context_destroy(secp_ctx);
    }
}

std::string BitcoinChecker::bytes_to_hex(const uint8_t* data, size_t length) {
    return bytes_to_hex_helper(data, length);
}

std::string BitcoinChecker::to_wif(const uint8_t* key_bytes) {
    // Base58 check encoding para WIF
    static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    uint8_t wif_data[38];
    wif_data[0] = 0x80; // Mainnet prefix
    memcpy(wif_data + 1, key_bytes, 32);
    wif_data[33] = 0x01; // Compressed flag
    
    // SHA256 dos veces
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, wif_data, 34);
    SHA256_Final(hash, &sha_ctx);
    
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &sha_ctx);
    
    memcpy(wif_data + 34, hash2, 4);
    
    // Base58 encoding
    std::string wif;
    uint128_t num = 0;
    for (int i = 0; i < 38; ++i) {
        num = num * 256 + wif_data[i];
    }
    
    if (num == 0) return "1";
    
    while (num > 0) {
        wif = BASE58_ALPHABET[num % 58] + wif;
        num /= 58;
    }
    
    // Contar leading zeros
    int leading_zeros = 0;
    for (int i = 0; i < 38; ++i) {
        if (wif_data[i] == 0) leading_zeros++;
        else break;
    }
    
    for (int i = 0; i < leading_zeros; ++i) {
        wif = "1" + wif;
    }
    
    return wif;
}

std::string BitcoinChecker::bytes_to_bitcoin_address(const uint8_t* key_bytes) {
    // Crear clave pública desde la clave privada
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(secp_ctx, &pubkey, key_bytes)) {
        return "";
    }
    
    // Serializar clave pública comprimida
    unsigned char pubkey_ser[33];
    size_t pubkey_len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp_ctx, pubkey_ser, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        return "";
    }
    
    // SHA256 de la clave pública
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, pubkey_ser, pubkey_len);
    SHA256_Final(sha256_hash, &sha_ctx);
    
    // RIPEMD160 del SHA256
    auto ripemd_result = ripemd160(sha256_hash, SHA256_DIGEST_LENGTH);
    
    // Agregar versión y checksum (P2PKH mainnet = 0x00)
    uint8_t versioned_hash[21];
    versioned_hash[0] = 0x00;
    memcpy(versioned_hash + 1, ripemd_result.data(), 20);
    
    // Checksum: SHA256(SHA256(versioned_hash))
    unsigned char checksum_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, versioned_hash, 21);
    SHA256_Final(checksum_hash, &sha_ctx);
    
    unsigned char checksum_hash2[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, checksum_hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(checksum_hash2, &sha_ctx);
    
    // Concatenar versión + hash + checksum
    uint8_t address_bytes[25];
    memcpy(address_bytes, versioned_hash, 21);
    memcpy(address_bytes + 21, checksum_hash2, 4);
    
    // Base58 encoding
    static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string address;
    
    uint128_t num = 0;
    for (int i = 0; i < 25; ++i) {
        num = num * 256 + address_bytes[i];
    }
    
    if (num == 0) return "1";
    
    while (num > 0) {
        address = BASE58_ALPHABET[num % 58] + address;
        num /= 58;
    }
    
    // Leading ones para leading zeros
    for (int i = 0; i < 21; ++i) {
        if (address_bytes[i] == 0) address = "1" + address;
        else break;
    }
    
    return address;
}

void BitcoinChecker::log_found_address(const uint8_t* private_key, const std::string& wif, const std::string& address) {
    std::ofstream file(FOUND_FILE, std::ios::app);
    if (file.is_open()) {
        file << "¡ENCONTRADA DIRECCIÓN CON BALANCE!\n";
        file << "Private Key: " << bytes_to_hex(private_key, 32) << "\n";
        file << "WIF: " << wif << "\n";
        file << "Address: " << address << "\n";
        file << "\n";
        file.close();
    }
}

void BitcoinChecker::main() {
    auto logger = spdlog::get("main");
    
    fs::path found_file(FOUND_FILE);
    if (fs::exists(found_file)) {
        logger->info("Clave privada encontrada en {}", FOUND_FILE);
    } else {
        logger->info("Iniciando búsqueda de direcciones entre {} y {}", 
                     uint128_to_hex(from_num), uint128_to_hex(to_num));
        run();
    }
}

void BitcoinChecker::run() {
    auto logger = spdlog::get("main");
    
    size_t num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    
    uint128_t sub_range_size = range_size / num_threads;
    auto last_log = std::chrono::steady_clock::now();
    size_t last_checks = 0;
    
    while (!found.load(std::memory_order_relaxed)) {
        std::vector<std::thread> threads;
        
        for (size_t thread_id = 0; thread_id < num_threads; ++thread_id) {
            threads.emplace_back([this, thread_id, num_threads, sub_range_size]() {
                uint128_t sub_from = from_num + thread_id * sub_range_size;
                uint128_t sub_to = (thread_id == num_threads - 1) ? to_num : sub_from + sub_range_size;
                uint128_t max_start = sub_to > BLOCK_SIZE ? sub_to - BLOCK_SIZE : sub_from;
                
                // Generar punto de inicio aleatorio
                std::random_device rd;
                uint64_t seed = rd();
                std::hash<std::thread::id> hash_fn;
                seed ^= hash_fn(std::this_thread::get_id());
                std::mt19937_64 gen(seed);
                std::uniform_int_distribution<uint128_t> dis(sub_from, max_start);
                uint128_t start = dis(gen);
                
                uint8_t key_bytes[32] = {0};
                
                for (uint128_t i = 0; i < BLOCK_SIZE && !found.load(std::memory_order_relaxed); ++i) {
                    uint128_t num = start + i;
                    
                    // Convertir a big-endian bytes
                    for (int j = 0; j < 16; ++j) {
                        key_bytes[31 - j] = (num >> (j * 8)) & 0xFF;
                    }
                    
                    std::string address = bytes_to_bitcoin_address(key_bytes);
                    
                    if (address == target_address) {
                        auto logger = spdlog::get("main");
                        std::string hex_key = bytes_to_hex(key_bytes, 32);
                        std::string wif_key = to_wif(key_bytes);
                        
                        logger->info("\n¡ENCONTRADA DIRECCIÓN CON BALANCE!");
                        logger->info("Clave Privada: {}", hex_key);
                        logger->info("WIF: {}", wif_key);
                        logger->info("Dirección: {}", address);
                        
                        found.store(true, std::memory_order_seq_cst);
                        log_found_address(key_bytes, wif_key, address);
                    }
                }
            });
        }
        
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        
        checked_addresses.fetch_add(num_threads * BLOCK_SIZE, std::memory_order_relaxed);
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_log);
        
        if (elapsed.count() >= static_cast<int>(SECONDS_LOG)) {
            size_t total_checked = checked_addresses.load(std::memory_order_relaxed);
            double elapsed_sec = elapsed.count();
            size_t partial_checks = total_checked - last_checks;
            uint64_t rate = static_cast<uint64_t>(partial_checks / elapsed_sec);
            
            logger->info("Direcciones revisadas: {} - Tasa de cálculo: {} addr/s", total_checked, rate);
            last_log = now;
            last_checks = total_checked;
        }
    }
}
