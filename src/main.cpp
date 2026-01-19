#include "bitcoin_checker.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <map>
#include <iostream>

using uint128_t = unsigned __int128;

int main(int argc, char* argv[]) {
    // Configurar logging
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("app.log", true);
    
    std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("main", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::register_logger(logger);
    
    std::map<uint8_t, std::tuple<std::string, std::string, std::string>> puzzles;
    puzzles[69] = std::make_tuple("100000000000000000", "1fffffffffffffffff", "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG");
    puzzles[70] = std::make_tuple("200000000000000000", "3fffffffffffffffff", "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR");
    puzzles[71] = std::make_tuple("400000000000000000", "7fffffffffffffffff", "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU");
    puzzles[72] = std::make_tuple("800000000000000000", "ffffffffffffffffff", "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR");
    puzzles[73] = std::make_tuple("1000000000000000000", "1ffffffffffffffffff", "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4");
    puzzles[74] = std::make_tuple("2000000000000000000", "3ffffffffffffffffff", "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv");
    
    if (argc < 2) {
        logger->error("Uso: {} <número>", argv[0]);
        logger->error("Números válidos: ");
        for (const auto& [key, _] : puzzles) {
            logger->error("{}", static_cast<int>(key));
        }
        return 1;
    }
    
    try {
        uint8_t numero = std::stoi(argv[1]);
        
        auto it = puzzles.find(numero);
        if (it != puzzles.end()) {
            const auto& [from, to, address] = it->second;
            logger->info("{}: {} {} {}", static_cast<int>(numero), from, to, address);
            
            BitcoinChecker checker(from, to, address);
            checker.main();
        } else {
            logger->error("Número no encontrado");
            logger->error("Números válidos: ");
            for (const auto& [key, _] : puzzles) {
                logger->error("{}", static_cast<int>(key));
            }
            return 1;
        }
    } catch (const std::exception& e) {
        logger->error("Error: {}", e.what());
        return 1;
    }
    
    return 0;
}
