cmake_minimum_required(VERSION 3.14)
project(RustBitcoinPuzzle)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Descargar spdlog para logging
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0
    TIMEOUT 30
)

# Descargar libsecp256k1
FetchContent_Declare(secp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
    GIT_TAG master
    TIMEOUT 30
)

# Hacer disponibles las dependencias
FetchContent_MakeAvailable(spdlog)

# Poblar secp256k1 antes de usarlo
FetchContent_Populate(secp256k1)

# Compilar secp256k1 con opciones específicas
set(SECP256K1_BUILD_SHARED_LIBS OFF)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON)
add_subdirectory(${secp256k1_SOURCE_DIR} ${CMAKE_BINARY_DIR}/secp256k1_build EXCLUDE_FROM_ALL)

# Buscar OpenSSL
find_package(OpenSSL REQUIRED)

# Crear ejecutable
add_executable(RustBitcoinPuzzle
    src/main.cpp
    src/bitcoin_checker.cpp
)

# Enlazar librerías
target_link_libraries(RustBitcoinPuzzle
    PRIVATE
    spdlog::spdlog
    secp256k1
    OpenSSL::Crypto
    pthread
)

# Incluir directorios
target_include_directories(RustBitcoinPuzzle
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${secp256k1_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Opciones de compilación
if(MSVC)
    target_compile_options(RustBitcoinPuzzle PRIVATE /W4 /O2)
else()
    target_compile_options(RustBitcoinPuzzle PRIVATE -Wall -Wextra -O2)
endif()
