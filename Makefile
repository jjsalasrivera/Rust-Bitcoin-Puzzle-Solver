# Makefile para el proyecto C++ Bitcoin Puzzle

.PHONY: all build clean configure help install-deps

# Variables
BUILD_DIR := build
CMAKE := cmake
MAKE := make

# Detectar número de CPUs para compilación paralela
NPROC := $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

# Mensajes
MSG_INFO := echo "ℹ️"
MSG_SUCCESS := echo "✓"
MSG_ERROR := echo "✗"

help:
	@echo "=========================================="
	@echo "Targets disponibles:"
	@echo "=========================================="
	@echo "  make configure   - Configura el proyecto (descarga dependencias)"
	@echo "  make build       - Compila el proyecto"
	@echo "  make rebuild     - Limpia y recompila"
	@echo "  make clean       - Elimina archivos compilados"
	@echo "  make install-deps - Instala dependencias del sistema"
	@echo "  make help        - Muestra esta ayuda"
	@echo "=========================================="

install-deps:
	@$(MSG_INFO) "Instalando dependencias del sistema..."
	@bash ./configure

configure: install-deps
	@$(MSG_INFO) "Configurando proyecto con CMake..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && $(CMAKE) -DCMAKE_BUILD_TYPE=Release ..
	@$(MSG_SUCCESS) "Proyecto configurado correctamente"

build: configure
	@$(MSG_INFO) "Compilando proyecto..."
	@cd $(BUILD_DIR) && $(CMAKE) --build . --config Release -j $(NPROC)
	@$(MSG_SUCCESS) "Compilación completada"
	@$(MSG_INFO) "Ejecutable: $(BUILD_DIR)/RustBitcoinPuzzle"

rebuild: clean build

clean:
	@$(MSG_INFO) "Limpiando archivos compilados..."
	@rm -rf $(BUILD_DIR)
	@$(MSG_SUCCESS) "Limpieza completada"

# Default target
.DEFAULT_GOAL := build
