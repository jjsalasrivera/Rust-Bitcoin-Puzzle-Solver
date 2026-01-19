# C++ Bitcoin Puzzle Solver

Versión C++ del resolutor de puzzles de Bitcoin. Este proyecto busca direcciones Bitcoin con balance dentro de rangos específicos usando cálculo paralelo.

## Requisitos del Sistema

- macOS, Linux o Windows
- CMake 3.14+
- Compilador C++17 (g++ o clang++)
- OpenSSL
- Git (para descargar dependencias)

## Instalación Rápida

### Opción 1: Usar configure + make (Recomendado)

```bash
# Configurar proyecto e instalar dependencias
./configure

# Compilar
make build
```

### Opción 2: Usar CMake directamente

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
```

## Uso

```bash
./build/RustBitcoinPuzzle <número_puzzle>

# Ejemplo:
./build/RustBitcoinPuzzle 69
```

### Números de Puzzle Disponibles

- **69**: Rango 0x100000000000000000 - 0x1fffffffffffffffff
- **70**: Rango 0x200000000000000000 - 0x3fffffffffffffffff
- **71**: Rango 0x400000000000000000 - 0x7fffffffffffffffff
- **72**: Rango 0x800000000000000000 - 0xffffffffffffffffff
- **73**: Rango 0x1000000000000000000 - 0x1ffffffffffffffffff
- **74**: Rango 0x2000000000000000000 - 0x3ffffffffffffffffff

## Comandos Makefile

```bash
make configure      # Configura e instala dependencias
make build          # Compila el proyecto
make rebuild        # Limpia y recompila
make clean          # Elimina archivos compilados
make install-deps   # Instala solo dependencias
make help           # Muestra ayuda
```

## Dependencias

El proyecto usa las siguientes librerías que se descargan automáticamente:

- **libsecp256k1**: Criptografía ECDSA para Bitcoin
- **spdlog**: Logging de alto rendimiento
- **OpenSSL**: Funciones criptográficas (SHA256, RIPEMD160)

## Compilación Manual en Diferentes Plataformas

### macOS
```bash
brew install cmake openssl
./configure
make build
```

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install cmake build-essential libssl-dev
./configure
make build
```

### Fedora/RHEL
```bash
sudo yum install cmake gcc-c++ openssl-devel
./configure
make build
```

## Salida

Si se encuentra una dirección con balance, se registrará en:
- **Consola**: Mensajes en tiempo real
- **app.log**: Log de la aplicación
- **found.txt**: Detalles de la dirección encontrada

## Rendimiento

El programa:
- Usa paralelización con threads nativos de C++
- Genera búsquedas aleatorias dentro de cada rango
- Muestra tasa de direcciones revisadas por segundo
- Guarda automáticamente claves encontradas

## Licencia

Ver archivo LICENSE

## Notas

- Primera ejecución descarga y compila secp256k1 (puede tardar)
- El programa crea un archivo `found.txt` cuando encuentra una dirección
- Usa 100,000 direcciones por bloque de búsqueda
- Log cada 10 segundos del progreso
