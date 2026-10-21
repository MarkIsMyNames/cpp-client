#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

install_if_missing() {
    local manager="$1"
    shift
    local missing=()
    for pkg in "$@"; do
        case "$manager" in
            dnf)     rpm -q "$pkg" &>/dev/null || missing+=("$pkg") ;;
            apt-get) dpkg -s "$pkg" &>/dev/null || missing+=("$pkg") ;;
        esac
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Installing: ${missing[*]}"
        sudo "$manager" install -y "${missing[@]}"
    fi
}

if command -v dnf &>/dev/null; then
    install_if_missing dnf gcc-c++ cmake ninja-build git \
        openssl-devel libcurl-devel nlohmann-json-devel \
        glibc-devel kernel-headers qrencode clang \
        catch2-devel ftxui-devel python3-devel \
        sqlite-devel python3-pip
elif command -v apt-get &>/dev/null; then
    # catch2-dev and libftxui-dev are not in Ubuntu apt — Conan provides them
    install_if_missing apt-get g++ cmake ninja-build git \
        libssl-dev libcurl4-openssl-dev nlohmann-json3-dev libsqlite3-dev \
        linux-libc-dev qrencode clang clang-tools-18 \
        python3-dev python3-pip
else
    echo "Unsupported package manager."
    exit 1
fi

# Build OpenSSL 3.5 if not already available (required for ML-KEM-1024)
OPENSSL_VERSION=$(openssl version 2>/dev/null | awk '{print $2}')
OPENSSL_MAJOR_MINOR=$(echo "$OPENSSL_VERSION" | cut -d. -f1,2)
if [ -f /usr/local/openssl-3.5/lib64/libssl.so ]; then
    : # already built from source
elif [ "$OPENSSL_MAJOR_MINOR" = "3.5" ]; then
    : # system OpenSSL is 3.5 — no build needed
else
    echo "Building OpenSSL 3.5 (required for ML-KEM-1024, system has $OPENSSL_VERSION)..."
    cd /tmp
    rm -f openssl-3.5.0.tar.gz
    rm -rf openssl-3.5.0
    wget --show-progress -O openssl-3.5.0.tar.gz \
        https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
    if ! tar tzf openssl-3.5.0.tar.gz >/dev/null 2>&1; then
        echo "ERROR: OpenSSL tarball is corrupt or incomplete."
        exit 1
    fi
    tar xf openssl-3.5.0.tar.gz
    cd openssl-3.5.0
    ./Configure --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5 shared
    make -j"$(nproc)"
    sudo make install
    cd "$SCRIPT_DIR"
fi

# Install Python dependencies and Conan
pip3 install --quiet srp conan --break-system-packages
if [ ! -f cmake-build-debug/sqlite_ormConfig.cmake ] && [ ! -f cmake-build-debug/sqlite_orm-config.cmake ]; then
    conan profile detect --force >/dev/null 2>&1 || true
    conan install . --output-folder=cmake-build-debug \
        --build=missing \
        -s build_type=Release \
        -s compiler=clang \
        -s compiler.version=22 \
        -s compiler.libcxx=libstdc++11 \
        -s compiler.cppstd=20 \
        -c tools.cmake.cmaketoolchain:generator=Ninja \
        2>&1 | grep -v "^WARN: deprecated"
fi

rm -rf cmake-build-debug/CMakeCache.txt cmake-build-debug/CMakeFiles
cmake -B cmake-build-debug -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=cmake-build-debug/conan_toolchain.cmake \
    -DCMAKE_MAKE_PROGRAM=/usr/bin/ninja \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++-22 \
    -DCMAKE_C_COMPILER=/usr/bin/clang-22 \
    -Wno-dev
/usr/bin/ninja -C cmake-build-debug -j"$(nproc)"
exec env LD_LIBRARY_PATH=/usr/local/openssl-3.5/lib64:$LD_LIBRARY_PATH ./cmake-build-debug/securemsg
