#!/bin/sh
set -eu

ROCKSDB_REQUIRED_VERSION="10.4.2"

fail() {
    echo "cargo-rocksdb: $*" >&2
    exit 1
}

has_libclang() {
    candidate_dir="$1"
    [ -d "$candidate_dir" ] || return 1
    for candidate in \
        "$candidate_dir/libclang.dylib" \
        "$candidate_dir"/libclang.so \
        "$candidate_dir"/libclang.so.* \
        "$candidate_dir"/libclang-*.so.*
    do
        [ -f "$candidate" ] && return 0
    done
    return 1
}

append_loader_path() {
    loader_dir="$1"
    case "$(uname -s)" in
        Darwin)
            case ":${DYLD_FALLBACK_LIBRARY_PATH:-}:" in
                *":$loader_dir:"*) ;;
                *) DYLD_FALLBACK_LIBRARY_PATH="$loader_dir${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}" ;;
            esac
            export DYLD_FALLBACK_LIBRARY_PATH
            ;;
        Linux)
            case ":${LD_LIBRARY_PATH:-}:" in
                *":$loader_dir:"*) ;;
                *) LD_LIBRARY_PATH="$loader_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
            esac
            export LD_LIBRARY_PATH
            ;;
    esac
}

rocksdb_header_version() {
    version_header="$1/rocksdb/version.h"
    [ -f "$version_header" ] || return 1
    awk '
        $1 == "#define" && $2 == "ROCKSDB_MAJOR" { major = $3 }
        $1 == "#define" && $2 == "ROCKSDB_MINOR" { minor = $3 }
        $1 == "#define" && $2 == "ROCKSDB_PATCH" { patch = $3 }
        END {
            if (major != "" && minor != "" && patch != "") {
                print major "." minor "." patch
                exit 0
            }
            exit 1
        }
    ' "$version_header"
}

discover_libclang() {
    if [ -n "${LIBCLANG_PATH:-}" ]; then
        has_libclang "$LIBCLANG_PATH" || fail "LIBCLANG_PATH does not contain libclang: $LIBCLANG_PATH"
        return 0
    fi

    if command -v brew >/dev/null 2>&1; then
        brew_llvm_prefix="$(brew --prefix llvm 2>/dev/null || true)"
        if [ -n "$brew_llvm_prefix" ] && has_libclang "$brew_llvm_prefix/lib"; then
            LIBCLANG_PATH="$brew_llvm_prefix/lib"
            export LIBCLANG_PATH
            return 0
        fi
    fi

    if [ "$(uname -s)" = "Darwin" ] && command -v xcode-select >/dev/null 2>&1; then
        developer_dir="$(xcode-select -p 2>/dev/null || true)"
        if [ -n "$developer_dir" ]; then
            xcode_clang_dir="$developer_dir/Toolchains/XcodeDefault.xctoolchain/usr/lib"
            if has_libclang "$xcode_clang_dir"; then
                LIBCLANG_PATH="$xcode_clang_dir"
                export LIBCLANG_PATH
                return 0
            fi
        fi
    fi

    if command -v llvm-config >/dev/null 2>&1; then
        llvm_libdir="$(llvm-config --libdir 2>/dev/null || true)"
        if [ -n "$llvm_libdir" ] && has_libclang "$llvm_libdir"; then
            LIBCLANG_PATH="$llvm_libdir"
            export LIBCLANG_PATH
            return 0
        fi
    fi

    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libclang 2>/dev/null; then
        pkg_clang_dir="$(pkg-config --variable=libdir libclang 2>/dev/null || true)"
        if [ -n "$pkg_clang_dir" ] && has_libclang "$pkg_clang_dir"; then
            LIBCLANG_PATH="$pkg_clang_dir"
            export LIBCLANG_PATH
            return 0
        fi
    fi

    for llvm_dir in /usr/lib/llvm-*/lib /usr/local/opt/llvm/lib; do
        if has_libclang "$llvm_dir"; then
            LIBCLANG_PATH="$llvm_dir"
            export LIBCLANG_PATH
            return 0
        fi
    done

    fail "libclang was not found; install Xcode Command Line Tools or LLVM, or set LIBCLANG_PATH"
}

discover_system_rocksdb() {
    if [ -n "${ROCKSDB_LIB_DIR:-}" ] || [ -n "${ROCKSDB_INCLUDE_DIR:-}" ]; then
        [ -n "${ROCKSDB_LIB_DIR:-}" ] || fail "ROCKSDB_LIB_DIR must accompany ROCKSDB_INCLUDE_DIR"
        [ -n "${ROCKSDB_INCLUDE_DIR:-}" ] || fail "ROCKSDB_INCLUDE_DIR must accompany ROCKSDB_LIB_DIR"
        [ -d "$ROCKSDB_LIB_DIR" ] || fail "ROCKSDB_LIB_DIR is not a directory: $ROCKSDB_LIB_DIR"
        [ -f "$ROCKSDB_INCLUDE_DIR/rocksdb/c.h" ] || fail "ROCKSDB_INCLUDE_DIR lacks rocksdb/c.h: $ROCKSDB_INCLUDE_DIR"
        explicit_version="$(rocksdb_header_version "$ROCKSDB_INCLUDE_DIR" || true)"
        [ -n "$explicit_version" ] || fail "cannot determine the RocksDB version from $ROCKSDB_INCLUDE_DIR/rocksdb/version.h"
        [ "$explicit_version" = "$ROCKSDB_REQUIRED_VERSION" ] || fail "RocksDB $explicit_version does not match required $ROCKSDB_REQUIRED_VERSION"
        append_loader_path "$ROCKSDB_LIB_DIR"
        return 0
    fi

    rocksdb_prefix=""
    if command -v brew >/dev/null 2>&1; then
        rocksdb_prefix="$(brew --prefix rocksdb 2>/dev/null || true)"
    fi

    if [ -n "$rocksdb_prefix" ] && [ -f "$rocksdb_prefix/lib/pkgconfig/rocksdb.pc" ]; then
        rocksdb_version="$(PKG_CONFIG_PATH="$rocksdb_prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" pkg-config --modversion rocksdb 2>/dev/null || true)"
        if [ "$rocksdb_version" = "$ROCKSDB_REQUIRED_VERSION" ]; then
            ROCKSDB_LIB_DIR="$rocksdb_prefix/lib"
            ROCKSDB_INCLUDE_DIR="$rocksdb_prefix/include"
            export ROCKSDB_LIB_DIR ROCKSDB_INCLUDE_DIR
            append_loader_path "$ROCKSDB_LIB_DIR"
            return 0
        fi
        echo "cargo-rocksdb: system RocksDB $rocksdb_version does not match $ROCKSDB_REQUIRED_VERSION; using bundled RocksDB" >&2
        return 0
    fi

    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists rocksdb 2>/dev/null; then
        rocksdb_version="$(pkg-config --modversion rocksdb 2>/dev/null || true)"
        if [ "$rocksdb_version" = "$ROCKSDB_REQUIRED_VERSION" ]; then
            ROCKSDB_LIB_DIR="$(pkg-config --variable=libdir rocksdb)"
            ROCKSDB_INCLUDE_DIR="$(pkg-config --variable=includedir rocksdb)"
            export ROCKSDB_LIB_DIR ROCKSDB_INCLUDE_DIR
            append_loader_path "$ROCKSDB_LIB_DIR"
            return 0
        fi
        echo "cargo-rocksdb: system RocksDB $rocksdb_version does not match $ROCKSDB_REQUIRED_VERSION; using bundled RocksDB" >&2
    fi
}

[ "$#" -gt 0 ] || fail "pass a cargo command, for example: test --workspace"
command -v cargo >/dev/null 2>&1 || fail "cargo was not found"

discover_libclang
append_loader_path "$LIBCLANG_PATH"
discover_system_rocksdb

echo "cargo-rocksdb: libclang=$LIBCLANG_PATH" >&2
if [ -n "${ROCKSDB_LIB_DIR:-}" ]; then
    echo "cargo-rocksdb: rocksdb=$ROCKSDB_LIB_DIR (system $ROCKSDB_REQUIRED_VERSION)" >&2
else
    echo "cargo-rocksdb: rocksdb=bundled $ROCKSDB_REQUIRED_VERSION" >&2
fi

exec cargo "$@"
