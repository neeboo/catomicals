#!/bin/sh
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
wrapper="$repo_dir/scripts/cargo-rocksdb.sh"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/catomicals-rocksdb-wrapper.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

mkdir -p "$test_dir/bin" "$test_dir/libclang" "$test_dir/rocksdb/lib" "$test_dir/rocksdb/include/rocksdb"
ln -s /usr/bin/true "$test_dir/bin/cargo"
: > "$test_dir/libclang/libclang.dylib"
: > "$test_dir/libclang/libclang.so"
: > "$test_dir/rocksdb/include/rocksdb/c.h"

write_version() {
    version_major="$1"
    version_minor="$2"
    version_patch="$3"
    printf '#define ROCKSDB_MAJOR %s\n#define ROCKSDB_MINOR %s\n#define ROCKSDB_PATCH %s\n' \
        "$version_major" "$version_minor" "$version_patch" \
        > "$test_dir/rocksdb/include/rocksdb/version.h"
}

run_wrapper() {
    env -i \
        PATH="$test_dir/bin:/usr/bin:/bin" \
        LIBCLANG_PATH="$test_dir/libclang" \
        ROCKSDB_LIB_DIR="$test_dir/rocksdb/lib" \
        ROCKSDB_INCLUDE_DIR="$test_dir/rocksdb/include" \
        "$wrapper" --version
}

write_version 10 4 2
run_wrapper >/dev/null 2>&1

write_version 10 4 3
if run_wrapper >"$test_dir/stdout" 2>"$test_dir/stderr"; then
    echo "test-cargo-rocksdb: mismatched explicit RocksDB version was accepted" >&2
    exit 1
fi
grep -F "RocksDB 10.4.3 does not match required 10.4.2" "$test_dir/stderr" >/dev/null

rm "$test_dir/rocksdb/include/rocksdb/version.h"
if run_wrapper >"$test_dir/stdout" 2>"$test_dir/stderr"; then
    echo "test-cargo-rocksdb: unversioned explicit RocksDB was accepted" >&2
    exit 1
fi
grep -F "cannot determine the RocksDB version" "$test_dir/stderr" >/dev/null

echo "test-cargo-rocksdb: passed"
