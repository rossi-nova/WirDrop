#!/bin/bash
# 跨实现互操作验证：WirDrop(C#) ↔ Owly(Rust)
# 用法：bash cross-verify.sh
set -euo pipefail

TMP="$(mktemp -d)"
WIRDROP_PROJ="$PWD/tools/Interop"
OWLY_PROJ="$PWD/tools/owly"
W="/tmp/interop/wirdrop"
O="/tmp/interop/owly"
rm -rf "$W" "$O"
mkdir -p "$W" "$O"

echo "=== 1. WirDrop(C#) 编码，Owly(Rust) 解析 ==="
dotnet run --project "$WIRDROP_PROJ" -- encode "$(cygpath -w "$W")" 2>&1 | tail -1
cargo run --quiet --manifest-path "$OWLY_PROJ/Cargo.toml" --bin interop -- decode "$(cygpath -w "$W")" 2>&1 | tail -6

echo ""
echo "=== 2. Owly(Rust) 编码，WirDrop(C#) 解析 ==="
cargo run --quiet --manifest-path "$OWLY_PROJ/Cargo.toml" --bin interop -- encode "$(cygpath -w "$O")" 2>&1 | tail -1
dotnet run --project "$WIRDROP_PROJ" -- decode "$(cygpath -w "$O")" 2>&1 | tail -8

echo ""
echo "=== 跨实现互操作验证完成 ==="