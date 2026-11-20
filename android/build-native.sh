#!/usr/bin/env bash
# Cross-compile the Rust bridge for Android and place the shared libraries in
# app/src/main/jniLibs/<abi>/ for Gradle to package.
#
# Requires ANDROID_NDK_HOME and the Rust targets below. No extra tools (no
# cargo-ndk): the NDK's clang is used directly as the linker.
#
# Updates stay fail-closed unless the builder sets
# JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX and JSS_ANDROID_MIN_RULES_VERSION for a
# release build. Never use the published test key in a release.
set -euo pipefail
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the NDK directory}"
API=26  # matches minSdk
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
out="$root/android/app/src/main/jniLibs"
rm -rf "$out"

build() {
  local triple=$1 clang=$2 abi=$3
  local var
  var=$(echo "$triple" | tr 'a-z-' 'A-Z_')
  # 16 KB page alignment: required for Android 15+ devices with 16 KB pages.
  env "CARGO_TARGET_${var}_LINKER=$bin/${clang}${API}-clang" \
      "CARGO_TARGET_${var}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384" \
      cargo build --manifest-path "$root/bridge/Cargo.toml" --release --locked \
        --lib --target "$triple"
  mkdir -p "$out/$abi"
  "$bin/llvm-strip" --strip-unneeded \
    -o "$out/$abi/libjay_squad_sec_bridge.so" \
    "$root/bridge/target/$triple/release/libjay_squad_sec_bridge.so"
}

build aarch64-linux-android    aarch64-linux-android    arm64-v8a
build armv7-linux-androideabi  armv7a-linux-androideabi armeabi-v7a
build x86_64-linux-android     x86_64-linux-android     x86_64
ls -l "$out"/*/
