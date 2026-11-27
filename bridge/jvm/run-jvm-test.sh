#!/usr/bin/env bash
# Build the bridge as a shared library and exercise its JNI entry points from a
# live JVM. Android's runtime uses the same JNI ABI, so this tests the exact
# boundary the Kotlin wrapper calls. Requires a JDK (javac/java) on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --locked
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -d "$out" jvm/src/com/jaysquadsec/bridge/NativeBridge.java jvm/test/BridgeTest.java
java -ea -Xcheck:jni -Djava.library.path=target/release -cp "$out" BridgeTest
