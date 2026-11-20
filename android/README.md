# Jay Squad Sec Android foundation

This is the first native Android application scaffold for the consumer product.
It uses Kotlin, Jetpack Compose and the existing Rust/JNI bridge sources.

## Build

Requirements:
- JDK 17
- Android SDK Platform 35 and build tools installed
- Gradle 8.9 (Android Gradle Plugin 8.7.3)

From the repository root:

```sh
gradle -p android testDebugUnitTest
gradle -p android assembleDebug
```

The debug APK, when CI builds it successfully, is written under
`android/app/build/outputs/apk/debug/`.

## Current functionality

- A Compose dashboard with an explicit inventory-only status.
- Lists launchable apps visible to this app under Android package-visibility
  rules.
- Reads package labels, package names, current signing-certificate SHA-256
  digest(s), requested permissions and the granted flag reported by Android.
- Supports refreshing the visible inventory.
- Includes a small process-generation tracker with unit tests. It requires a
  legitimate observation source to provide a stable process-start token; the
  app does not currently claim to observe arbitrary third-party processes.

## Android privacy and platform boundaries

The manifest intentionally does **not** request `QUERY_ALL_PACKAGES`,
Accessibility, Usage Access, notification access, contacts, SMS, storage,
microphone, camera, location or VPN privileges.

The package list is not a complete device inventory. Android filters package
queries unless the package is visible to the app. The permission list reports
permissions requested by each visible package and whether PackageManager
reports them granted; it does not mean Jay Squad Sec can revoke those
permissions.

An ordinary non-rooted app cannot inspect another app's private memory or
files, enumerate all system processes, terminate arbitrary apps, or revoke
another app's permissions. The process-generation helper is a contract
boundary, not a source of system-wide process telemetry.

No network monitor, VPN service, background polling, automatic enforcement,
cloud service or telemetry upload is enabled in this stage.

## Native engine status

The Java and Kotlin bridge sources are included in the Android module source
sets. The Rust shared library is not yet built and packaged for Android ABIs.
The dashboard therefore remains usable as an inventory-only app; creating a
native engine will require the ABI-specific library to be present.

Signed rules updates remain fail-closed. Release builds must embed the Android
builder public key and an explicit minimum rules version. Never use the
published test key in a release build.

## Next engineering gates

1. Run Gradle unit tests and build the debug APK in CI.
2. Cross-compile the Rust bridge for arm64-v8a, armeabi-v7a and x86_64 with the
   Android NDK and package the resulting shared libraries.
3. Compile and test the Kotlin bridge wrapper as part of the Android module.
4. Add Keystore-backed anti-rollback state and verify signed rules on device.
5. Test inventory and signer observations on physical devices across Android
   versions and OEM builds.
6. Only then design opt-in network observation, battery profiling and
   lifecycle-safe monitoring.
