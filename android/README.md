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
- Keeps a baseline of each visible app's signer set and granted sensitive
  runtime permissions (app-private, excluded from backup and transfer) and
  reports changes since it: new or removed apps, a changed signing
  certificate, and newly granted or removed sensitive permissions. The user
  accepts changes to make them the new baseline. A corrupted or altered
  baseline file is rejected whole, replaced, and reported.
- Runs a native engine self-test at launch (synthetic events for a fake
  identity) to prove the Rust core loads and decides on this device.
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

`android/build-native.sh` cross-compiles the Rust bridge for arm64-v8a,
armeabi-v7a and x86_64 (16 KB page aligned), and CI packages it into the APK
and fails if any ABI is missing. The self-test has passed on a physical
32-bit ARM phone (Android 14). Inventory changes are not yet fed to the
engine: that needs Android event kinds in the core, which changes the signed
rules format and gets its own reviewed step.

Signed rules updates remain fail-closed. Release builds must embed the Android
builder public key and an explicit minimum rules version. Never use the
published test key in a release build.

## Next engineering gates

Done: Gradle tests and debug APK in CI; NDK build packaged for all ABIs;
Kotlin bridge compiled in the Android module; engine self-test on a device.

1. Add Android event kinds to the core (new app, signer change, sensitive
   permission granted) with a versioned rules format, and feed baseline
   changes to the engine.
2. Release signing with an offline key, separate from the debug key.
3. Verify signed rules on device with a release build.
4. Test across more Android versions and OEM builds.
5. Only then design opt-in network observation, battery profiling and
   lifecycle-safe monitoring.

On Keystore: an app's Keystore keys are deleted when its data is cleared or it
is reinstalled, so a Keystore-backed high-water mark cannot survive a data
wipe. It would only add protection against file tampering. The defense
against rollback after a wipe is the compiled `JSS_ANDROID_MIN_RULES_VERSION`,
raised every release.
