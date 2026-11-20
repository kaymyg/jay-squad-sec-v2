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

Debug builds are signed with a fixed debug key checked in as
`app/debug.keystore`, so test builds from any CI run install over each other.
Debug keys are public by convention and are not a release key; release
signing is not set up yet and its key must never be stored in this
repository.

CI also runs `android/device-smoke.sh` on a fresh Android 14 emulator. It
installs the debug APK as a new user would and checks the notification
prompt and the "Notifications are off" warning, the engine self-test, a
forced background check, that a real permission grant is shown, rated by the
engine ("Risk: Low (engine score 15)") and notified, that rejecting it in
Settings clears the warning and the notification, and that a removal is
absorbed while a later re-grant is flagged again.

## Current functionality

- A Compose dashboard whose protection status states it is alert-only
  ("Alert-only: watches for app changes").
- Lists launchable apps visible to this app under Android package-visibility
  rules.
- Reads package labels, package names, current signing-certificate SHA-256
  digest(s), requested permissions and the granted flag reported by Android.
- Supports refreshing the visible inventory.
- Keeps a baseline of each visible app's signer set and granted sensitive
  runtime permissions (app-private, excluded from backup and transfer) and
  reports changes since it: new or removed apps, a changed signing
  certificate, and newly granted sensitive permissions. A corrupted or
  altered baseline file is rejected whole, replaced, and reported.
- Per-app review. **Accept** makes that app's current state its new
  baseline; other apps keep their old baseline, and "Accept all" covers only
  the apps shown on screen. **Reject** opens the app's system settings,
  because Android lets only the user switch another app's permission off or
  uninstall it; the warning clears once the change is undone. A signer that
  could not be read never overwrites the known one on Accept.
- Accepting a removed app keeps a tombstone with its known signer, so if it
  comes back signed by a different key that is still reported as a signer
  change.
- Permission removals are the safe direction and need no review: they are
  written into the baseline automatically, so a later re-grant is flagged as
  new.
- An hourly background check (JobScheduler, persisted across reboots,
  re-armed whenever the app opens) compares with the baseline and posts a
  notification only for changes that add sensitive access or swap an app: a
  changed signing certificate, a newly granted sensitive permission, or a
  new app that already holds one. Plain new apps, removals and revocations
  are shown in the app but never notify. Each change is notified once (a
  ledger of SHA-256 keys); it counts as announced only if the post
  succeeded, and the notification is removed once nothing is left to review.
- Notifications use a HIGH importance channel ("Security alerts": a short
  banner, then the shade, never full screen) with the phone's default tone.
  On the lock screen only "Jay Squad Sec" and the title show; details need
  the phone unlocked. If the user blocked the older channel, the new one is
  created blocked too.
- An engine verdict per app. Each scan feeds the unreviewed changes to a
  fresh native engine as app-level events (signer change, sensitive
  permission granted, new app with sensitive access) and shows
  `Risk: Low/Watch/High/Very high/Critical (engine score N)` per app,
  riskiest first. Signals on the same app add up: one new permission is Low
  (15), a new app with SMS and microphone is Watch (40), a swapped app with
  SMS access is Very high (75). The notification title leads with
  "High risk: <app>" when the engine rates an app High or above. The verdict
  is alert-only wording; nothing is blocked. If the engine is unavailable the
  app works without ratings. Verdicts use the engine's built-in default
  rules; the app does not load signed rules yet.
- App labels come from other apps and are untrusted: control, bidi and
  invisible characters are stripped, stacked marks are capped, length is
  limited, and the fixed warning text always comes first with the package
  name.
- Tapjacking protection: the screen ignores touches while another app's
  window covers it, and hides other apps' overlays on Android 12+.
- Runs a native engine self-test at launch (synthetic events for a fake
  identity) to prove the Rust core loads and decides on this device.
- Includes a small process-generation tracker with unit tests. It requires a
  legitimate observation source to provide a stable process-start token; the
  app does not currently claim to observe arbitrary third-party processes.

## Android privacy and platform boundaries

The manifest requests only three permissions:

- `POST_NOTIFICATIONS`, asked at runtime on Android 13+, to post change
  alerts. If it is denied the app shows a "Notifications are off" warning
  and keeps working in the foreground.
- `RECEIVE_BOOT_COMPLETED` (normal, granted at install), so the persisted
  hourly check survives a reboot.
- `HIDE_OVERLAY_WINDOWS` (normal), so the app can hide other apps' overlays
  on its own screen on Android 12+.

It intentionally does **not** request `QUERY_ALL_PACKAGES`, Accessibility,
Usage Access, notification access, contacts, SMS, storage, microphone,
camera, location or VPN privileges. Package visibility is limited to
launcher apps through a `<queries>` intent filter. The background job
service is not exported and only the system scheduler can bind it.

The package list is not a complete device inventory. Android filters package
queries unless the package is visible to the app. The permission list reports
permissions requested by each visible package and whether PackageManager
reports them granted; it does not mean Jay Squad Sec can revoke those
permissions.

An ordinary non-rooted app cannot inspect another app's private memory or
files, enumerate all system processes, terminate arbitrary apps, or revoke
another app's permissions. The process-generation helper is a contract
boundary, not a source of system-wide process telemetry.

Only sensitive runtime permissions whose grant flag Android reports
reliably are compared. Special app-ops (draw over other apps, install
unknown apps, all-files access) are not reported through these flags and are
not tracked. A background check runs at most about hourly and Android may
defer it (Doze, battery restrictions), so a change can be noticed late; a
force stop cancels the job until the app is opened again.

No network monitor, VPN service, automatic enforcement, cloud service or
telemetry upload is enabled. The only background work is the hourly
on-device inventory check.

## Native engine status

`android/build-native.sh` cross-compiles the Rust bridge for arm64-v8a,
armeabi-v7a and x86_64 (16 KB page aligned), and CI packages it into the APK
and fails if any ABI is missing. The self-test has passed on a physical
32-bit ARM phone (Android 14). Inventory changes are fed to the engine as
app-level events through bridge ABI v5 (`submitAppEvent`, `appAssessment`);
the core added these kinds with signed rules format v2 (see
`docs/updates.md`).

Signed rules updates remain fail-closed. Release builds must embed the Android
builder public key and an explicit minimum rules version. Never use the
published test key in a release build.

## Next engineering gates

Done: Gradle tests and debug APK in CI; NDK build packaged for all ABIs;
Kotlin bridge compiled in the Android module; engine self-test on a device;
Android event kinds in the core (rules format v2) with baseline changes fed
to the engine; emulator smoke test in CI.

1. Load signed rules in the app (today verdicts use the built-in defaults).
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
