#!/usr/bin/env bash
# Device smoke test, run in CI on a fresh Android 14 emulator. Installs the
# debug APK as a new user would and checks, on a real Android runtime:
#   1. the app launches without crashing;
#   2. a new user is asked to allow notifications;
#   3. after "Don't allow", the red "Notifications are off" warning shows;
#   4. after allowing, the warning is gone and the native engine self-test
#      passes;
#   5. a forced background check completes without crashing.
# JVM unit tests cannot catch Android-only failures (such as regex syntax
# Android rejects), which is why this exists.
set -euo pipefail
APK=$1
PKG=com.jaysquadsec.android
ACT=$PKG/com.jaysquadsec.app.MainActivity
OUT=${SMOKE_OUT:-smoke-out}
mkdir -p "$OUT"
step=0

fail() {
  echo "SMOKE FAIL: $*"
  adb exec-out screencap -p > "$OUT/failure.png" || true
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 && adb shell cat /sdcard/ui.xml > "$OUT/failure-ui.xml" || true
  adb logcat -d > "$OUT/logcat.txt" || true
  exit 1
}

ui() {
  step=$((step + 1))
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || true
  adb shell cat /sdcard/ui.xml > "$OUT/ui-$step.xml"
  adb exec-out screencap -p > "$OUT/screen-$step.png" || true
  cat "$OUT/ui-$step.xml"
}

no_crash() {
  if adb logcat -d -b crash | grep -q "$PKG"; then
    adb logcat -d -b crash | tail -40
    fail "app crashed ($1)"
  fi
}

tap_resource() {  # tap the centre of the node with this resource-id suffix
  local xml=$1 id=$2
  read -r x y < <(python3 - "$xml" "$id" <<'PY'
import re, sys
xml, rid = sys.argv[1], sys.argv[2]
for node in re.findall(r"<node [^>]*>", open(xml).read()):
    if re.search(r'resource-id="[^"]*' + re.escape(rid) + '"', node):
        a, b, c, d = map(int, re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node).groups())
        print((a + c) // 2, (b + d) // 2); break
PY
)
  [ -n "${x:-}" ] || fail "button $id not found"
  adb shell input tap "$x" "$y"
}

adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 1; done'
adb install -r "$APK"
adb logcat -c
adb logcat -b crash -c || true

echo "== 1-2: first launch, expect the notification prompt"
adb shell am start -W -n "$ACT" >/dev/null
sleep 8
no_crash "first launch"
ui > /dev/null
grep -q "permissioncontroller" "$OUT/ui-$step.xml" || fail "no notification permission prompt on first launch"
grep -qi "notifications" "$OUT/ui-$step.xml" || fail "permission prompt is not about notifications"
echo "prompt shown"

echo "== 3: Don't allow, expect the red warning"
tap_resource "$OUT/ui-$step.xml" "permission_deny_button"
sleep 4
no_crash "after deny"
ui > /dev/null
grep -q "Notifications are off" "$OUT/ui-$step.xml" || fail "no 'Notifications are off' warning after denying"
echo "warning shown"

echo "== 4: allow, expect the warning gone and the engine self-test passed"
adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -W -n "$ACT" >/dev/null
sleep 6
no_crash "after allow"
ui > /dev/null
if grep -q "Notifications are off" "$OUT/ui-$step.xml"; then fail "warning still shown after allowing"; fi
grep -q "self-test passed" "$OUT/ui-$step.xml" || fail "native engine self-test did not pass"
grep -q "Visible launchable apps" "$OUT/ui-$step.xml" || fail "inventory not shown"
echo "warning cleared, engine ok"

echo "== 5: forced background check"
adb shell cmd jobscheduler run -f "$PKG" 4201
sleep 8
no_crash "background check"
adb shell run-as "$PKG" cat files/last-check >/dev/null 2>&1 || fail "background check did not complete"
if adb shell run-as "$PKG" cat files/last-check-error >/dev/null 2>&1; then fail "background check reported an error"; fi
echo "background check ok"

echo "SMOKE PASS"
