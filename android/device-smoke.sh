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
  echo "--- texts on screen at failure:"
  grep -o 'text="[^"]*"' "$OUT/failure-ui.xml" 2>/dev/null | grep -v 'text=""' | head -60 || true
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

# Find a text on screen, scrolling down a few times if needed. Leaves the
# matching dump in $OUT/ui-$step.xml. Returns 1 if not found.
find_text() {
  local text=$1 i
  for i in 0 1 2 3 4 5; do
    ui > /dev/null
    grep -qF "$text" "$OUT/ui-$step.xml" && return 0
    adb shell input swipe "$SX" "$SY_LOW" "$SX" "$SY_HIGH" 300
    sleep 1
  done
  return 1
}

scroll_top() { for _ in 1 2 3 4 5; do adb shell input swipe "$SX" "$SY_HIGH" "$SX" "$SY_LOW" 200; done; sleep 1; }

tap_text() {  # tap the centre of the node whose text starts with $2
  local xml=$1 text=$2
  local x="" y=""
  read -r x y < <(python3 - "$xml" "$text" <<'PYTEXT'
import re, sys, html
xml, want = sys.argv[1], sys.argv[2]
for node in re.findall(r"<node [^>]*>", open(xml).read()):
    m = re.search(r' text="([^"]*)"', node)
    if m and html.unescape(m.group(1)).startswith(want):
        a, b, c, d = map(int, re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node).groups())
        print((a + c) // 2, (b + d) // 2); break
PYTEXT
) || true
  [ -n "${x:-}" ] || fail "text '$text' not found to tap"
  adb shell input tap "$x" "$y"
}

tap_resource() {  # tap the centre of the node with this resource-id suffix
  local xml=$1 id=$2
  local x="" y=""
  read -r x y < <(python3 - "$xml" "$id" <<'PY'
import re, sys
xml, rid = sys.argv[1], sys.argv[2]
for node in re.findall(r"<node [^>]*>", open(xml).read()):
    if re.search(r'resource-id="[^"]*' + re.escape(rid) + '"', node):
        a, b, c, d = map(int, re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node).groups())
        print((a + c) // 2, (b + d) // 2); break
PY
) || true
  [ -n "${x:-}" ] || fail "button $id not found"
  adb shell input tap "$x" "$y"
}

adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 1; done'
adb install -r "$APK"
# Swipe coordinates from the real screen size (emulator screens vary).
read -r W H < <(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x\([0-9]*\).*/\1 \2/p' | tail -1)
SX=$((W / 2)); SY_LOW=$((H * 3 / 4)); SY_HIGH=$((H / 4))
echo "screen ${W}x${H}"
adb logcat -c
adb logcat -b crash -c || true

# Target for the grant/reject test: a launcher app whose runtime permission
# can be revoked, so the first baseline records it as off.
TARGET=""; PERM=""; SHORT=""
for cand in "com.android.camera2 android.permission.RECORD_AUDIO" \
            "com.android.camera2 android.permission.ACCESS_FINE_LOCATION" \
            "com.android.contacts android.permission.READ_CONTACTS" \
            "com.android.dialer android.permission.RECORD_AUDIO" \
            "com.google.android.dialer android.permission.RECORD_AUDIO"; do
  read -r cpkg cperm <<< "$cand"
  if adb shell pm list packages | tr -d '\r' | grep -qx "package:$cpkg" && adb shell pm revoke "$cpkg" "$cperm" 2>/dev/null; then
    TARGET=$cpkg; PERM=$cperm; SHORT=${cperm##*.}; break
  fi
done
[ -n "$TARGET" ] || fail "no app on this image to test grant/reject with"
echo "grant/reject target: $TARGET $PERM"

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

echo "== 6: a permission grant shows up, and notifies"
adb shell pm grant "$TARGET" "$PERM"
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -W -n "$ACT" >/dev/null
sleep 6
no_crash "after grant"
find_text "$SHORT access granted to" || fail "grant of $SHORT to $TARGET not shown"
grep -qF "($TARGET)" "$OUT/ui-$step.xml" || fail "package name not shown with the change"
# The native engine rated it: one new permission alone is Low (score 15).
# The verdict line sits above the app's changes, and find_text only scrolls
# down, so start again from the top.
scroll_top
find_text "Risk: Low (engine score 15)" || fail "engine verdict not shown for the grant"
grep -o 'text="Risk: [^"]*"' "$OUT/ui-$step.xml" || true
adb shell cmd jobscheduler run -f "$PKG" 4201
sleep 8
adb shell dumpsys notification --noredact | grep -q "pkg=$PKG" || fail "no notification posted for the grant"
echo "grant shown and notified"

echo "== 7: Reject, switch it off in Settings, Back: the warning must clear"
find_text "Reject: turn off" || fail "Reject button not found"
tap_text "$OUT/ui-$step.xml" "Reject: turn off"
sleep 4
adb shell dumpsys activity activities | grep -E "topResumedActivity" | head -1
adb shell pm revoke "$TARGET" "$PERM"
adb shell input keyevent KEYCODE_BACK
sleep 6
no_crash "after reject"
adb shell dumpsys activity activities | grep -E "topResumedActivity" | grep -q "$PKG" \
  || fail "Back from Settings did not return to Jay Squad Sec"
scroll_top
if find_text "$SHORT access granted to"; then fail "warning did not clear after the permission was switched off"; fi
if adb shell dumpsys notification --noredact | grep -q "pkg=$PKG"; then fail "stale notification not removed"; fi
echo "warning and notification cleared"

echo "== 8: accepted access, then removed: no review; granted again: flagged"
relaunch() { adb shell input keyevent KEYCODE_HOME; sleep 1; adb shell am start -W -n "$ACT" >/dev/null; sleep 6; }
adb shell pm grant "$TARGET" "$PERM"
relaunch
find_text "$SHORT access granted to" || fail "grant not shown before accept"
find_text "Accept" || fail "Accept button not found"
tap_text "$OUT/ui-$step.xml" "Accept"
sleep 3
adb shell pm revoke "$TARGET" "$PERM"
relaunch
no_crash "after removal"
scroll_top
if find_text "access removed from"; then fail "a permission removal was listed for review"; fi
adb shell pm grant "$TARGET" "$PERM"
relaunch
scroll_top
find_text "$SHORT access granted to" || fail "re-granted access after a removal was not flagged"
echo "removal absorbed, re-grant flagged"

echo "SMOKE PASS"
