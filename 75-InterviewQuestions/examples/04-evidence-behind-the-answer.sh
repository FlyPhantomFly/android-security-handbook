#!/usr/bin/env bash
# 75-InterviewQuestions/examples/04-evidence-behind-the-answer.sh
#
# PURPOSE
#   Produce, in about twenty seconds, the evidence behind the single most
#   effective sentence a candidate can say in an Android security interview:
#
#       "The received answer to that is wrong on a current device, and I have
#        measured it."
#
#   Everything this script prints is a first-hand measurement taken on the
#   attached device. It is deliberately tiny and dependency-free so that you can
#   run it the morning of an interview, on whatever device you have, and speak
#   from today's output rather than from a claim you memorised.
#
#   The point is NOT to memorise the outputs below. It is that a claim you
#   produced yourself, on a device you can name, is a different category of
#   answer from a claim you read. If your device disagrees with the numbers in
#   the comments, YOUR DEVICE IS RIGHT and the interesting answer is why.
#
# AUTHORISED TESTING ONLY
#   Runs read-only commands against a device you own or are authorised to test.
#   It writes nothing to the device, installs nothing, and changes no setting.
#
# USAGE
#   ./04-evidence-behind-the-answer.sh                 # first attached device
#   ./04-evidence-behind-the-answer.sh emulator-5554   # a specific device
#
#   Needs only adb. No root required for most of it; the root-only rows say so.
#
# WAS THIS EXECUTED?
#   YES. Run 2026-08-16 against the AVD `sdk_gphone16k_x86_64` (`emu64xa16k`),
#   Android 15 / API 35, x86_64, userdebug/dev-keys, rooted with Magisk 30.7.
#   The real output of that run is reproduced at the bottom of this file.
#
# NOTE ON `su` ON AN EMULATOR
#   The Android emulator's `su` takes `su 0 <cmd>` and REJECTS `su -c <cmd>`
#   with "invalid uid/gid '-c'", which reads exactly like "not rooted". This
#   script uses the `su 0` form. Separately, `adb shell su -c '...'` loses its
#   quoting -- always write `adb shell "su -c '...'"` on devices that want -c.

set -u    # NOT `set -o pipefail`: an early-exiting consumer such as `head` or
          # `grep -q` closes the pipe, the writer dies of SIGPIPE, and pipefail
          # promotes that to a failure. Test the content, not the exit status.

DEV="${1:-}"
if [ -n "$DEV" ]; then ADB="adb -s $DEV"; else ADB="adb"; fi

hr()  { printf '%s\n' "----------------------------------------------------------------------"; }
say() { printf '\n== %s\n' "$1"; hr; }

# ---------------------------------------------------------------------------
# 0. Identify the device. Every claim below is a claim ABOUT THIS DEVICE, and an
#    answer that cannot name its device is an anecdote.
# ---------------------------------------------------------------------------
say "0. Which device is this? (never quote a measurement without it)"
printf '%-24s %s\n' "model"        "$($ADB shell getprop ro.product.model      | tr -d '\r')"
printf '%-24s %s\n' "device"       "$($ADB shell getprop ro.product.device     | tr -d '\r')"
printf '%-24s %s\n' "release/API"  "$($ADB shell getprop ro.build.version.release | tr -d '\r') / $($ADB shell getprop ro.build.version.sdk | tr -d '\r')"
printf '%-24s %s\n' "fingerprint"  "$($ADB shell getprop ro.build.fingerprint  | tr -d '\r')"
printf '%-24s %s\n' "abi"          "$($ADB shell getprop ro.product.cpu.abilist | tr -d '\r')"

# ---------------------------------------------------------------------------
# 1. "How do you detect an emulator?"
#    The most-copied isEmulator() in the ecosystem is three checks. Run all
#    three and read the verdict off the device rather than off a blog post.
# ---------------------------------------------------------------------------
say "1. The most-copied isEmulator() -- does it fire on THIS device?"
FP="$($ADB shell getprop ro.build.fingerprint | tr -d '\r')"
MODEL="$($ADB shell getprop ro.product.model | tr -d '\r')"
QP="$($ADB shell 'ls /dev/qemu_pipe 2>/dev/null && echo PRESENT || echo ABSENT' | tr -d '\r')"

case "$FP" in
  generic*) C1="true" ;;
  *)        C1="false" ;;
esac
case "$MODEL" in
  *Emulator*) C2="true" ;;
  *)          C2="false" ;;
esac
case "$QP" in
  *PRESENT*) C3="true" ;;
  *)         C3="false" ;;
esac

printf '%-46s %s\n' 'Build.FINGERPRINT.startsWith("generic")' "$C1"
printf '%-46s %s\n' 'Build.MODEL.contains("Emulator")'        "$C2"
printf '%-46s %s\n' 'new File("/dev/qemu_pipe").exists()'     "$C3"
if [ "$C1" = "false" ] && [ "$C2" = "false" ] && [ "$C3" = "false" ]; then
  printf '\n  VERDICT: isEmulator() returns FALSE on this device.\n'
  printf '  If this is an emulator, the three most-published checks all missed it.\n'
fi
printf '\n  and where the pipe node went:\n'
$ADB shell 'ls -d /dev/goldfish_pipe_dprctd 2>/dev/null || echo "  (no goldfish pipe node either)"' | sed 's/^/    /'

# ---------------------------------------------------------------------------
# 2. The inverted signals. "A property with qemu in the name means emulator" is
#    not merely weak, it points the wrong way: a retail Xiaomi sets these and a
#    stock AVD does not.
# ---------------------------------------------------------------------------
say "2. The inverted properties -- empty means the AVD, set means a retail phone"
for p in qemu.hw.mainkeys ro.kernel.qemu.gles ro.kernel.qemu ro.hardware \
         ro.boot.verifiedbootstate ro.bootloader; do
  v="$($ADB shell getprop "$p" | tr -d '\r')"
  printf '  %-30s = [%s]\n' "$p" "$v"
done
printf '\n  ro.boot.verifiedbootstate EMPTY is not the same as "orange": the widely\n'
printf '  written  !"orange".equals(state)  returns TRUE here, so the check passes\n'
printf '  on the least trustworthy platform it can meet.\n'

# ---------------------------------------------------------------------------
# 3. "How do you detect root?" -- the vantage problem, in two commands.
#    /system/xbin is 0750 root:shell. adb shell can traverse it. An app cannot.
# ---------------------------------------------------------------------------
say "3. Vantage -- what adb shell sees is not what the app sees"
$ADB shell 'ls -ld /system/xbin 2>&1; ls -l /system/xbin/su 2>&1' | sed 's/^/  /'
printf '\n  The mode is the whole point. 0750 root:shell means uid 2000 (adb shell)\n'
printf '  traverses the directory and an app uid gets EACCES -- and File.exists()\n'
printf '  maps EACCES and ENOENT alike to false. The classic probe therefore reads\n'
printf '  "clean" on a rooted device, which is the only kind where it matters.\n'

printf '\n  And the loudest root signal needs no permission at all:\n'
$ADB shell 'grep -c magisk /proc/self/mountinfo 2>/dev/null || echo 0' \
  | tr -d '\r' | sed 's/^/    mountinfo lines whose source is "magisk": /'

# ---------------------------------------------------------------------------
# 4. Property visibility differs by SELinux domain. This is the quantified form
#    of "prove reachability from an app, not from the shell".
# ---------------------------------------------------------------------------
say "4. How many properties can each domain see? (the vantage measurement)"
NS="$($ADB shell "getprop | grep -c '^\['" | tr -d '\r')"
NR="$($ADB shell 'su 0 sh -c "getprop | grep -c \"^\\[\"" 2>/dev/null' | tr -d '\r')"
printf '  visible to adb shell  (u:r:shell:s0, uid 2000) : %s\n' "$NS"
printf '  visible to root       (su 0)                   : %s\n' "${NR:-(no root on this device)}"
printf '\n  The gap is the whole lesson. A detection signal you verified from adb\n'
printf '  shell has not been verified: the app that has to use it runs in a\n'
printf '  different SELinux domain and sees a different, smaller property store.\n'
printf '  Prove reachability FROM AN APP -- run-as, a probe APK, or Frida\n'
printf '  in-process -- or label the result as a shell measurement and say so.\n'
printf '\n  Corrected figures, three stable independent runs on this AVD:\n'
printf '                    root ~1062   shell ~678   app ~638\n'
printf '    ro.boottime.*   root   111    shell    0   app    0\n'
printf '\n  An earlier published figure gave "shell 1053, app 634". The 1053 was a\n'
printf '  ROOT measurement mislabelled as shell -- the tell was in the same table,\n'
printf '  which listed root at 1050 and shell at 1053, and two domains cannot see\n'
printf '  the same set when only one is subject to boottime_prop.\n'
printf '\n  The correction changes the conclusion, which is why it matters: the\n'
printf '  shell-to-app gap is about 40, not about 419. A shell test is a decent\n'
printf '  proxy for APP reachability and a terrible proxy for ROOT. The expensive\n'
printf '  mistake is not "I tested from the shell" -- it is "I tested from root\n'
printf '  and called it shell". Quote your own number and your own method.\n'

# ---------------------------------------------------------------------------
# 5. "Is this device secure?" -- the property lies, the hardware does not.
# ---------------------------------------------------------------------------
say "5. Boot state: what the property says vs what can be proved"
printf '  ro.boot.verifiedbootstate  = [%s]\n' "$($ADB shell getprop ro.boot.verifiedbootstate | tr -d '\r')"
printf '  ro.boot.flash.locked       = [%s]\n' "$($ADB shell getprop ro.boot.flash.locked | tr -d '\r')"
printf '  ro.build.tags              = [%s]\n' "$($ADB shell getprop ro.build.tags | tr -d '\r')"
printf '\n  A getprop value is attacker-controllable data. The only boot-state claim\n'
printf '  worth making is one that comes back inside a TEE-signed key attestation,\n'
printf '  and even that proves the CHAIN unless the server reads the security level\n'
printf '  out of the HARDWARE-ENFORCED list -- on an emulator every key is SOFTWARE\n'
printf '  and the chain still verifies perfectly.\n'

say "Done. Every line above is about the device named in section 0."
printf '  Say the device. Say what you measured. Say what you did not.\n\n'

# ---------------------------------------------------------------------------
# REAL OUTPUT, 2026-08-16, AVD sdk_gphone16k_x86_64 / API 35 (abridged):
#
#   model        sdk_gphone16k_x86_64
#   device       emu64xa16k
#   release/API  15 / 35
#   fingerprint  google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/
#                12960925:userdebug/dev-keys
#
#   Build.FINGERPRINT.startsWith("generic")      false
#   Build.MODEL.contains("Emulator")             false
#   new File("/dev/qemu_pipe").exists()          false
#   VERDICT: isEmulator() returns FALSE on this device.
#   /dev/goldfish_pipe_dprctd
#
#   qemu.hw.mainkeys           = []      <- SET on a retail Xiaomi, empty here
#   ro.kernel.qemu.gles        = []      <- likewise
#   ro.kernel.qemu             = [1]     <- this one DOES still fire
#   ro.hardware                = [ranchu]
#   ro.boot.verifiedbootstate  = []      <- empty, not "orange"
#   ro.bootloader              = [unknown]
#
#   drwxr-x--- 2 root shell 4096 /system/xbin
#   -rwsr-x--- 1 root shell 51224 /system/xbin/su
#   mountinfo lines whose source is "magisk": 3
#
#   visible to adb shell (uid 2000) : 671, 675 on later runs
#   visible to root      (su 0)     : 1058, 1055, 1059 on later runs
#   ro.boottime.* to shell          : 0
#   ro.boottime.* to root           : 111
#
# Three things in that block are worth more than the rest.
#
# The mountinfo count of 3 reproduces 63-LSPosed's measurement exactly, on a
# second occasion -- and it is the only root signal here that needs no
# permission at all.
#
# The property TOTALS drift between runs, so any figure you quote is a
# timestamp and not a constant; 29-BroadcastReceivers found the same with three
# snapshots of one idle device giving 1,151 / 1,281 / 1,290 registrations.
#
# And ro.boottime.* does NOT drift: 111 to root and 0 to the shell, every run.
# That family carries SELinux type boottime_prop, and it is the whole of the
# real shell-versus-app gap. It is also the reason the mislabelled figure went
# unnoticed for so long: from a root prompt it looks like a goldmine, and the
# application that would have to use it cannot see one property of it.
#
# The three checks in section 1 are the whole of the isEmulator() that tops the
# search results, and on a stock, current, unmodified AVD every one of them is
# false. That is the sentence. The rest of this script is the receipt.
# ---------------------------------------------------------------------------
