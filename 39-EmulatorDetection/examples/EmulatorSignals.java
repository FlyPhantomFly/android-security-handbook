// examples/EmulatorSignals.java
//
// PURPOSE
//   The Java-layer half of chapter 39's measurement kit. It reads every
//   emulator signal reachable from an ordinary application process -- an app
//   uid in the SELinux domain `untrusted_app` -- and prints each one with the
//   evidence that produced it.
//
//   This exists because `adb shell` is NOT an app. The shell runs as uid 2000
//   in the domain `u:r:shell:s0` and holds group memberships and SELinux
//   permissions an app does not. Every table in this chapter that says "an app
//   can read X" was produced by running THIS class, not by running a command.
//   Where the shell and the app disagree, the chapter prints both numbers.
//
//   It is deliberately a *probe*, not a *detector*. It computes no overall
//   boolean. See README section 3.2 for why a single isEmulator() is the
//   weakest possible shape for this logic.
//
// BUILD AND RUN
//   ../scripts/build-probe-app.sh --install --run
//
//   That script builds this file into an APK with aapt2 + javac + d8 +
//   zipalign + apksigner (no Gradle, no Android Studio, no network), installs
//   it, launches it, and prints the results back out of logcat. Read its header
//   for the manual steps if you would rather drive them yourself.
//
// READING THE OUTPUT
//   Each line is:   <group> | <signal> | <value> | <grade>
//
//   <grade> is the signal's STRENGTH, not its truth:
//
//     HARD   costly to fake; survives a naive Frida hook or needs kernel work
//     SOFT   a single value an app reads; one hook or one resetprop defeats it
//     DEAD   published everywhere, measured NOT to fire on a current AVD
//     NOISY  fires on real devices too -- a false-positive source
//     INFO   context, never a verdict on its own
//
//   The grades are assigned from measurement on a physical Redmi M2101K6P
//   (Android 11 / API 30) and a Pixel_6_Pro_API_35 AVD (Android 15 / API 35,
//   x86_64). They are recorded in README section 3.14's grading table.
//
// AUTHORISED TESTING ONLY
//   This app reads only its own process's view of the device. It requests no
//   permissions, opens no network connection, and writes nothing outside its
//   own private directory. Install it on a device you own.

package com.pentest.ch39;

import android.app.Activity;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class EmulatorSignals extends Activity {

    /** logcat tag. `adb logcat -s CH39` gives you the whole report. */
    public static final String TAG = "CH39";

    // ------------------------------------------------------------------ //
    // Grades. See the header comment.
    // ------------------------------------------------------------------ //
    private static final String HARD  = "HARD";
    private static final String SOFT  = "SOFT";
    private static final String DEAD  = "DEAD";
    private static final String NOISY = "NOISY";
    private static final String INFO  = "INFO";

    private final StringBuilder report = new StringBuilder();

    private void emit(String group, String signal, String value, String grade) {
        String line = group + " | " + signal + " | "
                + (value == null || value.isEmpty() ? "(empty)" : value)
                + " | " + grade;
        Log.i(TAG, line);
        report.append(line).append('\n');
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        emit("meta", "probe", "chapter 39 EmulatorSignals", INFO);
        emit("meta", "uid", String.valueOf(android.os.Process.myUid()), INFO);

        probeBuildFields();
        probeSystemProperties();
        probeFilesystem();
        probeSensors();
        probePackages();
        probeFeatures();
        probeTelephony();
        probeAbi();
        probeProcFiles();

        // Show it on screen as well as in logcat, so the app is usable on a
        // device with no host attached.
        TextView tv = new TextView(this);
        tv.setText(report.toString());
        tv.setTextSize(9f);
        tv.setTextIsSelectable(true);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
    }

    // ------------------------------------------------------------------ //
    // 1. android.os.Build
    // ------------------------------------------------------------------ //
    //
    // These are the single most-cited emulator signals on the internet, and
    // several of them are measurably DEAD on a current AVD.
    //
    // Where they come from: every Build field is a `public static final` set in
    // a static initialiser that calls SystemProperties.get(). The mapping lives
    // in frameworks/base/core/java/android/os/Build.java. Because they are
    // static finals populated once at class-init time, hooking
    // SystemProperties.get() AFTER Build has been loaded changes nothing --
    // the values are already latched. That timing detail is why bypass scripts
    // set the fields reflectively instead. See README section 6.4.
    //
    private void probeBuildFields() {
        emit("build", "FINGERPRINT", Build.FINGERPRINT, INFO);

        // The famous check. On the API 35 AVD measured for this chapter the
        // fingerprint is
        //   google/sdk_gphone16k_x86_64/emu64xa16k:15/...:userdebug/dev-keys
        // which contains no "generic" anywhere. This check does not fire.
        boolean genericFp = Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.contains("generic");
        emit("build", "FINGERPRINT contains 'generic'",
                String.valueOf(genericFp), DEAD);

        emit("build", "MODEL", Build.MODEL, INFO);
        // "sdk_gphone" is the current naming; "google_sdk"/"Emulator" are the
        // legacy ones and are kept only so the chapter can show the difference.
        boolean sdkModel = Build.MODEL.contains("sdk_gphone")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for");
        emit("build", "MODEL looks like an SDK image",
                String.valueOf(sdkModel), SOFT);

        emit("build", "BRAND", Build.BRAND, INFO);
        emit("build", "DEVICE", Build.DEVICE, INFO);
        // BRAND=google + DEVICE starting "generic" is the classic pair. On the
        // measured AVD DEVICE is "emu64xa16k", so again: no "generic".
        emit("build", "BRAND=generic && DEVICE=generic",
                String.valueOf(Build.BRAND.startsWith("generic")
                        && Build.DEVICE.startsWith("generic")), DEAD);

        emit("build", "PRODUCT", Build.PRODUCT, INFO);
        emit("build", "MANUFACTURER", Build.MANUFACTURER, INFO);

        // HARDWARE is the strongest field on this list because it is set from
        // the kernel command line / bootconfig (androidboot.hardware), not from
        // a build-time string. "ranchu" is the modern emulator machine type;
        // "goldfish" is its predecessor.
        emit("build", "HARDWARE", Build.HARDWARE, INFO);
        emit("build", "HARDWARE is goldfish/ranchu",
                String.valueOf("goldfish".equals(Build.HARDWARE)
                        || "ranchu".equals(Build.HARDWARE)), SOFT);

        emit("build", "BOARD", Build.BOARD, INFO);
        emit("build", "BOOTLOADER", Build.BOOTLOADER, INFO);
        emit("build", "HOST", Build.HOST, INFO);
        emit("build", "USER", Build.USER, INFO);
        emit("build", "TAGS", Build.TAGS, INFO);

        // test-keys/dev-keys means the image was not signed with the OEM's
        // release key. NOISY on purpose: it is also true of every custom ROM,
        // every AOSP build and many engineering devices, so on its own it is a
        // "this is not a retail image" signal, not an emulator signal.
        emit("build", "TAGS are test-keys/dev-keys",
                String.valueOf(Build.TAGS != null
                        && (Build.TAGS.contains("test-keys")
                            || Build.TAGS.contains("dev-keys"))), NOISY);

        emit("build", "TYPE", Build.TYPE, INFO);
        emit("build", "TYPE is userdebug/eng",
                String.valueOf("userdebug".equals(Build.TYPE)
                        || "eng".equals(Build.TYPE)), NOISY);

        emit("build", "VERSION.SDK_INT", String.valueOf(Build.VERSION.SDK_INT), INFO);
    }

    // ------------------------------------------------------------------ //
    // 2. System properties through the hidden SystemProperties class
    // ------------------------------------------------------------------ //
    //
    // android.os.SystemProperties is @hide, so an app reaches it by reflection.
    // On API 28+ it is on the greylist rather than the blocklist, which is why
    // this still works; a blocklisted member would throw. If reflection is
    // refused, this method says so rather than silently reporting "not an
    // emulator", which is the failure mode of most published implementations.
    //
    private String getProp(String key) {
        try {
            @SuppressWarnings("rawtypes")
            Class c = Class.forName("android.os.SystemProperties");
            @SuppressWarnings("unchecked")
            Method get = c.getMethod("get", String.class);
            Object v = get.invoke(null, key);
            return v == null ? "" : (String) v;
        } catch (Throwable t) {
            // Distinguish "no value" from "could not ask". They are not the
            // same, and conflating them is how a check silently stops working.
            return "<reflection-failed:" + t.getClass().getSimpleName() + ">";
        }
    }

    private void probeSystemProperties() {
        // Grade SOFT throughout: an app reads these one key at a time through a
        // single method, so one Frida hook on SystemProperties.get covers every
        // row at once. Compare examples/emu_probe.c, which reads the same
        // values through libc where that hook does not reach.
        String[] keys = {
            "ro.kernel.qemu", "ro.boot.qemu", "ro.boot.qemu.avd_name",
            "ro.hardware", "ro.boot.hardware", "ro.product.board",
            "ro.hardware.egl", "ro.hardware.gralloc", "ro.hardware.vulkan",
            "ro.soc.model", "ro.build.characteristics",
            "ro.dalvik.vm.native.bridge", "init.svc.goldfish-logcat",
            "ro.boottime.qemu-props", "ro.boottime.ranchu-net",
            "qemu.hw.mainkeys", "ro.kernel.qemu.gles",
        };
        for (String k : keys) {
            String v = getProp(k);
            // The last two rows are the interesting ones. Both are SET on the
            // physical Redmi measured for this chapter -- qemu.hw.mainkeys=0
            // and ro.kernel.qemu.gles=0 -- so any check of the form "a property
            // whose name contains qemu exists" reports a real phone as an
            // emulator. Graded NOISY for exactly that reason.
            String grade = ("qemu.hw.mainkeys".equals(k)
                         || "ro.kernel.qemu.gles".equals(k)) ? NOISY : SOFT;
            emit("prop", k, v, grade);
        }
    }

    // ------------------------------------------------------------------ //
    // 3. Filesystem
    // ------------------------------------------------------------------ //
    //
    // File.exists() ends in a faccessat(AT_FDCWD, path, F_OK, 0) syscall and
    // returns false for BOTH "absent" and "forbidden". An app cannot tell those
    // apart at this layer; examples/emu_probe.c can, because it reads errno.
    // README section 3.6 works through why that matters.
    //
    private void probeFilesystem() {
        // Graded DEAD: measured absent on the API 35 AVD. They are in every
        // published checklist and they no longer fire.
        String[] dead = {
            "/dev/qemu_pipe",
            "/dev/socket/qemud",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/bin/qemu-props",
            "/system/bin/qemud",
            "/dev/goldfish_pipe",
        };
        for (String p : dead) {
            emit("file", p, String.valueOf(new File(p).exists()), DEAD);
        }

        // Graded SOFT: measured PRESENT on the API 35 AVD. These are what the
        // dead checks above were renamed to.
        String[] live = {
            "/dev/goldfish_pipe_dprctd",
            "/dev/goldfish_sync",
            "/dev/goldfish_address_space",
            "/sys/module/goldfish_pipe",
            "/sys/bus/platform/drivers/goldfish_pipe",
        };
        for (String p : live) {
            emit("file", p, String.valueOf(new File(p).exists()), SOFT);
        }

        // Other virtualisation stacks.
        String[] others = {
            "/dev/socket/genyd", "/dev/socket/baseband_genyd",
            "/dev/vboxguest", "/dev/vboxuser",
            "/system/bin/androVM-prop", "/system/bin/microvirt-prop",
        };
        for (String p : others) {
            emit("file", p, String.valueOf(new File(p).exists()), SOFT);
        }
    }

    // ------------------------------------------------------------------ //
    // 4. Sensors
    // ------------------------------------------------------------------ //
    //
    // The best cheap signal on this list, because it is not one value -- it is
    // a whole population, and faking it means fabricating a consistent set of
    // vendor strings, resolutions, power figures and delivery rates rather than
    // patching one string.
    //
    // Measured: 41 hardware sensors on the physical Redmi against 12 on the
    // API 35 AVD, and every AVD sensor is vendored to "AOSP" or "The Android
    // Open Source Project" while the phone's name real silicon -- TDK-Invensense,
    // akm, Rohm, qualcomm, XiaoMi.
    //
    private void probeSensors() {
        SensorManager sm = (SensorManager) getSystemService(SENSOR_SERVICE);
        if (sm == null) {
            emit("sensor", "SensorManager", "unavailable", INFO);
            return;
        }
        List<Sensor> all = sm.getSensorList(Sensor.TYPE_ALL);
        emit("sensor", "count(TYPE_ALL)", String.valueOf(all.size()), HARD);

        int aospVendor = 0;
        List<String> vendors = new ArrayList<String>();
        for (Sensor s : all) {
            String v = s.getVendor();
            if (!vendors.contains(v)) {
                vendors.add(v);
            }
            if (v != null && (v.contains("AOSP")
                    || v.contains("The Android Open Source Project")
                    || v.contains("Goldfish"))) {
                aospVendor++;
            }
        }
        emit("sensor", "distinct vendors", vendors.toString(), HARD);
        emit("sensor", "sensors vendored AOSP/Goldfish",
                aospVendor + "/" + all.size(), HARD);

        // A device with no accelerometer at all is either an emulator with
        // sensors switched off, or a television. Check the form factor before
        // concluding.
        emit("sensor", "has accelerometer",
                String.valueOf(sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null), SOFT);
        emit("sensor", "has gyroscope",
                String.valueOf(sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null), SOFT);
        // Step counter is a good one: it needs a low-power always-on sensor hub
        // that emulators do not model and cheap phones sometimes lack. NOISY.
        emit("sensor", "has step counter",
                String.valueOf(sm.getDefaultSensor(Sensor.TYPE_STEP_COUNTER) != null), NOISY);
    }

    // ------------------------------------------------------------------ //
    // 5. Installed packages
    // ------------------------------------------------------------------ //
    //
    // Note the API 30 change: an app targeting API 30+ cannot enumerate
    // arbitrary packages without QUERY_ALL_PACKAGES or a <queries> element.
    // getInstalledPackages() therefore returns a FILTERED list -- and the
    // filtering is silent. A package-counting check written before API 30 and
    // never revisited now counts a handful of visible packages on every device
    // and reports "suspiciously few packages: emulator". That is a real
    // false-positive class, and it is why this is graded NOISY.
    //
    private void probePackages() {
        PackageManager pm = getPackageManager();
        int count = -1;
        try {
            count = pm.getInstalledPackages(0).size();
        } catch (Throwable t) {
            emit("pkg", "getInstalledPackages", "threw " + t.getClass().getSimpleName(), INFO);
        }
        emit("pkg", "visible package count", String.valueOf(count), NOISY);

        // Emulator-only overlay packages. On the API 35 AVD there are dozens of
        // com.android.internal.emulation.pixel_* and com.android.systemui.
        // emulation.pixel_* device-profile overlays. On the Redmi there are only
        // the display-cutout emulation overlays, which exist on every device --
        // so matching on the bare word "emulation" is a false positive and the
        // pattern has to be anchored. Measured: 5 cutout overlays on the phone.
        String[] telltale = {
            "com.android.emulator.multidisplay",
            "com.android.emulator.radio.config",
            "com.google.android.connectivity.resources.goldfish.overlay",
            "com.bluestacks.appmart",
            "com.genymotion.genyd",
        };
        for (String p : telltale) {
            boolean present;
            try {
                pm.getPackageInfo(p, 0);
                present = true;
            } catch (PackageManager.NameNotFoundException e) {
                present = false;
            }
            emit("pkg", p, String.valueOf(present), SOFT);
        }
    }

    // ------------------------------------------------------------------ //
    // 6. Hardware features
    // ------------------------------------------------------------------ //
    private void probeFeatures() {
        PackageManager pm = getPackageManager();
        FeatureInfo[] fi = pm.getSystemAvailableFeatures();
        emit("feature", "total features", String.valueOf(fi == null ? -1 : fi.length), INFO);

        String[] feats = {
            PackageManager.FEATURE_TELEPHONY,
            PackageManager.FEATURE_BLUETOOTH,
            PackageManager.FEATURE_CAMERA_FLASH,
            PackageManager.FEATURE_SENSOR_STEP_COUNTER,
            PackageManager.FEATURE_NFC,
            PackageManager.FEATURE_WIFI,
            PackageManager.FEATURE_TOUCHSCREEN_MULTITOUCH_JAZZHAND,
        };
        for (String f : feats) {
            emit("feature", f, String.valueOf(pm.hasSystemFeature(f)), NOISY);
        }
    }

    // ------------------------------------------------------------------ //
    // 7. Telephony
    // ------------------------------------------------------------------ //
    //
    // Historically the giveaway was the operator "Android" with MCC/MNC 310260
    // and the line-1 number 15555215554. The MCC/MNC is still 310260 on the
    // measured AVD, but the operator NAME now reads "T-Mobile" -- 310260 is
    // genuinely T-Mobile US -- so a name check no longer fires while a
    // numeric check does. Only the numeric check is worth writing.
    //
    // Nothing here needs a permission: getNetworkOperator, getSimOperator,
    // getPhoneType and getSimOperatorName are all permission-free. Anything
    // touching the subscriber (IMEI, line-1 number) requires privileged access
    // an ordinary app cannot get on API 29+, so this probe does not ask -- and
    // any published check that reads the IMEI has been dead since API 29.
    //
    private void probeTelephony() {
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        if (tm == null) {
            emit("telephony", "TelephonyManager", "unavailable", INFO);
            return;
        }
        String netOp = tm.getNetworkOperator();
        String simOp = tm.getSimOperator();
        emit("telephony", "getNetworkOperator (MCCMNC)", netOp, SOFT);
        emit("telephony", "getSimOperator (MCCMNC)", simOp, SOFT);
        emit("telephony", "getNetworkOperatorName", tm.getNetworkOperatorName(), DEAD);
        emit("telephony", "getSimOperatorName", tm.getSimOperatorName(), DEAD);
        emit("telephony", "MCCMNC is 310260 (AVD default)",
                String.valueOf("310260".equals(netOp) || "310260".equals(simOp)), SOFT);
        emit("telephony", "getPhoneType", String.valueOf(tm.getPhoneType()), INFO);
    }

    // ------------------------------------------------------------------ //
    // 8. ABI
    // ------------------------------------------------------------------ //
    //
    // Build.SUPPORTED_ABIS listing an x86 ABI first, with arm64-v8a present
    // behind it, means a binary translator is installed. On the measured AVD
    // this reads [x86_64, arm64-v8a] and ro.dalvik.vm.native.bridge names
    // libndk_translation.so. No physical arm64 phone advertises x86_64.
    //
    private void probeAbi() {
        StringBuilder sb = new StringBuilder();
        for (String a : Build.SUPPORTED_ABIS) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(a);
        }
        emit("abi", "SUPPORTED_ABIS", sb.toString(), HARD);

        boolean x86 = false, arm = false;
        for (String a : Build.SUPPORTED_ABIS) {
            if (a.startsWith("x86")) {
                x86 = true;
            }
            if (a.startsWith("arm")) {
                arm = true;
            }
        }
        emit("abi", "advertises both x86 and ARM", String.valueOf(x86 && arm), HARD);
        emit("abi", "ro.dalvik.vm.native.bridge",
                getProp("ro.dalvik.vm.native.bridge"), HARD);
    }

    // ------------------------------------------------------------------ //
    // 9. /proc files an app may actually read
    // ------------------------------------------------------------------ //
    //
    // Measured, and this is the section most published checklists get wrong:
    //
    //   /proc/cpuinfo        readable by an app        -- usable
    //   /proc/self/mounts    readable by an app        -- usable
    //   /proc/tty/drivers    EACCES for shell AND app  -- NOT usable
    //   /proc/cmdline        EACCES for shell AND app  -- NOT usable
    //
    // The last two appear in nearly every "how to detect an emulator" article.
    // They cannot be read from an app on a modern device at all, so a check
    // built on them returns "no emulator" forever and nobody notices, because
    // the failure mode is a silent false negative.
    //
    private String readAll(String path) {
        BufferedReader r = null;
        try {
            StringBuilder sb = new StringBuilder();
            r = new BufferedReader(new FileReader(path));
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            return "<unreadable:" + t.getClass().getSimpleName() + ">";
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Throwable ignored) {
                    // Closing a reader we already failed to use adds nothing.
                }
            }
        }
    }

    private void probeProcFiles() {
        String cpu = readAll("/proc/cpuinfo");
        emit("proc", "/proc/cpuinfo readable",
                String.valueOf(!cpu.startsWith("<unreadable")), INFO);
        // The `hypervisor` CPUID feature bit is reported by the CPU, not by
        // Android, so the guest cannot clear it from userspace. HARD -- but only
        // on x86. An ARM emulator image has no equivalent bit, so a false here
        // proves nothing on an arm64 device.
        emit("proc", "cpuinfo has 'hypervisor' flag (x86 only)",
                String.valueOf(cpu.contains("hypervisor")), HARD);
        emit("proc", "cpuinfo has 'Android virtual processor'",
                String.valueOf(cpu.contains("Android virtual processor")), SOFT);

        String tty = readAll("/proc/tty/drivers");
        emit("proc", "/proc/tty/drivers readable",
                String.valueOf(!tty.startsWith("<unreadable")), DEAD);
        emit("proc", "tty drivers mention goldfish",
                String.valueOf(tty.contains("goldfish")), DEAD);

        String cmdline = readAll("/proc/cmdline");
        emit("proc", "/proc/cmdline readable",
                String.valueOf(!cmdline.startsWith("<unreadable")), DEAD);

        String mounts = readAll("/proc/self/mounts");
        emit("proc", "/proc/self/mounts readable",
                String.valueOf(!mounts.startsWith("<unreadable")), INFO);
        emit("proc", "mounts mention goldfish/ranchu",
                String.valueOf(mounts.contains("goldfish") || mounts.contains("ranchu")), SOFT);
        // Mount-table SIZE is a surprisingly serviceable signal and almost
        // nobody uses it: measured 254 lines on the Redmi against 137 on the
        // AVD. It is INFO rather than a verdict because the number moves with
        // OEM, API level and how many APEX modules are mounted.
        int mountLines = mounts.startsWith("<unreadable")
                ? -1 : mounts.split("\n").length;
        emit("proc", "mount entry count", String.valueOf(mountLines), INFO);
    }
}
