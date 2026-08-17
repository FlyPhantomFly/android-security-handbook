// IRiskyParser.aidl — the ENTIRE interface of an isolated process.
//
// WHAT IT DOES
//   Declares the two-method Binder interface between a host app and a service
//   running with android:isolatedProcess="true".
//
// WHY IT MATTERS
//   This file is the security argument, not the plumbing. An isolated process
//   has no UID of the host's, no permissions, no network, and no data
//   directory. Its complete data interface to the rest of the world is:
//
//       (a) the methods declared in this file, and
//       (b) any file descriptor the host explicitly passes across them.
//
//   That is the whole attack surface, and it is small enough to audit by
//   reading one file. Compare that with a parser running in the app's main
//   process, whose attack surface is "everything the app can reach".
//
//   Note countLines(): the host opens the file and passes a ParcelFileDescriptor.
//   The isolated process cannot open ANY file, but it can read through a
//   descriptor someone else opened, because the kernel checks permissions once,
//   at open() time, in the opening process — and never rechecks reads through
//   the resulting descriptor. That is the same mechanism that makes a
//   ContentProvider.openFile() path traversal so damaging (chapter 21 section
//   3.15, escape class 5). Used deliberately it is what makes isolated
//   processes usable at all.
//
// HOW TO USE
//   Place at src/main/aidl/com/example/sandboxlab/IRiskyParser.aidl and enable
//   AIDL in build.gradle:  android { buildFeatures { aidl true } }
//
// REQUIREMENTS
//   Android Gradle Plugin with AIDL enabled. No permissions.

package com.example.sandboxlab;

interface IRiskyParser {

    /**
     * Returns a human-readable report of what this process can actually reach.
     * Run it in an isolated process and in a normal one and diff the two —
     * that diff is the value of android:isolatedProcess, demonstrated rather
     * than asserted.
     */
    String probeSandbox();

    /**
     * Parses whatever the caller hands us, through a descriptor we did not and
     * could not open ourselves.
     *
     * Design rule for any real isolated worker: the return value must be a
     * PARSED RESULT, never a path, a handle, or anything the host will then
     * blindly trust. An attacker with code execution inside the isolated
     * process controls this return value, so the host must treat it as
     * untrusted input.
     */
    int countLines(in ParcelFileDescriptor pfd);
}
