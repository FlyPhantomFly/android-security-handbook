/*
 * examples/RawBinderClient.java
 *
 * WHAT THIS IS
 *   Calling a Binder service with NO generated code: no .aidl file, no Stub,
 *   no Proxy, and no dependency on the target app at all. Just a descriptor
 *   string, a transaction code, and a Parcel built by hand.
 *
 *   This is what an attacker actually writes, and shipping it is the point.
 *   Developers routinely assume their service is only reachable through the
 *   client library they wrote, and design their validation on that
 *   assumption. It is false.
 *
 * WHAT YOU NEED BEFORE YOU CAN USE IT
 *   Exactly two things, and both come out of JADX in about five minutes:
 *
 *     1. The DESCRIPTOR string. In the decompiled Stub it is a literal:
 *          private static final String DESCRIPTOR = "com.example.vault.IVaultService";
 *        It SURVIVES R8 -- both ends compare it at runtime, so it cannot be
 *        renamed -- and it is often the original, un-obfuscated class name.
 *        You can also just ask the object: transaction 1598968902 ('_NTF').
 *
 *     2. The transaction CODE. In the Stub:
 *          static final int TRANSACTION_readSecret =
 *              android.os.IBinder.FIRST_CALL_TRANSACTION + 0;   // = 1
 *        The codes are the methods' positions in the .aidl, starting at 1.
 *
 *   The parcel layout comes from the same place: the sequence of
 *   data.readXxx() calls inside the Stub's case for that code, in order.
 *
 * HOW TO RUN
 *   Drop this class into an ordinary, unprivileged Android app -- uid 10xxx,
 *   SELinux domain untrusted_app -- and call probe()/readSecretRaw() from an
 *   Activity.
 *
 *   RUN IT FROM AN APP, NOT FROM `adb shell`. This matters more than anything
 *   else in the file. `adb shell` is uid 2000 in the `shell` domain and holds
 *   platform permissions and service_manager:find rules that NO app has.
 *   Plenty of services answer `adb shell` happily and are completely
 *   unreachable from an app. Reproducing from a real app context is what
 *   separates a finding from a false positive. See README section 11.2.
 *
 *   Two ways to obtain the IBinder:
 *
 *     a) An app's exported service, via bindService() -- see bindAndProbe().
 *     b) A registered system service, via the hidden
 *        android.os.ServiceManager.getService(String). That class is
 *        @hide, so reaching it needs reflection and is blocked by the
 *        non-SDK interface restrictions on API 28+. getSystemServiceBinder()
 *        below shows the reflection and says plainly when it will fail.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - What a transaction code MEANS. Binder carries no schema and the device
 *     holds no .aidl files. Code 7 is whatever the interface said it was.
 *   - Whether a failure was SELinux, a missing manifest permission, or the
 *     service's own check. Read the exception: a SecurityException with a
 *     message naming a uid is the service's own check; a null IBinder from
 *     getService is usually SELinux service_manager:find; a DeadObjectException
 *     may be either a dead target or an exhausted binder buffer (README 3.14).
 *   - Anything safely. transact() with a guessed code on a service with no
 *     enforceInterface can crash that service, and crashing system_server
 *     reboots the device. Guess codes on a spare device, with a death
 *     recipient attached so you know which code did it.
 *
 * DO NOT point this at software you are not authorised to test.
 */

package com.example.rawclient;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import java.lang.reflect.Method;

public final class RawBinderClient {

    private static final String TAG = "RawBinderClient";

    /** The four ASCII bytes '_NTF', packed big-endian. See README 3.8. */
    public static final int INTERFACE_TRANSACTION     = 0x5f4e5446;   // 1598968902
    public static final int DUMP_TRANSACTION          = 0x5f444d50;   // 1598311760
    public static final int SHELL_COMMAND_TRANSACTION = 0x5f434d44;   // 1598246212
    public static final int PING_TRANSACTION          = 0x5f504e47;   // 1599098439

    private RawBinderClient() { }

    /* ====================================================================
     * 1. THE THREE PROBES YOU RUN BEFORE ANYTHING ELSE
     * ==================================================================== */

    /**
     * "What interface do you claim to be?"
     *
     * This is how you obtain the interface token without decompiling
     * anything, and it is the first thing to run against an unknown object.
     *
     * An EMPTY or null result is the most interesting outcome. It means the
     * object did not answer with a descriptor, which almost always means a
     * raw Binder subclass with a hand-written onTransact -- no
     * enforceInterface, so every transaction code is reachable with an
     * arbitrary parcel. That is a lead, not an error. See README 3.9.
     */
    public static String getDescriptor(IBinder binder) {
        // The convenience method does exactly this transaction for you...
        try {
            final String viaApi = binder.getInterfaceDescriptor();
            if (viaApi != null && !viaApi.isEmpty()) return viaApi;
        } catch (RemoteException e) {
            Log.w(TAG, "getInterfaceDescriptor threw", e);
        }
        // ...but here is the transaction itself, so you can see there is no
        // magic in it.
        final Parcel data  = Parcel.obtain();
        final Parcel reply = Parcel.obtain();
        try {
            binder.transact(INTERFACE_TRANSACTION, data, reply, 0);
            return reply.readString();
        } catch (RemoteException e) {
            return null;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    /** "Are you alive?" -- transaction '_PNG'. Cheap, harmless, and definitive. */
    public static boolean ping(IBinder binder) {
        return binder != null && binder.pingBinder();
    }

    /**
     * "Tell me when you die."
     *
     * This is the whole fuzzing harness in one call. Attach it before you
     * sweep transaction codes and you learn IMMEDIATELY which input killed
     * the service, without having to correlate against logcat.
     */
    public static void watchForDeath(IBinder binder, final String label) {
        try {
            binder.linkToDeath(new IBinder.DeathRecipient() {
                @Override public void binderDied() {
                    Log.e(TAG, "*** " + label + " DIED *** -- the last code you sent did this");
                }
            }, 0);
        } catch (RemoteException e) {
            Log.w(TAG, label + " was already dead");
        }
    }

    /* ====================================================================
     * 2. CALLING A METHOD WITH NO GENERATED CODE
     * ==================================================================== */

    /**
     * IVaultService.readSecret(String) -- transaction code 1.
     *
     * Compare this with the generated Proxy method it replaces. They are the
     * same six lines. That is the point: the generated client is a
     * convenience, never a gate.
     *
     * Parcel layout, straight from the Stub's `case 1:` body:
     *   in  : interface token, then String16 name
     *   out : int32 exception header, then String16 result
     */
    public static String readSecretRaw(IBinder binder, String descriptor, String name)
            throws RemoteException {
        final Parcel data  = Parcel.obtain();
        final Parcel reply = Parcel.obtain();
        try {
            // writeInterfaceToken emits FOUR fields, in this order:
            //   int32 strict-mode policy
            //   int32 work-source uid   (-1 = unset)
            //   int32 header 'SYST' = 0x53595354
            //   String16 descriptor
            // Getting any of them wrong produces
            //   SecurityException: "Binder invocation to an incorrect interface"
            data.writeInterfaceToken(descriptor);
            data.writeString(name);

            binder.transact(1 /* readSecret */, data, reply, 0);

            // Decodes the int32 header: 0 means none, -1 SecurityException,
            // -3 IllegalArgumentException, and so on. See README 3.7.5.
            reply.readException();
            return reply.readString();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    /**
     * A oneway call -- IVaultService.notifyChanged(String), code 5.
     *
     * FLAG_ONEWAY changes three things and you must expect all three:
     *   - transact() returns immediately; the reply Parcel is never written;
     *   - an exception thrown by the service NEVER reaches you. A refusal and
     *     a success look identical from here;
     *   - the service sees Binder.getCallingPid() == 0.
     *
     * So a oneway method is a poor oracle. If you need to know whether the
     * call was accepted, find a synchronous method that observes the same
     * state.
     */
    public static void notifyChangedOneway(IBinder binder, String descriptor, String name)
            throws RemoteException {
        final Parcel data = Parcel.obtain();
        try {
            data.writeInterfaceToken(descriptor);
            data.writeString(name);
            binder.transact(5 /* notifyChanged */, data, null, IBinder.FLAG_ONEWAY);
        } finally {
            data.recycle();
        }
    }

    /* ====================================================================
     * 3. SWEEPING TRANSACTION CODES
     * ==================================================================== */

    /**
     * Try a range of codes with an empty (but correctly tokenised) parcel and
     * report what came back.
     *
     * READ THE FAILURES, NOT THE SUCCESSES. The exception tells you more than
     * a result does:
     *
     *   SecurityException          the code EXISTS and you were refused. The
     *                              message often names the uid it saw and the
     *                              guard method, and the reply carries a
     *                              remote stack trace naming the class and
     *                              line. This is the most informative outcome
     *                              there is.
     *   IllegalArgumentException   the code EXISTS and your ARGUMENTS were
     *   NullPointerException       wrong. Keep going; add arguments.
     *   "unknown transaction"      the code does not exist.
     *   nothing, empty reply       it worked and returned void.
     *
     * SAFETY: a code you guessed, sent to a service with no enforceInterface,
     * can crash that service. Call watchForDeath() first. Do this on a device
     * you can afford to reboot.
     */
    public static void sweepCodes(IBinder binder, String descriptor, int from, int to) {
        watchForDeath(binder, descriptor);
        for (int code = from; code <= to; code++) {
            final Parcel data  = Parcel.obtain();
            final Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(descriptor);
                binder.transact(code, data, reply, 0);
                reply.readException();
                Log.i(TAG, "code " + code + ": OK, reply " + reply.dataSize() + " bytes");
            } catch (SecurityException e) {
                Log.w(TAG, "code " + code + ": EXISTS, refused -- " + e.getMessage());
            } catch (IllegalArgumentException | NullPointerException e) {
                Log.w(TAG, "code " + code + ": EXISTS, wrong args -- " + e.getMessage());
            } catch (RemoteException e) {
                Log.e(TAG, "code " + code + ": transact failed -- " + e);
            } catch (RuntimeException e) {
                Log.w(TAG, "code " + code + ": " + e.getClass().getSimpleName()
                        + " -- " + e.getMessage());
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
    }

    /**
     * Send a DELIBERATELY WRONG interface token and confirm the service
     * rejects it. Run this once per target: a service that accepts a wrong
     * token has no enforceInterface, which is a finding on its own.
     *
     * Expected on a healthy service, measured on a real device:
     *   SecurityException: "Binder invocation to an incorrect interface"
     */
    public static void probeTokenEnforcement(IBinder binder, int code) {
        final Parcel data  = Parcel.obtain();
        final Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken("com.example.definitely.not.this.Interface");
            binder.transact(code, data, reply, 0);
            reply.readException();
            Log.e(TAG, "!!! wrong token ACCEPTED at code " + code
                     + " -- no enforceInterface. Every code is reachable.");
        } catch (SecurityException e) {
            Log.i(TAG, "token enforced (good): " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "rejected with " + e.getClass().getSimpleName()
                     + ": " + e.getMessage());
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    /* ====================================================================
     * 4. GETTING HOLD OF AN IBinder
     * ==================================================================== */

    /**
     * Bind an app's exported service and hand the IBinder to a callback.
     *
     * Note what the manifest permission does and does not do: it is checked
     * ONCE, here, by ActivityManager. Once you hold the IBinder you may call
     * it forever, and you may pass it on to someone who never held the
     * permission. That is why a service must ALSO check inside onTransact.
     */
    public interface OnBound { void onBound(IBinder binder); }

    public static ServiceConnection bindAndProbe(Context ctx, String pkg, String cls,
                                                 final OnBound cb) {
        final Intent intent = new Intent();
        intent.setComponent(new ComponentName(pkg, cls));
        final ServiceConnection conn = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName n, IBinder binder) {
                Log.i(TAG, "bound: " + n);
                Log.i(TAG, "  descriptor = " + getDescriptor(binder));
                Log.i(TAG, "  alive      = " + ping(binder));
                watchForDeath(binder, n.flattenToShortString());
                cb.onBound(binder);
            }
            @Override public void onServiceDisconnected(ComponentName n) {
                Log.w(TAG, "disconnected: " + n);
            }
        };
        if (!ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE)) {
            Log.e(TAG, "bindService refused -- not exported, or a permission we lack, "
                     + "or (API 30+) missing <queries> in our manifest");
        }
        return conn;
    }

    /**
     * android.os.ServiceManager.getService(String) by reflection.
     *
     * BE HONEST ABOUT THIS ONE. ServiceManager is @hide, and non-SDK
     * interface restrictions (API 28+) will usually block the reflective
     * lookup from an ordinary app. When it fails, that is the platform
     * working, not your code being wrong.
     *
     * A null return has three quite different causes and they are worth
     * distinguishing before you conclude anything:
     *   - the service is not registered under that name;
     *   - SELinux refused service_manager:find for your domain (the common
     *     case for an app, and the reason `adb shell` results do not
     *     transfer);
     *   - the reflective call itself was blocked.
     */
    public static IBinder getSystemServiceBinder(String name) {
        try {
            final Class<?> sm = Class.forName("android.os.ServiceManager");
            final Method get = sm.getMethod("getService", String.class);
            final IBinder b = (IBinder) get.invoke(null, name);
            if (b == null) {
                Log.w(TAG, "getService(\"" + name + "\") returned null: not registered, "
                         + "or SELinux denied service_manager:find for our domain");
            }
            return b;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            Log.e(TAG, "ServiceManager not reachable -- non-SDK interface restrictions", e);
        } catch (Exception e) {
            Log.e(TAG, "reflective getService failed", e);
        }
        return null;
    }

    /* ====================================================================
     * 5. A COMPLETE WORKED SEQUENCE
     * ==================================================================== */

    /** What you actually run first, in order. */
    public static void assess(IBinder binder) {
        if (binder == null) { Log.e(TAG, "no binder"); return; }

        final String desc = getDescriptor(binder);
        Log.i(TAG, "descriptor : " + (desc == null || desc.isEmpty()
                ? "<EMPTY> -- raw BBinder, no interface token enforced. START HERE."
                : desc));
        Log.i(TAG, "alive      : " + ping(binder));

        watchForDeath(binder, desc == null ? "target" : desc);

        if (desc != null && !desc.isEmpty()) {
            // Confirm the token is actually enforced before trusting it as a
            // constraint on what you can send.
            probeTokenEnforcement(binder, 1);
            // Then map the interface. Keep the range small at first.
            sweepCodes(binder, desc, 1, 20);
        } else {
            // No token to write at all. An empty parcel reaches onTransact.
            Log.w(TAG, "no descriptor: sweeping with an EMPTY parcel. "
                     + "Expect crashes. Spare device only.");
        }
    }
}
