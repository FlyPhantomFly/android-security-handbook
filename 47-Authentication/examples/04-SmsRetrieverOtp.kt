// 47-Authentication/examples/04-SmsRetrieverOtp.kt
//
// PURPOSE
//   SMS one-time-password collection done the way it should be done on Android:
//   with NO SMS permission at all, using the SMS Retriever API - and the same
//   flow written the wrong way, with READ_SMS, so the difference is concrete.
//
// WHY THIS MATTERS MORE THAN IT LOOKS
//   Measured across 17 real APKs pulled from a consumer handset (README 8.6):
//
//       12/17 contained SMS Retriever markers
//        9/17 ALSO contained READ_SMS / RECEIVE_SMS markers
//        2/17 actually declared full SMS access in the manifest
//
//   That overlap is the finding. An app that demonstrably has a working,
//   permissionless path to the one message it needs, and reads the user's entire
//   message history anyway, has a privacy defect that is easy to argue and hard
//   to justify. It usually happens because an SDK bundles one API while the
//   app's own code uses the other - which is why you must check what the app
//   ACTUALLY requests at runtime, not just what a grep finds.
//
// THE THREE PERMISSIONLESS OPTIONS
//   1. SMS Retriever API      - app gets ONE message, matched by an 11-char hash
//                               of its package + signing certificate. No UI, no
//                               permission, no user interaction. Best.
//   2. SMS User Consent API   - app gets ONE message after the user taps a
//                               system dialog. No permission. Use when you
//                               cannot control the message format.
//   3. createAppSpecificSmsToken - platform API 26+, same idea, token in body.
//
//   READ_SMS is not on that list because it is never the right answer for OTP.
//
// DEPENDENCIES
//   com.google.android.gms:play-services-auth-api-phone

package com.pentest.ch47.otp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.Status

// ===========================================================================
// THE CORRECT VERSION
// ===========================================================================

class OtpAutofill(private val context: Context) {

    private var receiver: SmsBroadcastReceiver? = null

    /**
     * Start listening BEFORE asking the server to send the code, so there is no
     * window in which the message can arrive unobserved. The listener expires
     * after five minutes on its own; there is nothing to clean up if the user
     * abandons the flow, but unregister anyway (see [stop]).
     */
    fun start(onCode: (String) -> Unit, onTimeout: () -> Unit) {
        val client = SmsRetriever.getClient(context)

        // No permission is requested here. None is needed. This is the entire
        // point of the API, and it is the sentence to quote in a report when a
        // developer argues that READ_SMS is required for OTP.
        client.startSmsRetriever().addOnSuccessListener {

            receiver = SmsBroadcastReceiver(
                onMessage = { body -> extractCode(body)?.let(onCode) },
                onTimeout = onTimeout
            )
            context.registerReceiver(
                receiver,
                IntentFilter(SmsRetriever.SMS_RETRIEVED_ACTION),
                // The broadcast is protected: only Play services holds this
                // permission, so no other app can forge an OTP delivery into
                // this receiver. Omitting it would make the receiver spoofable
                // by any app on the device - which would be a real vulnerability
                // in an app that then auto-submits the code.
                SmsRetriever.SEND_PERMISSION,
                null
            )
        }
    }

    fun stop() {
        receiver?.let {
            runCatching { context.unregisterReceiver(it) }
            receiver = null
        }
    }

    /**
     * Pull the digits out of the message body.
     *
     * Deliberately anchored and length-bounded. A greedy `\d+` will happily
     * match a phone number, an order id, or the year in a footer, and an app
     * that auto-submits whatever it matched will lock the user's account out by
     * submitting garbage - which is a real bug that presents as "OTP never
     * works".
     */
    private fun extractCode(body: String): String? =
        Regex("""(?<!\d)(\d{6})(?!\d)""").find(body)?.groupValues?.get(1)
}

class SmsBroadcastReceiver(
    private val onMessage: (String) -> Unit,
    private val onTimeout: () -> Unit
) : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != SmsRetriever.SMS_RETRIEVED_ACTION) return

        val extras = intent.extras ?: return
        val status = extras.get(SmsRetriever.EXTRA_STATUS) as? Status ?: return

        when (status.statusCode) {
            CommonStatusCodes.SUCCESS -> {
                // This is the ONLY message this app will ever receive through
                // this channel: the one whose body ended with this app's own
                // 11-character hash. Not the inbox. Not other senders. One
                // message, matched by package name AND signing certificate.
                val body = extras.getString(SmsRetriever.EXTRA_SMS_MESSAGE) ?: return
                onMessage(body)
            }
            CommonStatusCodes.TIMEOUT -> onTimeout()
        }
    }
}

// ===========================================================================
// THE WRONG VERSION - for comparison only. DO NOT SHIP.
// ===========================================================================
//
// AndroidManifest.xml:
//     <uses-permission android:name="android.permission.RECEIVE_SMS"/>
//     <uses-permission android:name="android.permission.READ_SMS"/>
//     <receiver android:name=".SmsWatcher" android:exported="true">
//         <intent-filter android:priority="999">
//             <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
//         </intent-filter>
//     </receiver>
//
// class SmsWatcher : BroadcastReceiver() {
//     override fun onReceive(context: Context, intent: Intent) {
//         for (sms in Telephony.Sms.Intents.getMessagesFromIntent(intent)) {
//             // EVERY message. From everyone. Forever. Including the user's
//             // bank, their doctor, their other two-factor codes, and their
//             // private correspondence.
//             Log.d("otp", sms.messageBody)
//         }
//     }
// }
//
// What the user is asked: a runtime permission dialog reading roughly "Allow
// <app> to send and view SMS messages?" - which does not convey "and read every
// message you have ever received". What the app gets: the whole inbox, and the
// ability to read it at any time in the future for any reason.
//
// WHAT TO WRITE IN THE REPORT
//   Severity: Medium on its own. It rises if the app also has INTERNET (it
//   does) and bundles analytics or attribution SDKs (it probably does), because
//   message content then plausibly leaves the device - at which point you should
//   look for it in the traffic rather than speculating.
//
//   The recommendation writes itself and is unusually easy for a developer to
//   accept: the SMS Retriever API is a drop-in replacement, needs no permission,
//   removes a permission prompt from the onboarding funnel (which product will
//   like), and requires one change on the server - appending the app's hash to
//   the message.

// ===========================================================================
// THE MESSAGE FORMAT, AND THE HASH
// ===========================================================================
//
// SMS Retriever matches on a strict format. The message must:
//   - begin with <#>
//   - contain the one-time code
//   - end with an 11-character hash identifying the app
//   - be no more than 140 bytes
//
//     <#> Your VulnBank code is 481203
//     FA+9qCX9VSu
//
// The hash is computed from the package name and the signing certificate:
//
//     hash = base64( SHA-256( "<package> <hex of signing cert DER>" )[0:9] )[0:11]
//
// scripts/sms-retriever-hash.py computes it from an APK.
//
// TWO CONSEQUENCES WORTH UNDERSTANDING
//
//   A repackaged clone of this app has a DIFFERENT signing certificate, so a
//   DIFFERENT hash, so it never receives the code. That is a genuine anti-clone
//   property and it comes free.
//
//   A debug build signed with the debug key has a different hash from the
//   release build. Developers hit this, conclude "the API does not work", and
//   fix it by adding READ_SMS. That is the origin of a large fraction of the
//   9-out-of-17 measured above. If you find both APIs in one app, check whether
//   the server is sending the RIGHT hash before assuming malice - the finding is
//   still valid, but the recommendation is different.
