// 47-Authentication/examples/03-CredentialManagerLogin.kt
//
// PURPOSE
//   Sign-in through androidx.credentials - the unified Credential Manager API -
//   covering all three credential kinds it brokers: a PASSKEY (public-key
//   credential), a SAVED PASSWORD, and a FEDERATED identity token.
//
//   This is the modern replacement for: a hand-rolled password form, the older
//   GMS FIDO2 API, and Smart Lock for Passwords.
//
// WHY THIS API EXISTS, IN ONE PARAGRAPH
//   Before it, an app that wanted to support passkeys, saved passwords and
//   "Sign in with Google" had to integrate three different SDKs, draw three
//   different pieces of UI, and decide itself which to show. Users saw three
//   inconsistent flows. Credential Manager makes one call, and the SYSTEM draws
//   one picker. That is not merely convenience: because the app never draws the
//   chooser, the app cannot make it look like something else, and the app never
//   learns which provider was used. The anti-phishing property is a consequence
//   of the architecture, not of any check in this file.
//
// MEASURED CONTEXT (README section 3.6)
//   The PLATFORM CredentialManager is API 34+. On the API 30 test device used
//   for this chapter, `service list` shows NO `credentials` service - the stack
//   genuinely is absent. androidx.credentials bridges to Google Play services on
//   older releases, which is why this code can ship with a low minSdkVersion.
//
//   Do not confuse `android.security.identity` (the Identity Credential API,
//   API 30, for mobile driving licences) with Credential Manager. Both have
//   "credential" in the name, both are on the device, and they are unrelated.
//
// ADOPTION, MEASURED (README section 8.6)
//   Across 17 real APKs pulled from a consumer handset: 4 carried genuine
//   passkey ceremony objects, and only 1 carried the androidx.credentials entry
//   point. This API is correct and it is not yet common.
//
// DEPENDENCIES
//   androidx.credentials:credentials
//   androidx.credentials:credentials-play-services-auth   (pre-34 bridge)
//
// SERVER SIDE
//   Every JSON blob below is produced and consumed by a WebAuthn relying party.
//   labs/authlab/auth_server.py implements a minimal one so the flow can be run
//   end to end locally.

package com.pentest.ch47.credmgr

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException

class CredentialManagerLogin(
    private val context: Context,
    private val api: RelyingPartyApi
) {

    private val credentialManager = CredentialManager.create(context)

    // -----------------------------------------------------------------------
    // SIGN IN - one call, three credential kinds
    // -----------------------------------------------------------------------
    /**
     * The order of `credentialOptions` is a hint about preference, not a filter.
     * The system shows the user everything that matches and lets them choose.
     *
     * @param activityContext MUST be an Activity context. The system picker is a
     *        UI operation; passing an application context throws.
     */
    suspend fun signIn(activityContext: Context): SignInResult {

        // 1. The server generates the challenge. It MUST be server-generated,
        //    single-use, and remembered server-side for verification. A
        //    client-generated challenge makes the whole ceremony replayable and
        //    is the single most common WebAuthn integration error.
        val requestJson = api.beginAssertion()      // {"challenge":"...","rpId":"...",...}

        val request = GetCredentialRequest(
            listOf(
                GetPublicKeyCredentialOption(requestJson = requestJson),
                GetPasswordOption()
                // GetSignInWithGoogleOption(serverClientId = "...") to add federation
            )
        )

        return try {
            val response = credentialManager.getCredential(activityContext, request)

            when (val credential = response.credential) {

                is PublicKeyCredential -> {
                    // A signature over the server's challenge, produced by a key
                    // the app has never seen and cannot export. There is NO
                    // bearer secret here for an attacker to find in storage -
                    // which is why "the app stores no credential" can be
                    // literally true for a passkey-only app.
                    val assertion = credential.authenticationResponseJson
                    api.finishAssertion(assertion)      // server verifies; returns a session
                    SignInResult.Success
                }

                is PasswordCredential -> {
                    // A saved password, released by the provider after the user
                    // chose it in the system UI. From the app's point of view
                    // this is an ordinary password login, and every rule in
                    // 02-HardenedLogin.kt still applies to what happens next.
                    api.passwordLogin(credential.id, credential.password)
                    SignInResult.Success
                }

                else -> SignInResult.Unsupported(credential.type)
            }
        } catch (e: NoCredentialException) {
            // The user has nothing saved for this app. This is NOT an error to
            // show as a failure - it is the normal first-run path. Fall through
            // to registration or to a manual form.
            SignInResult.NoCredential
        } catch (e: GetCredentialCancellationException) {
            SignInResult.Cancelled
        } catch (e: GetCredentialException) {
            SignInResult.Error(e.type)
        }
    }

    // -----------------------------------------------------------------------
    // REGISTER A PASSKEY
    // -----------------------------------------------------------------------
    /**
     * Creates a new passkey and registers its PUBLIC key with the server.
     *
     * The user must already be authenticated by some other means when this is
     * called - passkey registration is an operation ON an account, so it is a
     * sensitive action and belongs behind step-up authentication (README 5.12).
     * An app that lets an unauthenticated caller add a passkey to an account has
     * built an account-takeover primitive.
     */
    suspend fun registerPasskey(activityContext: Context, userId: String): RegisterResult {
        val requestJson = api.beginRegistration(userId)

        return try {
            val response = credentialManager.createCredential(
                context = activityContext,
                request = CreatePublicKeyCredentialRequest(
                    requestJson = requestJson,
                    // true asks the provider to require a user-verification
                    // gesture (biometric or device credential) for creation.
                    // Leave it true: it is what makes the resulting credential
                    // "user-verified" to the relying party.
                    preferImmediatelyAvailableCredentials = false
                )
            )
            api.finishRegistration(response.data.toString())
            RegisterResult.Success
        } catch (e: Exception) {
            RegisterResult.Failed(e.message ?: "unknown")
        }
    }
}

sealed interface SignInResult {
    data object Success : SignInResult
    data object NoCredential : SignInResult
    data object Cancelled : SignInResult
    data class Unsupported(val type: String) : SignInResult
    data class Error(val type: String) : SignInResult
}

sealed interface RegisterResult {
    data object Success : RegisterResult
    data class Failed(val reason: String) : RegisterResult
}

interface RelyingPartyApi {
    suspend fun beginAssertion(): String
    suspend fun finishAssertion(assertionJson: String)
    suspend fun beginRegistration(userId: String): String
    suspend fun finishRegistration(attestationJson: String)
    suspend fun passwordLogin(id: String, password: String)
}

// ===========================================================================
// THE FIVE THINGS A REVIEWER MUST CHECK, and they are all on the server
// ===========================================================================
//
// A passkey integration can use this exact client code and still be broken.
// Everything that makes a passkey secure is verified by the relying party:
//
//  1. CHALLENGE. Server-generated, cryptographically random, single-use, and
//     bound to this ceremony. If the server accepts a challenge it did not
//     issue, or accepts one twice, every assertion is replayable.
//
//  2. ORIGIN. The clientDataJSON carries the origin. On Android that is an
//     `android:apk-key-hash:` origin derived from the calling app's SIGNING
//     CERTIFICATE. The server must check it against an allow-list. This is the
//     link that makes a repackaged app fail, and it is the same signing-identity
//     scoping seen in AccountManager token types (README 3.4) and in the SMS
//     Retriever hash (README 3.7).
//
//  3. rpId. Must match the relying party. On Android the binding to the app is
//     established by Digital Asset Links - the /.well-known/assetlinks.json the
//     domain publishes, naming the package and its certificate fingerprint. If
//     that file lists a wildcard, a test package, or a debug certificate, the
//     phishing resistance is gone and it is a real finding. FETCH IT AND READ IT.
//
//  4. SIGNATURE. Verified against the PUBLIC key stored at registration, over
//     authenticatorData || SHA-256(clientDataJSON). Nothing else.
//
//  5. SIGNATURE COUNTER. If the authenticator reports one, a counter that fails
//     to increase indicates a cloned credential. Many platform authenticators
//     report 0 always, which is legitimate; the check is "if non-zero, must
//     increase", not "must be non-zero".
//
// AND THE ONE THAT IS NOT ABOUT PASSKEYS AT ALL:
//
//  6. WHAT THE SERVER HANDS BACK. A passkey ceremony ends with an ordinary
//     session credential, carrying every ordinary problem: lifetime, storage,
//     revocation, replay. PASSKEYS FIX LOGIN. THEY FIX NOTHING AFTER LOGIN.
//     An app with passkeys and a non-expiring bearer token in SharedPreferences
//     is not a well-authenticated app, and as passkey adoption rises this is
//     becoming a common finding shape.
